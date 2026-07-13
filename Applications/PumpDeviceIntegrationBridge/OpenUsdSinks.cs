/* ========================================================================
 * Copyright (c) 2005-2025 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;

namespace PumpDeviceIntegrationBridge
{
    /// <summary>USD-side sink the <see cref="OpenUsdConnector"/> writes into.</summary>
    public interface IUsdSink
    {
        void SetAttribute(string primPath, string propertyName, object value);
    }

    /// <summary>In-memory, thread-safe sink (used by tests and diagnostics).</summary>
    public sealed class MockUsdSink : IUsdSink
    {
        private readonly ConcurrentDictionary<string, (object Value, int Count)> m_state = new();
        private int m_total;

        public int TotalWrites => Volatile.Read(ref m_total);

        public void SetAttribute(string primPath, string propertyName, object value)
        {
            m_state.AddOrUpdate(primPath + "." + propertyName, (value, 1),
                (_, prev) => (value, prev.Count + 1));
            Interlocked.Increment(ref m_total);
        }

        public bool WasWritten(string primPath, string propertyName)
            => m_state.TryGetValue(primPath + "." + propertyName, out (object Value, int Count) v)
               && v.Count > 0;
    }

    /// <summary>
    /// Sink that authors a text USD override layer (<c>live.usda</c>). Each change
    /// rewrites the file as a single merged prim tree of <c>over</c> opinions, so
    /// composing it above the base asset (see <c>stage.usda</c>) yields the pump
    /// driven by live OPC UA data. This is the C# equivalent of a Nucleus
    /// <c>.live</c> layer; no USD library is required to author text USD.
    /// </summary>
    public sealed class UsdFileSink : IUsdSink
    {
        private static readonly char[] s_pathSeparator = ['/'];
        private readonly string m_path;
        private readonly object m_gate = new();
        private readonly Dictionary<string, object> m_values = new(StringComparer.Ordinal);
        private readonly List<(string Prim, string Prop)> m_order = new();

        public UsdFileSink(string path)
        {
            m_path = path;
        }

        public void SetAttribute(string primPath, string propertyName, object value)
        {
            // Validate names before authoring: prim-path segments and the
            // (namespaced) property name come from the server's binding model,
            // which the connector treats as untrusted for the purpose of file
            // authoring. Reject anything that is not a valid USD identifier so a
            // hostile or malformed name cannot corrupt or inject into the layer.
            if (!IsValidPrimPath(primPath) || !IsValidPropertyName(propertyName))
            {
                return;
            }
            lock (m_gate)
            {
                string key = primPath + "|" + propertyName;
                if (!m_values.ContainsKey(key))
                {
                    m_order.Add((primPath, propertyName));
                }
                m_values[key] = value;
                Write();
            }
        }

        private static bool IsValidPrimPath(string primPath)
        {
            if (string.IsNullOrEmpty(primPath))
            {
                return false;
            }
            string[] segs = primPath.Split(s_pathSeparator, StringSplitOptions.RemoveEmptyEntries);
            if (segs.Length == 0)
            {
                return false;
            }
            foreach (string seg in segs)
            {
                if (!IsValidIdentifier(seg))
                {
                    return false;
                }
            }
            return true;
        }

        // A USD property name is one or more identifier segments separated by ':'
        // (the USD namespace separator), e.g. "xformOp:rotateZ", "inputs:emissiveColor".
        private static bool IsValidPropertyName(string propertyName)
        {
            if (string.IsNullOrEmpty(propertyName))
            {
                return false;
            }
            foreach (string part in propertyName.Split(':'))
            {
                if (!IsValidIdentifier(part))
                {
                    return false;
                }
            }
            return true;
        }

        // USD identifier: starts with a letter or '_', then letters/digits/'_'.
        private static bool IsValidIdentifier(string s)
        {
            if (string.IsNullOrEmpty(s))
            {
                return false;
            }
            char c0 = s[0];
            if (!(char.IsLetter(c0) || c0 == '_'))
            {
                return false;
            }
            for (int i = 1; i < s.Length; i++)
            {
                char c = s[i];
                if (!(char.IsLetterOrDigit(c) || c == '_'))
                {
                    return false;
                }
            }
            return true;
        }

        private sealed class Node
        {
            public List<(string Prop, string UsdType, string Value)> Props { get; } = new();
            public Dictionary<string, Node> Children { get; } = new(StringComparer.Ordinal);
            public List<string> ChildOrder { get; } = new();

            public Node Child(string name)
            {
                if (!Children.TryGetValue(name, out Node? n))
                {
                    n = new Node();
                    Children[name] = n;
                    ChildOrder.Add(name);
                }
                return n;
            }
        }

        private void Write()
        {
            var root = new Node();
            var rootOrder = new List<string>();
            foreach ((string prim, string prop) in m_order)
            {
                object value = m_values[prim + "|" + prop];
                Node node = root;
                foreach (string seg in prim.Split(s_pathSeparator, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (node == root && !rootOrder.Contains(seg))
                    {
                        rootOrder.Add(seg);
                    }
                    node = node.Child(seg);
                }
                (string usdType, string formatted) = FormatValue(prop, value);
                node.Props.Add((prop, usdType, formatted));
            }

            var sb = new StringBuilder();
            sb.Append("#usda 1.0\n(\n    doc = \"OPC UA -> OpenUSD live bindings (override layer)\"\n)\n\n");
            foreach (string name in rootOrder)
            {
                Emit(sb, root.Children[name], name, string.Empty);
                sb.Append('\n');
            }

            string? dir = Path.GetDirectoryName(m_path);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllText(m_path, sb.ToString());
        }

        private static void Emit(StringBuilder sb, Node node, string name, string indent)
        {
            sb.Append(indent).Append("over \"").Append(name).Append("\"\n");
            sb.Append(indent).Append("{\n");
            foreach ((string prop, string usdType, string value) in node.Props)
            {
                sb.Append(indent).Append("    ").Append(usdType).Append(' ')
                  .Append(prop).Append(" = ").Append(value).Append('\n');
            }
            foreach (string child in node.ChildOrder)
            {
                Emit(sb, node.Children[child], child, indent + "    ");
            }
            sb.Append(indent).Append("}\n");
        }

        private static string F(double x)
            => x.ToString("0.0000", CultureInfo.InvariantCulture);

        // Escape a USD string/token value: backslash and quote are escaped and
        // control characters (newline, carriage return, tab) are rendered as
        // escape sequences so a value cannot break out of the quoted literal.
        private static string EscapeToken(string s)
        {
            var sb = new StringBuilder(s.Length);
            foreach (char c in s)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"': sb.Append("\\\""); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }

        private static (string UsdType, string Value) FormatValue(string prop, object value)
        {
            switch (value)
            {
                case float[] c when prop.EndsWith("displayColor", StringComparison.OrdinalIgnoreCase):
                    return ("color3f[]", "[(" + F(c[0]) + ", " + F(c[1]) + ", " + F(c[2]) + ")]");
                case float[] c:
                    return ("color3f", "(" + F(c[0]) + ", " + F(c[1]) + ", " + F(c[2]) + ")");
                case string s:
                    return ("token", "\"" + EscapeToken(s) + "\"");
                case double d:
                    return ("double", F(d));
                default:
                    return ("double", F(System.Convert.ToDouble(value, CultureInfo.InvariantCulture)));
            }
        }
    }
}
