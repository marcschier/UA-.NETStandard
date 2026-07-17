/* ========================================================================
 * Copyright (c) 2005-2026 The OPC Foundation, Inc. All rights reserved.
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
using System.IO;
using Opc.Ua.Export;

namespace Opc.Ua.Robotics
{
    /// <summary>
    /// Loads the OPC 40010 Robotics type system (and its required OPC 40001-1
    /// Industrial Automation base model) into a server's predefined-node
    /// collection at runtime, from the NodeSet2 XML embedded in this assembly.
    /// </summary>
    /// <remarks>
    /// Runtime import is used instead of source generation because the Robotics
    /// model relies on base state-machine/method types whose generated NodeState
    /// proxies are not all present in this Core; import loads the full, faithful
    /// type structure. The required OPC UA DI base model must already be present
    /// in the node collection before <see cref="ImportInto"/> is called (it
    /// is added by the Robotics server helper). IA is imported before Robotics
    /// because Robotics depends on it.
    /// </remarks>
    public static class RoboticsNodeSets
    {
        /// <summary>Embedded resource name of the IA base NodeSet2 XML.</summary>
        public const string IaResourceName = "Opc.Ua.IA.NodeSet2.xml";

        /// <summary>Embedded resource name of the Robotics NodeSet2 XML.</summary>
        public const string RoboticsResourceName = "Opc.Ua.Robotics.NodeSet2.xml";

        /// <summary>
        /// Imports the IA then Robotics NodeSets into <paramref name="nodes"/>,
        /// mapping their namespaces onto the context's namespace table. Returns
        /// the number of nodes added.
        /// </summary>
        public static int ImportInto(ISystemContext context, NodeStateCollection nodes)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            if (nodes is null)
            {
                throw new ArgumentNullException(nameof(nodes));
            }
            int before = nodes.Count;
            ImportEmbedded(context, nodes, IaResourceName);
            ImportEmbedded(context, nodes, RoboticsResourceName);
            return nodes.Count - before;
        }

        private static void ImportEmbedded(
            ISystemContext context, NodeStateCollection nodes, string resourceName)
        {
            using Stream? stream = typeof(RoboticsNodeSets).Assembly
                .GetManifestResourceStream(resourceName);
            if (stream == null)
            {
                throw new InvalidOperationException(
                    $"Embedded Robotics NodeSet resource '{resourceName}' was not found.");
            }
            UANodeSet nodeSet = UANodeSet.Read(stream)
                ?? throw new InvalidOperationException(
                    $"Failed to read the embedded Robotics NodeSet '{resourceName}'.");
            nodeSet.Import(context, nodes);
        }
    }
}
