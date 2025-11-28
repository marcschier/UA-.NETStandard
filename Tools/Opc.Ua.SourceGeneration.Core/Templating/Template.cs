/* ========================================================================
 * Copyright (c) 2005-2024 The OPC Foundation, Inc. All rights reserved.
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
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using static System.Net.Mime.MediaTypeNames;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Templating engine
    /// </summary>
    internal sealed class Template
    {
        /// <summary>
        /// Create template
        /// </summary>
        public Template(TextWriter writer, TemplateString templateString)
            : this(new TemplateWriter(writer), templateString)
        {
        }

        /// <summary>
        /// Create template
        /// </summary>
        private Template(
            TemplateWriter writer,
            TemplateString templateString,
            Template parent = null)
        {
            m_replacements = [];
            m_templateString = templateString;
            m_outerTemplate = parent;
            m_writer = writer;
            m_replacements.Add(Tokens.Header, CodeTemplates.Header);
            m_replacements.Add(Tokens.Tool,
                Assembly.GetExecutingAssembly().GetName().Name);
            m_replacements.Add(Tokens.Version, CoreUtils.Format(
                "{0}.{1}",
                s_softwareVersion,
                s_buildVersion));
        }

        /// <summary>
        /// Adds a replacement value for a token.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        public void AddReplacement<T>(string token, T replacement)
        {
            m_replacements[token] = CoreUtils.Format("{0}", replacement);
        }

        /// <summary>
        /// Adds a replacement value for a token.
        /// </summary>
        public void AddReplacement(string token, bool replacement)
        {
            m_replacements[token] = replacement ? "true" : "false";
        }

        /// <summary>
        /// Adds a replacement value for a token.
        /// </summary>
        public void AddReplacement(string token, string replacement)
        {
            m_replacements[token] = replacement;
        }

        /// <summary>
        /// Add template definition for a token.
        /// </summary>
        public void AddReplacement(string token, TemplateDefinition templateDefinition)
        {
            m_replacements[token] = templateDefinition;
        }

        /// <summary>
        /// Performs the substitutions specified in the template and writes it.
        /// </summary>
        public bool WriteTemplate()
        {
            bool written = false;
            bool dropNextNewLine = false;
            ParsedTemplateString parsed = m_templateString.ParsedTemplate;
            for (int i = 0; i < parsed.Operations.Count; i++)
            {
                ParsedTemplateString.Op op = parsed.Operations[i];
                switch (op.Type)
                {
                    case ParsedTemplateString.OpType.Token:
                        // check if a template substitution is required.
                        dropNextNewLine = false;
                        if (!TryGetReplacement(op.Item, out object replacement) ||
                            replacement == null)
                        {
                            break;
                        }
                        if (replacement is not TemplateDefinition definition)
                        {
                            Write(replacement.ToString());
                            written = true;
                            break;
                        }
                        if (definition.Targets == null ||
                            definition.Targets.Count == 0)
                        {
                            break;
                        }
                        written = false;
                        var context = new Context
                        {
                            Token = op.Item,
                            Index = 0,
                            NothingWrittenYet = true,
                            TemplateString = definition.TemplateString
                        };
                        m_writer.PushIndentChars(op.Offset);
                        var writeNewLineBetweenTargets = false;
                        for (int j = 0; j < definition.Targets.Count; j++)
                        {
                            context.Target = definition.Targets[j];

                            // get the template path name.
                            TemplateString templateString =
                                definition.Load(this, context);
                            // skip item if no template specified.
                            if (templateString == null)
                            {
                                context.Index++;
                                continue;
                            }

                            // begin new line between multi line items if needed.
                            if (writeNewLineBetweenTargets)
                            {
                                m_writer.WriteNewLine();
                            }

                            // load the template.
                            var template = new Template(
                                m_writer,
                                templateString,
                                this);
                            if (definition.Write(template, context))
                            {
                                context.NothingWrittenYet = false;
                                writeNewLineBetweenTargets =
                                    templateString.ParsedTemplate.IsMultiLine;
                                written = true;
                            }
                            else
                            {
                                writeNewLineBetweenTargets = false;
                            }
                            context.Index++;
                        }
                        m_writer.PopIndentation();
                        // Do not write final new line
                        dropNextNewLine = true;
                        break;
                    case ParsedTemplateString.OpType.LineBreak:
                        if (dropNextNewLine)
                        {
                            dropNextNewLine = false;
                            break;
                        }
                        m_writer.WriteNewLine();
                        written = true;
                        break;
                    // Not a token, e.g. a date time or value that was appended
                    case ParsedTemplateString.OpType.Value:
                    case ParsedTemplateString.OpType.Literal:
                    case ParsedTemplateString.OpType.WhiteSpace:
                        m_writer.Write(op.Item);
                        written = true;
                        dropNextNewLine = false;
                        break;
                }
            }
            return written;
        }

        /// <summary>
        /// Writes the text to the stream.
        /// </summary>
        public void Write(char text)
        {
            m_writer.Write(text);
        }

        /// <summary>
        /// Writes the text to the stream.
        /// </summary>
        public void Write(string text)
        {
            m_writer.Write(text);
        }

        /// <summary>
        /// Formats and then writes the text to the stream.
        /// </summary>
        public void Write(string format, object arg1)
        {
            m_writer.Write(format, arg1);
        }

        /// <summary>
        /// Formats and then writes the text to the stream.
        /// </summary>
        public void Write(string format, object arg1, object arg2)
        {
            m_writer.Write(format, arg1, arg2);
        }

        /// <summary>
        /// Formats and then writes the text to the stream.
        /// </summary>
        public void Write(string format, object arg1, object arg2, object arg3)
        {
            m_writer.Write(format, arg1, arg2, arg3);
        }

        /// <summary>
        /// Writes a a new line character.
        /// </summary>
        public void WriteNewLine()
        {
            m_writer.WriteNewLine();
        }

        /// <summary>
        /// Writes a new line and then indents the text and writes the text.
        /// </summary>
        public void WriteAfterNewLine(string text)
        {
            m_writer.WriteAfterNewLine(text);
        }

        /// <summary>
        /// Writes the text (indented) to the stream followed by a new line.
        /// </summary>
        public void WriteAfterNewLine(string text, params object[] args)
        {
            m_writer.WriteAfterNewLine(text, args);
        }

        /// <summary>
        /// Writes the text followed by a new line.
        /// </summary>
        public void WriteLine(string text)
        {
            m_writer.WriteLine(text);
        }

        /// <summary>
        /// Formats and then writes the text followed by a new line.
        /// </summary>
        public void WriteLine(string text, params object[] args)
        {
            m_writer.WriteLine(text, args);
        }

        /// <summary>
        /// Try get replacement and fall back to outer scope
        /// </summary>
        private bool TryGetReplacement(string token, out object replacement)
        {
            if (!m_replacements.TryGetValue(token, out replacement))
            {
                return m_outerTemplate != null &&
                    m_outerTemplate.TryGetReplacement(token, out replacement);
            }
            return true;
        }

        private static readonly string s_softwareVersion = CoreUtils.GetAssemblySoftwareVersion();
        private static readonly string s_buildVersion = CoreUtils.GetAssemblyBuildNumber();
        private readonly TemplateString m_templateString;
        private readonly Template m_outerTemplate;
        private readonly TemplateWriter m_writer;
        private readonly Dictionary<string, object> m_replacements;
    }
}
