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
            : this(writer, false, 0, templateString)
        {
        }

        /// <summary>
        /// Create template
        /// </summary>
        private Template(TextWriter writer, bool written, int indentCount, TemplateString templateString)
        {
            m_replacements = [];
            m_templates = [];
            m_indentCount = indentCount;

            m_templateString = templateString;
            m_writer = writer;
            m_written = written;

            m_replacements.Add(Tokens.Header, CodeTemplates.Header);
            m_replacements.Add(Tokens.Tool,
                Assembly.GetExecutingAssembly().GetName().Name);
            m_replacements.Add(Tokens.Version, CoreUtils.Format(
                "{0}.{1}",
                s_softwareVersion,
                s_buildVersion));
        }

        /// <summary>
        /// Returns enough whitespace to indent the current line properly.
        /// </summary>
        public string Indentation
            => m_indentCount > 0 ? new string(' ', m_indentCount * 4) : string.Empty;

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
            m_templates.Add(token, templateDefinition);
        }

        /// <summary>
        /// Reserves a token without a replacement value.
        /// </summary>
        public void Reserve(string token)
        {
            m_replacements[token] = null;
        }

        /// <summary>
        /// Performs the substitutions specified in the template and writes it to the stream.
        /// </summary>
        public bool WriteTemplate(Context context = null)
        {
            // ensure context is not null.
            context ??= new Context();

            bool written = false;
            foreach (ParsedTemplateString.Op op in m_templateString.ParsedTemplate.Operations)
            {
                switch (op.Type)
                {
                    case ParsedTemplateString.OpType.Token:
                        // check if a template substitution is required.
                        string token = op.Item;
                        if (m_templates.TryGetValue(token, out TemplateDefinition definition))
                        {
                            if (definition == null ||
                                definition.Targets == null ||
                                definition.Targets.Count == 0)
                            {
                                break;
                            }

                            // write multi-line template.
                            written = false;
                            var pushedContext = new Context
                            {
                                Token = token,
                                Index = 0,
                                NothingWrittenYet = true,
                                Prefix = context.Prefix,
                                TemplateString = definition.TemplateString
                            };
                            foreach (object target in definition.Targets)
                            {
                                pushedContext.Target = target;

                                // get the template path name.
                                TemplateString templateString = definition.Load(this, pushedContext);
                                // skip item if no template specified.
                                if (templateString == null)
                                {
                                    pushedContext.Index++;
                                    continue;
                                }

                                // load the template.
                                var template = new Template(
                                    m_writer,
                                    m_written,
                                    m_indentCount + op.Offset,
                                    templateString);

                                if (!pushedContext.NothingWrittenYet && pushedContext.BlankLine)
                                {
                                    Write(Environment.NewLine);
                                }

                                if (definition.Write(template, pushedContext))
                                {
                                    pushedContext.NothingWrittenYet = false;
                                    written = true;
                                }

                                m_written = template.m_written;
                                pushedContext.Index++;
                            }
                            Write(Environment.NewLine);
                            break;
                        }
                        else if (m_replacements.TryGetValue(token, out string tokenSubstitution) &&
                            tokenSubstitution != null)
                        {
                            Write(tokenSubstitution);
                            written = true;
                        }
                        else
                        {
                            // write line if no token found.
                            Write(Environment.NewLine);
                            Write(Indentation);
                        }
                        break;
                    case ParsedTemplateString.OpType.LineBreak:
                        Write(Environment.NewLine);
                        Write(Indentation);
                        written = true;
                        break;
                    case ParsedTemplateString.OpType.Value:  // Not a token, e.g. a date time or value that was appended
                    case ParsedTemplateString.OpType.Literal:
                    case ParsedTemplateString.OpType.WhiteSpace:
                        Write(op.Item);
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
            m_written = true;
        }

        /// <summary>
        /// Writes the text to the stream.
        /// </summary>
        public void Write(string text)
        {
            if (!m_written && text == Environment.NewLine)
            {
                return;
            }
            m_writer.Write(text);
            m_written = true;
        }

        /// <summary>
        /// Formats and then writes the text to the stream.
        /// </summary>
        public void Write(string format, object arg1)
        {
            m_writer.Write(format, arg1);
            m_written = true;
        }

        /// <summary>
        /// Formats and then writes the text to the stream.
        /// </summary>
        public void Write(string format, object arg1, object arg2)
        {
            m_writer.Write(format, arg1, arg2);
            m_written = true;
        }

        /// <summary>
        /// Formats and then writes the text to the stream.
        /// </summary>
        public void Write(string format, object arg1, object arg2, object arg3)
        {
            m_writer.Write(format, arg1, arg2, arg3);
            m_written = true;
        }

        /// <summary>
        /// Writes a Environment.NewLine and then indents the text for the next line.
        /// </summary>
        public void WriteNextLine(string prefix)
        {
            m_writer.Write(Environment.NewLine);
            m_writer.Write(Indentation);
            m_writer.Write(prefix);
            m_written = true;
        }

        /// <summary>
        /// Writes the text to the stream followed by a new line.
        /// </summary>
        public void WriteLine(string text)
        {
            m_writer.Write(Indentation);
            m_writer.Write(text);
            m_writer.Write(Environment.NewLine);
            m_written = true;
        }

        /// <summary>
        /// Formats and then writes the text to the stream followed by a new line.
        /// </summary>
        public void WriteLine(string text, object arg1)
        {
            WriteLine(text, [arg1]);
        }

        /// <summary>
        /// Formats and then writes the text to the stream followed by a new line.
        /// </summary>
        public void WriteLine(string text, object arg1, object arg2)
        {
            WriteLine(text, [arg1, arg2]);
        }

        /// <summary>
        /// Formats and then writes the text to the stream followed by a new line.
        /// </summary>
        public void WriteLine(string text, object arg1, object arg2, object arg3)
        {
            WriteLine(text, [arg1, arg2, arg3]);
        }

        /// <summary>
        /// Formats and then writes the text to the stream followed by a new line.
        /// </summary>
        public void WriteLine(string text, object[] args)
        {
            m_writer.Write(Indentation);
            m_writer.Write(text, args);
            m_writer.Write(Environment.NewLine);
            m_written = true;
        }

        private static readonly string s_softwareVersion = CoreUtils.GetAssemblySoftwareVersion();
        private static readonly string s_buildVersion = CoreUtils.GetAssemblyBuildNumber();
        private readonly TemplateString m_templateString;
        private readonly TextWriter m_writer;
        private readonly Dictionary<string, TemplateDefinition> m_templates;
        private readonly Dictionary<string, string> m_replacements;
        private readonly int m_indentCount;
        private bool m_written;
    }
}
