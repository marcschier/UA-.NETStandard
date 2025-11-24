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

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Generates types used to implement an address space.
    /// </summary>
    internal sealed class Template
    {
        /// <summary>
        /// Initializes the stream from the resource block of the specified assembly.
        /// </summary>
        public Template(TextWriter writer, string templatePath)
            : this(writer, false, templatePath)
        {
        }

        /// <summary>
        /// Initializes the stream from the resource block of the specified assembly.
        /// </summary>
        private Template(TextWriter writer, bool written, string templateString)
        {
            Replacements = [];
            Templates = [];
            m_reader = null;
            m_writer = null;
            IndentCount = 0;

            m_reader = new StringReader(templateString ?? string.Empty);

            m_writer = writer;
            m_written = written;

            Replacements.Add(Tokens.Header, CodeTemplateStrings.Header);
            Replacements.Add(Tokens.Tool,
                Assembly.GetExecutingAssembly().GetName().Name);
            Replacements.Add(Tokens.Version, CoreUtils.Format(
                "{0}.{1}",
                s_softwareVersion,
                s_buildVersion));
        }

        /// <summary>
        /// The number of levels to ident a the current line.
        /// </summary>
        private int IndentCount { get; }

        /// <summary>
        /// Returns enough whitespace to indent the current line properly.
        /// </summary>
        public string Indent
        {
            get
            {
                if (IndentCount > 0)
                {
                    return new string(' ', IndentCount * 4);
                }

                return string.Empty;
            }
        }

        /// <summary>
        /// The table of tokens to replace.
        /// </summary>
        public Dictionary<string, string> Replacements { get; }

        /// <summary>
        /// The templates to load.
        /// </summary>
        public Dictionary<string, TemplateDefinition> Templates { get; }

        /// <summary>
        /// Adds a replacement value for a token.
        /// </summary>
        public void AddReplacement(string token, object replacement)
        {
            if (replacement is bool boolValue)
            {
                Replacements[token] = boolValue ? "true" : "false";
            }
            else
            {
                Replacements[token] = CoreUtils.Format("{0}", replacement);
            }
        }

        /// <summary>
        /// Performs the substitutions specified in the template and writes it to the stream.
        /// </summary>
        public bool WriteTemplate(Context context)
        {
            // ensure context is not null.
            context ??= new Context();

            bool written = false;

            // build list of tokens.
            int count = 0;

            string[] tokens = new string[Replacements.Count];

            foreach (string token in Replacements.Keys)
            {
                tokens[count++] = token;
            }

            // read first line.
            string line = m_reader.ReadLine();

            while (line != null)
            {
                // process empty lines.
                if (line.Length == 0)
                {
                    if (written)
                    {
                        Write(Environment.NewLine);
                    }

                    written = true;
                    line = m_reader.ReadLine();
                    continue;
                }

                bool found = false;

                for (int index = 0; index < line.Length; index++)
                {
                    // check for a token at the current position.
                    string token = null;

                    for (int ii = 0; ii < tokens.Length; ii++)
                    {
                        if (StrCmp(line, index, tokens[ii]))
                        {
                            token = tokens[ii];
                            break;
                        }
                    }

                    // nothing found.
                    if (token == null)
                    {
                        continue;
                    }

                    // check if a template substitution is required.
                    if (Templates.TryGetValue(token, out TemplateDefinition definition))
                    {
                        if (definition == null || definition.Targets == null || definition.Targets.Count == 0)
                        {
                            found = true;
                            line = line[(index + token.Length)..];
                            index = -1;
                            continue;
                        }

                        // write multi-line template.
                        bool result = WriteTemplate(
                            context.Target,
                            token,
                            CoreUtils.Format("{0}{1}", context.Prefix, line[..index]));

                        if (result)
                        {
                            written = true;
                        }

                        line = string.Empty;
                        continue;
                    }

                    // only process tokens if a value is provided.
                    if (Replacements[token] != null)
                    {
                        written = WriteToken(
                            context.Target,
                            context,
                            !found,
                            line[..index],
                            token);

                        found = true;
                    }

                    line = line[(index + token.Length)..];
                    index = -1;
                }

                // write line if no token found.
                if (line.Length > 0)
                {
                    if (!found)
                    {
                        // ensure that an empty line does not get inserted at the start of a file.
                        if (written || context.Target != null)
                        {
                            Write(Environment.NewLine);
                        }

                        Write(context.Prefix);
                        written = true;
                    }

                    Write(line);
                }

                // read next line.
                line = m_reader.ReadLine();
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
            m_writer.Write(Indent);
            m_writer.Write(prefix);
            m_written = true;
        }

        /// <summary>
        /// Writes the text to the stream followed by a new line.
        /// </summary>
        public void WriteLine(string text)
        {
            m_writer.Write(Indent);
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
            m_writer.Write(Indent);
            m_writer.Write(text, args);
            m_writer.Write(Environment.NewLine);
            m_written = true;
        }

        /// <summary>
        /// Substitutes simple text template for a token.
        /// </summary>
        private bool WriteToken(
            object target,
            Context context,
            bool firstToken,
            string prefix,
            string token)
        {
            // write context prefix for first token.
            if (firstToken)
            {
                Write(Environment.NewLine);
                Write(context.Prefix);
            }

            // write prefix.
            Write(prefix);

            // write replacement.
            string replacement = Replacements[token];

            if (replacement != null)
            {
                Write(replacement);
            }

            return true;
        }

        /// <summary>
        /// Substitutes a multi-line template for a token.
        /// </summary>
        private bool WriteTemplate(
            object container,
            string token,
            string prefix)
        {
            bool written = false;

            // write each item in the list.
            var context = new Context
            {
                Container = container,
                Token = token,
                Index = 0,
                FirstInList = true,
                Prefix = prefix
            };

            TemplateDefinition definition = Templates[token];

            context.TemplateString = definition.TemplateString;

            foreach (object target in definition.Targets)
            {
                context.Target = target;

                // get the template path name.
                string templateString = definition.Load(this, context);

                // skip item if no template specified.
                if (templateString == null)
                {
                    context.Index++;
                    continue;
                }

                // load the template.
                var template = new Template(m_writer, m_written, templateString);

                if (!context.FirstInList && context.BlankLine)
                {
                    Write(Environment.NewLine);
                }

                if (definition.Write(template, context))
                {
                    context.FirstInList = false;
                    written = true;
                }

                m_written = template.m_written;

                context.Index++;
            }

            // return flag indicating whether something was written.
            return written;
        }

        /// <summary>
        /// Determines if the target exists in the string at the specified index.
        /// </summary>
        private static bool StrCmp(string source, int index, string target)
        {
            for (int ii = 0; ii < target.Length; ii++)
            {
                if (index + ii >= source.Length || source[index + ii] != target[ii])
                {
                    return false;
                }
            }

            return true;
        }

        private static readonly string s_softwareVersion = CoreUtils.GetAssemblySoftwareVersion();
        private static readonly string s_buildVersion = CoreUtils.GetAssemblyBuildNumber();
        private readonly StringReader m_reader;
        private readonly TextWriter m_writer;
        private bool m_written;
    }
}
