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
using System.Linq;
using System.Text;
using Opc.Ua.Schema.Model;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Generates embedded resources as code
    /// </summary>
    public class ResourceGenerator
    {
        /// <summary>
        /// Create code generator
        /// </summary>
        public ResourceGenerator(IFileSystem fileSystem, string outputFolder)
        {
            m_fileSystem = fileSystem;
            m_outputFolder = outputFolder;
        }

        /// <summary>
        /// Generate binary resource
        /// </summary>
        public string EmbeddAsBinary(string namespacePrefix, string name, params string[] fileNames)
        {
            string outputFile = Path.Combine(m_outputFolder, CoreUtils.Format(
                "{0}.{1}.g.cs",
                namespacePrefix,
                name));

            using TextWriter writer = m_fileSystem.CreateTextWriter(outputFile);
            string templateContent = CodeTemplateStrings.Resources_File_cs;
            var template = new Template(writer, templateContent);

            template.AddReplacement(Tokens.Date, DateTime.Now);
            template.AddReplacement(Tokens.Namespace, namespacePrefix);
            template.AddReplacement(Tokens.ClassName, "BinaryResources");

            template.AddTemplate(
                Tokens.ListOfResourceDeclarations,
                CodeTemplateStrings.ResourceDeclaration_cs,
                fileNames,
                null,
                (template, context) => WriteTemplate_ResourceDeclaration(
                    template,
                    context,
                    namespacePrefix,
                    false));

            template.WriteTemplate(null);
            return outputFile;
        }

        /// <summary>
        /// Generate code from Text
        /// </summary>
        public string EmbeddAsText(string namespacePrefix, string name, params string[] fileNames)
        {
            string outputFile = Path.Combine(m_outputFolder, CoreUtils.Format(
                "{0}.{1}.g.cs",
                namespacePrefix,
                name));

            using TextWriter writer = m_fileSystem.CreateTextWriter(outputFile);

            string templateContent = CodeTemplateStrings.Resources_File_cs;
            var template = new Template(writer, templateContent);

            template.AddReplacement(Tokens.Date, DateTime.Now);
            template.AddReplacement(Tokens.Namespace, namespacePrefix);
            template.AddReplacement(Tokens.ClassName, name);

            template.AddTemplate(
                Tokens.ListOfResourceDeclarations,
                CodeTemplateStrings.ResourceDeclaration_cs,
                fileNames,
                null,
                (template, context) => WriteTemplate_ResourceDeclaration(
                    template,
                    context,
                    namespacePrefix,
                    true));

            template.WriteTemplate(null);
            return outputFile;
        }

        private bool WriteTemplate_ResourceDeclaration(
            Template template,
            Context context,
            string namespacePrefix,
            bool isTextResource)
        {
            object[] target = [context.Target];
            if (context.Target is string fileName)
            {
                template.AddReplacement(Tokens.ResourceName, GetResourceName(fileName, namespacePrefix));
            }
            else if (context.Target is Tuple<string, Stream> tuple)
            {
                template.AddReplacement(Tokens.ResourceName, tuple.Item1);
                target = [tuple.Item2];
            }
            else
            {
                return false;
            }

            template.AddTemplate(
                Tokens.Resource,
                string.Empty,
                target,
                isTextResource ?
                    LoadTemplate_TextResource :
                    LoadTemplate_BinaryResource,
                null);

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_BinaryResource(Template template, Context context)
        {
            bool leaveOpen = false;
            Stream reader;
            if (context.Target is string fileName)
            {
                reader = m_fileSystem.OpenRead(fileName);
            }
            else if (context.Target is Stream stream)
            {
                reader = stream;
                leaveOpen = true;
            }
            else
            {
                return null;
            }

            try
            {
                template.WriteNextLine(context.Prefix);
                template.Write("[");
                bool first = true;
                int column = 0;

                int b = reader.ReadByte();
                while (b != -1)
                {
                    if (!first)
                    {
                        template.Write(", ");
                    }
                    first = false;
                    // line break after x entries
                    if (++column == 40)
                    {
                        template.WriteNextLine(context.Prefix);
                        template.Write(template.Indent);
                        column = 0;
                    }
                    template.Write("{0X}", (byte)b);
                    b = reader.ReadByte();
                }
                template.WriteNextLine(context.Prefix);
                template.Write("]");

                return string.Empty;
            }
            finally
            {
                if (!leaveOpen)
                {
                    reader.Dispose();
                }
            }
        }

        private string LoadTemplate_TextResource(Template template, Context context)
        {
            TextReader reader;
            if (context.Target is string fileName)
            {
                reader = m_fileSystem.CreateTextReader(fileName);
            }
            else if (context.Target is Stream stream)
            {
                reader = new StreamReader(stream, Encoding.UTF8, true, 8 * 1024, true);
            }
            else
            {
                return null;
            }
            try
            {
                template.WriteNextLine(context.Prefix);
                template.Write(template.Indent);
                template.Write("\"\"\"");
                for (string line = reader.ReadLine(); line != null; line = reader.ReadLine())
                {
                    line = line.Trim();
                    if (string.IsNullOrEmpty(line))
                    {
                        continue;
                    }
                    template.WriteNextLine(context.Prefix);
                    template.Write(template.Indent);
                    template.Write(line);
                }
                template.WriteNextLine(context.Prefix);
                template.Write(template.Indent);
                template.Write("\"\"\"u8");

                return string.Empty;
            }
            finally
            {
                reader.Dispose();
            }
        }

        /// <summary>
        /// Make a resource name out of the input file name
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="namespacePrefix"></param>
        /// <returns></returns>
        private static string GetResourceName(string inputFile, string namespacePrefix)
        {
            inputFile = Path.GetFileName(inputFile);
            if (inputFile.StartsWith(namespacePrefix, StringComparison.Ordinal))
            {
                inputFile = inputFile[namespacePrefix.Length..];
            }
            var parts = inputFile.Split('.');
            var buffer = new StringBuilder();
            foreach (var part in parts)
            {
                if (string.IsNullOrEmpty(part))
                {
                    continue;
                }
                buffer = buffer
                    .Append(char.ToUpperInvariant(part[0]))
                    .Append(part, 1, part.Length - 1);
            }
            return buffer.ToString();
        }

        private readonly IFileSystem m_fileSystem;
        private readonly string m_outputFolder;
    }
}
