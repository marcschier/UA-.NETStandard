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
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Generates embedded resources or string constants as code
    /// </summary>
    internal sealed class ResourceGenerator
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
        /// Embed resources as code into the compilation
        /// </summary>
        public string Embed(string namespacePrefix, string name, params Resource[] resources)
        {
            if (resources.Select(r => r.ResourceName).Distinct().Count() != resources.Length)
            {
                throw new ArgumentException("Resource names must be unique");
            }

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
                resources,
                LoadTemplate_ResourceDeclaration,
                WriteTemplate_ResourceDeclaration);

            template.WriteTemplate(null);
            return outputFile;
        }

        private string LoadTemplate_ResourceDeclaration(Template template, Context context)
        {
            if (context.Target is StringResource str && str.AsUtf16)
            {
                return CodeTemplateStrings.ResourceConstant_cs;
            }
            return CodeTemplateStrings.ResourceDeclaration_cs;
        }

        private bool WriteTemplate_ResourceDeclaration(
            Template template,
            Context context)
        {
            object[] target = [context.Target];
            if (context.Target is not Resource resource)
            {
                return false;
            }
            template.AddReplacement(Tokens.ResourceName, resource.ResourceName);
            template.AddTemplate(
                Tokens.Resource,
                string.Empty,
                target,
                resource.IsText ?
                    LoadTemplate_TextResource :
                    LoadTemplate_BinaryResource,
                WriteTemplate_Resource);

            return template.WriteTemplate(context);
        }

        private bool WriteTemplate_Resource(Template template, Context context)
        {
            if (context.Target is StringResource str && str.AsUtf16)
            {
                switch (str)
                {
                    case TextResource textResource:
                        template.AddReplacement(
                            Tokens.Resource,
                            textResource.Text);
                        return template.WriteTemplate(context);
                    case TextReaderResource textReaderResource:
                        template.AddReplacement(
                            Tokens.Resource,
                            textReaderResource.Reader.ReadToEnd());
                        return template.WriteTemplate(context);
                    default:
                        // SHould not be here
                        return false;
                }
            }
            // Already written
            return true;
        }

        private string LoadTemplate_BinaryResource(Template template, Context context)
        {
            bool leaveOpen = false;
            Stream reader;
            switch (context.Target)
            {
                case BinaryFileResource fileResource:
                    reader = m_fileSystem.OpenRead(fileResource.FileName);
                    break;
                case StreamResource stream:
                    reader = stream.Stream;
                    reader.Position = 0;
                    leaveOpen = true;
                    break;
                case BinaryResource binary:
                    reader = new MemoryStream(binary.Data);
                    break;
                default:
                    return null;
            }
            try
            {
                if (reader.Length > kBase64Threshold)
                {
                    WriteAsBase64StringLiteral(
                        template,
                        context,
                        AsBase64String(reader));
                }
                else
                {
                    WriteAsByteArray(template, context, reader);
                }
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
            Stream istrm = null;
            var leaveOpen = false;
            switch (context.Target)
            {
                case TextFileResource textFile:
                    istrm = m_fileSystem.OpenRead(textFile.FileName);
                    leaveOpen = false;
                    break;
                case StreamResource stream:
                    stream.Stream.Position = 0;
                    istrm = stream.Stream;
                    leaveOpen = true;
                    break;
                case BinaryResource binary:
                    istrm = new MemoryStream(binary.Data);
                    leaveOpen = false;
                    break;
            }
            if (istrm != null && istrm.Length > kBase64Threshold)
            {
                try
                {
                    WriteAsBase64StringLiteral(
                        template,
                        context,
                        AsBase64String(istrm));
                    return string.Empty;
                }
                finally
                {
                    if (!leaveOpen)
                    {
                        istrm.Dispose();
                    }
                }
            }

            TextReader reader;
            switch (context.Target)
            {
                case TextResource text:
                    reader = new StringReader(text.Text);
                    break;
                case TextReaderResource textReader:
                    reader = textReader.Reader;
                    break;
                default:
                    if (istrm == null)
                    {
                        // unknown resource type
                        return null;
                    }
                    reader = new StreamReader(
                        istrm,
                        Encoding.UTF8,
                        true,
                        kReadBufferSize,
                        leaveOpen);
                    break;
            }
            try
            {
                WriteAsUtf8StringLiteral(template, context, reader);
                return string.Empty;
            }
            finally
            {
                reader.Dispose();
            }
        }

        private static void WriteAsUtf8StringLiteral(
            Template template,
            Context context,
            TextReader reader)
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
        }

        private void WriteAsBase64StringLiteral(
            Template template,
            Context context,
            string base64)
        {
            template.WriteNextLine(context.Prefix);
            template.Write("Convert.FromBase64String(");
            for (int ii = 0; ii < base64.Length; ii += 80)
            {
                if (ii > 0)
                {
                    template.Write(" +");
                }
                if (ii + 80 >= base64.Length)
                {
                    WriteChunk(template, context, base64[ii..]);
                }
                else
                {
                    WriteChunk(template, context, base64.Substring(ii, 80));
                }
            }
            template.Write(")");

            static void WriteChunk(Template template, Context context, string line)
            {
                template.WriteNextLine(context.Prefix);
                template.Write(template.Indent);
                template.Write("   \"");

                for (int ii = 0; ii < line.Length; ii++)
                {
                    // Escape backslashes
                    if (line[ii] == '\\')
                    {
                        template.Write("""\\""");
                        continue;
                    }
                    template.Write(line[ii]);
                }

                template.Write("\"");
            }
        }

        private static void WriteAsByteArray(Template template, Context context, Stream reader)
        {
            template.WriteNextLine(context.Prefix);
            template.Write("new byte[]");
            template.WriteNextLine(context.Prefix);
            template.Write("{");
            template.WriteNextLine(context.Prefix);
            template.Write("    ");
            bool first = true;
            int column = 0;

            int b = reader.ReadByte();
            while (b != -1)
            {
                // line break after x entries
                if (column++ >= 12)
                {
                    template.Write(",");
                    template.WriteNextLine(context.Prefix);
                    template.Write("    ");
                    column = 1;
                }
                else if (!first)
                {
                    template.Write(", ");
                }
                first = false;
                template.Write("0x{0:X2}", (byte)b);
                b = reader.ReadByte();
            }
            template.WriteNextLine(context.Prefix);
            template.Write("}");
        }

        private static string AsBase64String(Stream reader)
        {
            if (reader is MemoryStream ms)
            {
                return Convert.ToBase64String(ms.ToArray());
            }
            else
            {
                using var memoryStream = new MemoryStream();
                reader.CopyTo(memoryStream);
                return Convert.ToBase64String(memoryStream.ToArray());
            }
        }

        /// <summary>
        /// This is the max size of the stream that will be inlined.
        /// The compiler is too slow to inline larger byte arrays.
        /// Otherwise it will be base64 encoded and must be decoded
        /// at runtime.
        /// </summary>
        private const int kBase64Threshold = 1024;
        private const int kReadBufferSize = 16 * 1024;
        private readonly IFileSystem m_fileSystem;
        private readonly string m_outputFolder;
    }

    /// <summary>
    /// An embeddeable resource
    /// </summary>
    internal abstract record class Resource(string ResourceName, bool IsText)
    {
        /// <summary>
        /// Make a resource name out of the input file name
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="namespacePrefix"></param>
        /// <returns></returns>
        public static string GetNameForFile(string inputFile, string namespacePrefix)
        {
            inputFile = Path.GetFileName(inputFile);
            if (namespacePrefix != null &&
                inputFile.StartsWith(namespacePrefix, StringComparison.Ordinal))
            {
                inputFile = inputFile[namespacePrefix.Length..];
            }
            string[] parts = inputFile.Split('.');
            var buffer = new StringBuilder();
            foreach (string part in parts)
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
    }

    internal sealed record class StreamResource(string ResourceName, Stream Stream, bool IsText = false)
        : Resource(ResourceName, IsText);

    internal sealed record class BinaryResource(string ResourceName, byte[] Data, bool IsText = false)
        : Resource(ResourceName, IsText);

    internal abstract record class StringResource(string ResourceName, bool AsUtf16)
        : Resource(ResourceName, true);

    internal sealed record class TextReaderResource(string ResourceName, TextReader Reader, bool AsUtf16 = false)
        : StringResource(ResourceName, AsUtf16);

    internal record class TextResource(string ResourceName, string Text, bool AsUtf16 = false)
        : StringResource(ResourceName, AsUtf16);

    internal sealed record class TextFileResource(string ResourceName, string FileName)
        : Resource(ResourceName, true);

    internal sealed record class BinaryFileResource(string ResourceName, string FileName)
        : Resource(ResourceName, false);

    internal sealed record class StringConstant(string Text)
        : TextResource(GetName(Text), Text, true)
    {
        private static string GetName(string text)
        {
            var buffer = new StringBuilder();
            foreach (char ch in text)
            {
                if (char.IsLetterOrDigit(ch))
                {
                    buffer.Append(ch);
                }
                else
                {
                    buffer.Append('_');
                }
            }
            return buffer.ToString();
        }
    }

    /// <summary>
    /// Extensions
    /// </summary>
    internal static class ResourceExtensions
    {
        public static TextFileResource AsTextFileResource(
            this string fileName,
            string namespaceUri = null)
        {
            return new TextFileResource(
                Resource.GetNameForFile(fileName, namespaceUri),
                fileName);
        }

        public static BinaryFileResource ToBinaryFileResource(
            this string fileName,
            string namespaceUri = null)
        {
            return new BinaryFileResource(
                Resource.GetNameForFile(fileName, namespaceUri),
                fileName);
        }
    }
}
