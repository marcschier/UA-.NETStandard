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
using System.Globalization;
using System.IO;
using System.Text;
using System.Xml;
using Opc.Ua.Schema.Types;
using Opc.Ua.Types;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Generates files used to describe data types.
    /// </summary>
    internal class BinarySchemaGenerator : SchemaGenerator
    {
        /// <summary>
        /// Generates the code from the contents of the address space.
        /// </summary>
        public BinarySchemaGenerator(
            IFileSystem fileSystem,
            string typeDictionary,
            string outputDirectory,
            Dictionary<string, string> knownFiles,
            IReadOnlyList<string> exclusions)
            : base(
                fileSystem,
                typeDictionary,
                outputDirectory,
                knownFiles,
                exclusions)
        {
        }

        /// <summary>
        /// Generates the datatype files.
        /// </summary>
        public TextFileResource Emit(
            string namespacePrefix,
            string targetNamespace,
            bool exportAll = true,
            bool validateOutput = true)
        {
            TargetNamespace = targetNamespace;
            m_exportAll = exportAll;

            string schemaFile = Path.Combine(OutputDirectory, CoreUtils.Format(
                "{0}.Types.bsd",
                namespacePrefix));

            WriteTemplate_BinarySchema(schemaFile);

            if (validateOutput)
            {
                // Validate generated file
                var validator = new Schema.Binary.BinarySchemaValidator(
                    FileSystem,
                    KnownFiles);
                validator.Validate(schemaFile);
            }
            return schemaFile.AsTextFileResource(namespacePrefix);
        }

        /// <summary>
        /// Writes schema file.
        /// </summary>
        private void WriteTemplate_BinarySchema(string fileName)
        {
            using TextWriter writer = FileSystem.CreateTextWriter(fileName);
            using var templateWriter = new TemplateWriter(writer);
            var template = new Template(templateWriter, SchemaTemplates.Stack_BinarySchema_File_xml);

            template.AddReplacement(Tokens.DictionaryUri, TargetNamespace);

            var buffer = new StringBuilder();
            buffer.AppendFormat(
                CultureInfo.InvariantCulture,
                """
                xmlns="{0}"
                """,
                NamespaceUris[0]);
            if (!m_exportAll)
            {
                for (int ii = 1; ii < NamespaceUris.Count; ii++)
                {
                    buffer.Append(Environment.NewLine)
                        .Append("  ")
                        .AppendFormat(
                        CultureInfo.InvariantCulture,
                        """
                        xmlns:s{0}="{1}"
                        """,
                        ii - 1,
                        NamespaceUris[ii]);
                }
            }
            buffer.Append(Environment.NewLine);

            template.AddReplacement(
                Tokens.XmlnsS0ListOfNamespaces,
                buffer.ToString(),
                ["Dummy"]); // Ensure new lines are correctly processed
            List<string> imports = [Namespaces.OpcUaBuiltInTypes];
            if (!m_exportAll)
            {
                for (int ii = 1; ii < NamespaceUris.Count; ii++)
                {
                    imports.Add(NamespaceUris[ii]);
                }
            }

            template.AddReplacement(
                Tokens.Imports,
                imports,
                LoadTemplate_Imports);

            template.AddReplacement(
                Tokens.ListOfTypes,
                SchemaTemplates.Stack_BinarySchema_OpaqueType_xml,
                GetListOfTypes(m_exportAll),
                LoadTemplate_DataType,
                WriteTemplate_DataType);

            template.WriteTemplate();
        }

        /// <summary>
        /// Creates a schema import statement.
        /// </summary>
        private static string GetImportStatment(string uri)
        {
            string location = null;
            string[] elements = uri.Split(['/']);

            for (int ii = elements.Length - 1; ii >= 0; ii--)
            {
                if (!string.IsNullOrEmpty(elements[ii]))
                {
                    location = elements[ii];
                    break;
                }
            }

            return CoreUtils.Format(
                "<opc:Import Namespace=\"{0}\" Location=\"{1}.bsd\" />",
                uri,
                location);
        }

        /// <summary>
        /// Writes the import statements.
        /// </summary>
        private TemplateString LoadTemplate_Imports(Template template, ITemplateContext context)
        {
            if (context.Target is not string namespaceUri)
            {
                return null;
            }

            if (!m_exportAll)
            {
                if (namespaceUri == Namespaces.OpcUaBuiltInTypes)
                {
                    template.WriteLine(
                        "<opc:Import Namespace=\"{0}\" />",
                        Namespaces.OpcUaBuiltInTypes);
                }
                else
                {
                    template.WriteLine(GetImportStatment(namespaceUri));
                }

                return null;
            }

            return SchemaTemplates.Stack_BinarySchema_BuiltInTypes_bsd;
        }

        /// <summary>
        /// Writes the attributes for a node.
        /// </summary>
        private TemplateString LoadTemplate_DataType(Template template, ITemplateContext context)
        {
            // do not publish type declarations in OPC BinarySchema files.
            if (context.Target is TypeDeclaration)
            {
                return null;
            }

            if (context.Target is ComplexType)
            {
                var complexType = context.Target as ComplexType;

                // do not publish types with no fields.
                if (complexType.Field == null || complexType.Field.Length == 0)
                {
                    return null;
                }

                return SchemaTemplates.Stack_BinarySchema_ComplexType_xml;
            }

            if (context.Target is EnumeratedType)
            {
                return SchemaTemplates.Stack_BinarySchema_EnumeratedType_xml;
            }

            if (context.Target is ServiceType)
            {
                return SchemaTemplates.Stack_BinarySchema_ServiceType_xml;
            }

            // do not publish unrecognized sub-types.
            return null;
        }

        /// <summary>
        /// Writes the
        /// </summary>
        private bool WriteTemplate_DataType(Template template, ITemplateContext context)
        {
            if (context.Target is not DataType datatype)
            {
                return false;
            }

            template.AddReplacement(Tokens.TypeName, datatype.QName.Name);
            CreateDescription(template, Tokens.Description, datatype.Documentation);

            if (datatype is ComplexType complexType)
            {
                List<FieldType> fields = [];
                GetFields(complexType, fields);

                template.AddReplacement(
                    Tokens.ListOfFields,
                    fields,
                    LoadTemplate_Field);
            }

            if (datatype is EnumeratedType enumeratedType)
            {
                uint lengthInBits = 32;
                bool isOptionSet = false;
                List<EnumeratedValue> values = [];

                foreach (EnumeratedValue value in enumeratedType.Value)
                {
                    if (!TypeDictionaryValidator.IsExcluded(Exclusions, value))
                    {
                        values.Add(value);
                    }
                }

                if (enumeratedType.IsOptionSet)
                {
                    isOptionSet = true;

                    DataType baseType = Validator.ResolveType(enumeratedType.BaseType);

                    if (baseType != null)
                    {
                        switch (baseType.Name)
                        {
                            case "SByte":
                            case "Byte":
                                lengthInBits = 8;
                                break;
                            case "Int16":
                            case "UInt16":
                                lengthInBits = 16;
                                break;
                            case "Int32":
                            case "UInt32":
                                lengthInBits = 32;
                                break;
                            case "Int64":
                            case "UInt64":
                                lengthInBits = 64;
                                break;
                        }
                    }

                    values.Add(new EnumeratedValue
                    {
                        Name = "None",
                        Value = 0,
                        ValueSpecified = true
                    });
                }

                template.AddReplacement(
                    Tokens.LengthInBits,
                    lengthInBits);
                template.AddReplacement(
                    Tokens.IsOptionSet,
                    isOptionSet ? " IsOptionSet=\"true\"" : string.Empty);

                template.AddReplacement(
                    Tokens.ListOfValues,
                    values,
                    LoadTemplate_EnumeratedValue);
            }

            if (datatype is ServiceType serviceType)
            {
                template.AddReplacement(
                    Tokens.ListOfRequestParameters,
                    serviceType.Request,
                    LoadTemplate_Field);

                template.AddReplacement(
                    Tokens.ListOfResponseParameters,
                    serviceType.Response,
                    LoadTemplate_Field);
            }

            return template.WriteTemplate();
        }

        /// <summary>
        /// Writes a field in an OPCBinary schema.
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        private TemplateString LoadTemplate_Field(Template template, ITemplateContext context)
        {
            if (context.Target is not FieldType fieldType)
            {
                return null;
            }

            // resolve any type definitions.
            DataType datatype = Validator.ResolveType(fieldType.DataType) ??
                throw new InvalidOperationException(CoreUtils.Format(
                    "Could not find datatype '{0}' for field '{1}'.",
                    fieldType.DataType,
                    fieldType.Name));

            template.WriteLine();
            if (fieldType.ValueRank == 0)
            {
                template.WriteLine(
                    "<opc:Field Name=\"NoOf{0}\" TypeName=\"opc:Int32\" />",
                    fieldType.Name);
            }

            template.Write("<opc:Field Name=\"{0}\"", fieldType.Name);
            template.Write(" TypeName=\"{0}\"", GetBinarySchemaTypeName(datatype.QName));

            if (fieldType.ValueRank == 0)
            {
                template.Write(" LengthField=\"NoOf{0}\"", fieldType.Name);
            }

            template.Write(" />");

            return null;
        }

        /// <summary>
        /// Writes an enumerated value in an OPCBinary schema.
        /// </summary>
        private TemplateString LoadTemplate_EnumeratedValue(Template template, ITemplateContext context)
        {
            if (context.Target is not EnumeratedValue valueType)
            {
                return null;
            }

            template.WriteLine(
                "<opc:EnumeratedValue Name=\"{0}\" Value=\"{1}\" />",
                valueType.Name,
                valueType.Value);

            return null;
        }

        /// <summary>
        /// Returns a name qualified with a namespace prefix.
        /// </summary>
        private string GetBinarySchemaTypeName(XmlQualifiedName qname)
        {
            if (qname.IsNull())
            {
                return string.Empty;
            }

            if (qname.Namespace == Namespaces.OpcUaBuiltInTypes)
            {
                // translate built-in types to OPC Binary Schema types.
                switch (qname.Name)
                {
                    case "Boolean":
                    case "SByte":
                    case "Byte":
                    case "Int16":
                    case "UInt16":
                    case "Int32":
                    case "UInt32":
                    case "Int64":
                    case "UInt64":
                    case "Float":
                    case "Double":
                    case "Guid":
                    case "DateTime":
                    case "ByteString":
                        return CoreUtils.Format("opc:{0}", qname.Name);
                    case "String":
                        return "opc:CharArray";
                }
            }

            if (!m_exportAll)
            {
                return GetPrefixedName(qname);
            }

            return qname.Name;
        }

        private bool m_exportAll;
    }
}
