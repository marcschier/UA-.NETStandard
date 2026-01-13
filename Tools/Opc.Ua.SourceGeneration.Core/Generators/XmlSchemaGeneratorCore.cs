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
    /// Generates an XML Schema based on a UA Type Dictionary.
    /// </summary>
    internal class XmlSchemaGeneratorCore : SchemaGenerator
    {
        /// <summary>
        /// Generates the code from the contents of the address space.
        /// </summary>
        public XmlSchemaGeneratorCore(
            IFileSystem fileSystem,
            string typeDictionary,
            string outputDirectory,
            Dictionary<string, string>
            knownFiles,
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
        /// Generates the schema file
        /// </summary>
        public TextFileResource Emit(
            string namespacePrefix,
            bool exportAll = true,
            bool validateOutput = true)
        {
            TargetNamespace = XmlSchemaNamespace.Types;
            m_exportAll = exportAll;

            string schemaFile = Path.Combine(OutputDirectory, CoreUtils.Format(
                "{0}.Types.xsd",
                namespacePrefix));

            WriteTemplate_XmlSchema(schemaFile);

            if (validateOutput)
            {
                // Validate generated file
                var validator = new Schema.Xml.XmlSchemaValidator2(
                    FileSystem,
                    KnownFiles);
                validator.Validate(schemaFile);
            }
            return schemaFile.AsTextFileResource(namespacePrefix);
        }

        /// <summary>
        /// Writes schema file.
        /// </summary>
        private void WriteTemplate_XmlSchema(string fileName)
        {
            using TextWriter writer = FileSystem.CreateTextWriter(fileName);
            using var templateWriter = new TemplateWriter(writer);
            var template = new Template(
                templateWriter,
                SchemaTemplates.Stack_XmlSchema_File_xml);

            template.AddReplacement(Tokens.Namespace, TargetNamespace);

            var buffer = new StringBuilder();
            buffer.AppendFormat(
                CultureInfo.InvariantCulture,
                """
                xmlns:tns="{0}"
                """,
                TargetNamespace);

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
                GetListOfTypes(m_exportAll),
                LoadTemplate_DataType,
                WriteTemplate_DataType);

            template.Render();
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
                """<xs:import namespace="{0}" schemaLocation="{1}.xsd" />""",
                uri,
                location);
        }

        /// <summary>
        /// Writes the import statements.
        /// </summary>
        private TemplateString LoadTemplate_Imports(ILoadContext context)
        {
            if (context.Target is not string namespaceUri)
            {
                return null;
            }

            if (!m_exportAll)
            {
                if (namespaceUri == Namespaces.OpcUaBuiltInTypes)
                {
                    context.Out.WriteLine(
                        """<xs:import namespace="{0}" schemaLocation="BuiltInTypes.xsd" />""",
                        Namespaces.OpcUaBuiltInTypes);
                }
                else
                {
                    context.Out.WriteLine(GetImportStatment(namespaceUri));
                }

                return null;
            }

            return SchemaTemplates.Stack_XmlSchema_BuiltInTypes_xsd;
        }

        /// <summary>
        /// Writes the attributes for a node.
        /// </summary>
        private TemplateString LoadTemplate_DataType(ILoadContext context)
        {
            // do not publish type declarations in OPC BinarySchema files.
            if (context.Target is TypeDeclaration)
            {
                return null;
            }

            if (context.Target is ComplexType complexType)
            {
                if (!complexType.BaseType.IsNull())
                {
                    return SchemaTemplates.Stack_XmlSchema_DerivedType_xml;
                }

                return SchemaTemplates.Stack_XmlSchema_ComplexType_xml;
            }

            if (context.Target is EnumeratedType)
            {
                return SchemaTemplates.Stack_XmlSchema_EnumeratedType_xml;
            }

            if (context.Target is ServiceType)
            {
                return SchemaTemplates.Stack_XmlSchema_ServiceType_xml;
            }

            // do not publish unrecognized sub-types.
            return null;
        }

        /// <summary>
        /// Writes a datatype to the stream.
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        private bool WriteTemplate_DataType(IWriteContext context)
        {
            if (context.Target is not DataType datatype)
            {
                return false;
            }

            context.Template.AddReplacement(Tokens.TypeName, datatype.QName.Name);
            CreateDescription(context.Template, Tokens.Description, datatype.Documentation);

            context.Template.AddReplacement(
                Tokens.ArrayDeclaration,
                SchemaTemplates.Stack_XmlSchema_Array_xml,
                [datatype],
                WriteTemplate_Array);

            if (datatype is ComplexType complexType)
            {
                if (!complexType.BaseType.IsNull())
                {
                    DataType basetype = Validator.ResolveType(complexType.BaseType) ??
                        throw new InvalidOperationException(CoreUtils.Format(
                            "Could not find base type '{0}' for complex type '{1}'.",
                            complexType.BaseType,
                            complexType.QName));

                    context.Template.AddReplacement(Tokens.BaseType, GetXmlSchemaTypeName(basetype.QName, -1));
                }

                List<FieldType> fields = [];

                foreach (FieldType field in complexType.Field)
                {
                    if (!TypeDictionaryValidator.IsExcluded(Exclusions, field))
                    {
                        fields.Add(field);
                    }
                }

                context.Template.AddReplacement(
                    Tokens.ListOfFields,
                    fields,
                    LoadTemplate_Field);
            }

            if (datatype is EnumeratedType enumeratedType)
            {
                var values = new List<EnumeratedValue>();

                foreach (EnumeratedValue value in enumeratedType.Value)
                {
                    if (!TypeDictionaryValidator.IsExcluded(Exclusions, value))
                    {
                        values.Add(value);
                    }
                }

                context.Template.AddReplacement(
                    Tokens.ListOfValues,
                    values,
                    LoadTemplate_EnumeratedValue);
            }

            if (datatype is ServiceType serviceType)
            {
                context.Template.AddReplacement(
                    Tokens.ListOfRequestParameters,
                    serviceType.Request,
                    LoadTemplate_Field);

                context.Template.AddReplacement(
                    Tokens.ListOfResponseParameters,
                    serviceType.Response,
                    LoadTemplate_Field);
            }

            return context.Template.Render();
        }

        /// <summary>
        /// Writes an array declaration to the stream.
        /// </summary>
        private bool WriteTemplate_Array(IWriteContext context)
        {
            if (context.Target is not DataType datatype)
            {
                return false;
            }

            if (!datatype.AllowArrays)
            {
                return false;
            }

            context.Template.AddReplacement(Tokens.TypeName, datatype.QName.Name);

            return context.Template.Render();
        }

        /// <summary>
        /// Writes a field in an OPCBinary schema.
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        private TemplateString LoadTemplate_Field(ILoadContext context)
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

            context.Out.Write("""
                <xs:element name="{0}"
                """, fieldType.Name);

            if (datatype.Name == "XmlElement" && fieldType.ValueRank < 0)
            {
                context.Out.WriteLine(">");
                context.Out.WriteLine("  <xs:complexType>");
                context.Out.WriteLine("    <xs:sequence>");
                context.Out.WriteLine("""      <xs:any minOccurs="0" processContents="lax" />""");
                context.Out.WriteLine("    </xs:sequence>");
                context.Out.WriteLine("  </xs:complexType>");
                context.Out.WriteLine("</xs:element>");
            }
            else
            {
                context.Out.Write("""
                     type="{0}" minOccurs="0"
                    """, GetXmlSchemaTypeName(datatype.QName, fieldType.ValueRank));

                if (datatype.Name is "String" or "ByteString")
                {
                    context.Out.Write("""
                         nillable="true"
                        """);
                }

                context.Out.WriteLine(" />");
            }

            return null;
        }

        /// <summary>
        /// Writes an enumerated value in an OPCBinary schema.
        /// </summary>
        private TemplateString LoadTemplate_EnumeratedValue(ILoadContext context)
        {
            if (context.Target is not EnumeratedValue valueType)
            {
                return null;
            }

            context.Out.Write(
                """<xs:enumeration value="{0}_{1}" />""",
                valueType.Name,
                valueType.Value);

            /*
            if (valueType.Value != 1)
            {
                context.Out.WriteLine(">");
                context.Out.WriteLine("  <xs:annotation>");
                context.Out.WriteLine("    <xs:appinfo>");
                context.Out.WriteLine("      <EnumerationValue xmlns=\"http://schemas.microsoft.com/2003/10/Serialization/\">{1}</EnumerationValue>", valueType.Value);
                context.Out.WriteLine("    </xs:appinfo>");
                context.Out.WriteLine("  </xs:annotation>");
                context.Out.WriteLine("</xs:enumeration>");
            }
            else
            {
                context.Out.WriteLine(" />");
            }
            */

            return null;
        }

        /// <summary>
        /// Returns a name qualified with a namespace prefix.
        /// </summary>
        private string GetXmlSchemaTypeName(XmlQualifiedName qname, int valueRank)
        {
            if (qname.IsNull())
            {
                return string.Empty;
            }

            if (qname.Namespace == Namespaces.OpcUaBuiltInTypes)
            {
                // translate built-in types to XML Schema types.
                if (valueRank < 0)
                {
                    switch (qname.Name)
                    {
                        case "Boolean":
                            return "xs:boolean";
                        case "SByte":
                            return "xs:byte";
                        case "Byte":
                            return "xs:unsignedByte";
                        case "Int16":
                            return "xs:short";
                        case "UInt16":
                            return "xs:unsignedShort";
                        case "Int32":
                            return "xs:int";
                        case "UInt32":
                            return "xs:unsignedInt";
                        case "Int64":
                            return "xs:long";
                        case "UInt64":
                            return "xs:unsignedLong";
                        case "Float":
                            return "xs:float";
                        case "Double":
                            return "xs:double";
                        case "String":
                            return "xs:string";
                        case "DateTime":
                            return "xs:dateTime";
                        case "ByteString":
                            return "xs:base64Binary";
                    }
                }
            }

            string typeName = qname.Name;

            if (!m_exportAll)
            {
                typeName = GetPrefixedName(qname);
            }

            int index = typeName.IndexOf(':', StringComparison.Ordinal);

            // convert to an array element.
            if (valueRank >= 0)
            {
                string prefix;

                if (index != -1)
                {
                    prefix = typeName[..(index + 1)];
                    typeName = typeName[(index + 1)..];
                }
                else
                {
                    prefix = "tns:";
                }

                return CoreUtils.Format("{0}ListOf{1}", prefix, typeName);
            }
            else if (index == -1)
            {
                return "tns:" + typeName;
            }

            return typeName;
        }

        private bool m_exportAll;
    }
}
