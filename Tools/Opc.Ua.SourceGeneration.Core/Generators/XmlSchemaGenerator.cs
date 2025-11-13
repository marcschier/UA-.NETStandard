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

using System.Text;
using System.Xml;
using Opc.Ua.Schema.Types;
using Opc.Ua.Types;
using System.Globalization;
using System.Collections.Generic;
using System.IO;
using System;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Generates an XML Schema based on a UA Type Dictionary.
    /// </summary>
    public class XmlSchemaGenerator : SchemaGenerator
    {
        /// <summary>
        /// Generates the code from the contents of the address space.
        /// </summary>
        public XmlSchemaGenerator(
            string inputPath,
            string outputDirectory,
            Dictionary<string, string>
            knownFiles,
            string resourcePath,
            IReadOnlyList<string> exclusions)
        :
            base(inputPath, outputDirectory, knownFiles, exclusions)
        {
        }

        /// <summary>
        /// Generates the datatype files.
        /// </summary>
        public virtual void Generate(
            string fileName,
            string namespacePrefix,
            string dictionaryName,
            bool exportAll)
        {
            TargetNamespace = XmlSchemas.Types;
            m_exportAll = exportAll;

            WriteTemplate_XmlSchema(fileName, dictionaryName);

            // only write WSDL is services exist.
            foreach (DataType datatype in Dictionary.Items)
            {
                if (datatype is ServiceType)
                {
                    WriteTemplate_ServicesWsdl(fileName, namespacePrefix);
                    WriteTemplate_EndpointWsdl(fileName, namespacePrefix);
                    break;
                }
            }
        }

        /// <summary>
        /// Writes the address space declaration file.
        /// </summary>
        private void WriteTemplate_EndpointWsdl(string fileName, string namespacePrefix)
        {
            var writer = new StreamWriter(CoreUtils.Format(
                @"{0}\{1}.Endpoints.wsdl",
                OutputDirectory,
                namespacePrefix,
                fileName), false);
            try
            {
                var template = new Template(
                    writer,
                    TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Endpoint_wsdl);

                template.Replacements.Add("_BuildDate_", CoreUtils.Format("{0:yyyy-MM-dd}", DateTime.UtcNow));
                template.Replacements.Add("_Version_", CoreUtils.Format(
                    "{0}.{1}",
                    CoreUtils.GetAssemblySoftwareVersion(),
                    CoreUtils.GetAssemblyBuildNumber()));
                template.Replacements.Add("_Namespace_", TargetNamespace);
                template.Replacements.Add("_NamespacePrefix_", fileName);
                template.Replacements.Add("_EndpointsNamespace_", XmlSchemas.Endpoints);
                template.Replacements.Add("_ServicesNamespace_", XmlSchemas.Services);
                template.Replacements.Add("_TypesNamespace_", XmlSchemas.Types);

                AddTemplate(
                     template,
                     "<!-- Session Binding List -->",
                     TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Binding_wsdl,
                     GetListOfServices(InterfaceType.Session),
                     null,
                     new WriteTemplateEventHandler(WriteTemplate_Message));

                AddTemplate(
                     template,
                     "<!-- Discovery Binding List -->",
                     TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Binding_wsdl,
                     GetListOfServices(InterfaceType.Discovery),
                     null,
                     new WriteTemplateEventHandler(WriteTemplate_Message));

                AddTemplate(
                     template,
                     "<!-- Registration Binding List -->",
                     TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Binding_wsdl,
                     GetListOfServices(InterfaceType.Registration),
                     null,
                     new WriteTemplateEventHandler(WriteTemplate_Message));

                template.WriteTemplate(null);
            }
            finally
            {
                writer.Close();
            }
        }

        /// <summary>
        /// Writes the address space declaration file.
        /// </summary>
        private void WriteTemplate_ServicesWsdl(string fileName, string namespacePrefix)
        {
            var writer = new StreamWriter(CoreUtils.Format(
                @"{0}\{1}.Services.wsdl",
                OutputDirectory,
                namespacePrefix,
                fileName), false);

            try
            {
                var template = new Template(
                    writer,
                    TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Services_wsdl);

                template.Replacements.Add("_BuildDate_", CoreUtils.Format(
                    "{0:yyyy-MM-dd}",
                    DateTime.UtcNow));
                template.Replacements.Add("_Version_", CoreUtils.Format(
                    "{0}.{1}",
                    CoreUtils.GetAssemblySoftwareVersion(),
                    CoreUtils.GetAssemblyBuildNumber()));
                template.Replacements.Add("_Namespace_", TargetNamespace);
                template.Replacements.Add("_NamespacePrefix_", fileName);
                template.Replacements.Add("_ServicesNamespace_", XmlSchemas.Services);
                template.Replacements.Add("_TypesNamespace_", XmlSchemas.Types);

                AddTemplate(
                     template,
                     "<!-- Message List -->",
                     TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Message_wsdl,
                     GetListOfTypes(typeof(ServiceType), m_exportAll, true),
                     null,
                     new WriteTemplateEventHandler(WriteTemplate_Message));

                AddTemplate(
                     template,
                     "<!-- Session Operation List -->",
                     TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_PortType_wsdl,
                     GetListOfServices(InterfaceType.Session),
                     null,
                     new WriteTemplateEventHandler(WriteTemplate_Message));

                AddTemplate(
                     template,
                     "<!-- Discovery Operation List -->",
                     TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_PortType_wsdl,
                     GetListOfServices(InterfaceType.Discovery),
                     null,
                     new WriteTemplateEventHandler(WriteTemplate_Message));

                AddTemplate(
                     template,
                     "<!-- Registration Operation List -->",
                     TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_PortType_wsdl,
                     GetListOfServices(InterfaceType.Registration),
                     null,
                     new WriteTemplateEventHandler(WriteTemplate_Message));

                template.WriteTemplate(null);
            }
            finally
            {
                writer.Close();
            }
        }

        /// <summary>
        /// Returns a list of services filter by their interface type.
        /// </summary>
        private List<ServiceType> GetListOfServices(InterfaceType interfaceType)
        {
            List<DataType> datatypes = [.. GetListOfTypes(typeof(ServiceType), m_exportAll, true)];

            List<ServiceType> services = [];

            for (int ii = 0; ii < datatypes.Count; ii++)
            {
                if (datatypes[ii] is ServiceType serviceType &&
                    serviceType.InterfaceType == interfaceType)
                {
                    services.Add(serviceType);
                }
            }

            return services;
        }

        /// <summary>
        /// Writes an array declaration to the stream.
        /// </summary>
        private bool WriteTemplate_Message(Template template, Context context)
        {
            if (context.Target is not ServiceType datatype)
            {
                return false;
            }

            template.AddReplacement("_Namespace_", TargetNamespace);
            template.AddReplacement("_ServicesNamespace_", XmlSchemas.Services);
            template.AddReplacement("_TypesNamespace_", XmlSchemas.Types);
            template.AddReplacement("_NAME_", datatype.QName.Name);

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes the address space declaration file.
        /// </summary>
        private void WriteTemplate_XmlSchema(string fileName, string dictionaryName)
        {
            var writer = new StreamWriter(CoreUtils.Format(
                @"{0}\{1}.Types.xsd",
                OutputDirectory,
                fileName,
                dictionaryName), false);

            try
            {
                var template = new Template(
                    writer,
                    TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_File_xml);

                template.Replacements.Add("_BuildDate_", CoreUtils.Format(
                    "{0:yyyy-MM-dd}",
                    DateTime.UtcNow));
                template.Replacements.Add("_Version_", CoreUtils.Format(
                    "{0}.{1}",
                    CoreUtils.GetAssemblySoftwareVersion(),
                    CoreUtils.GetAssemblyBuildNumber()));
                template.Replacements.Add("_Namespace_", TargetNamespace);

                var buffer = new StringBuilder();
                buffer.AppendFormat(
                    CultureInfo.InvariantCulture,
                    "xmlns:tns=\"{0}\"",
                    TargetNamespace);

                if (!m_exportAll)
                {
                    for (int ii = 1; ii < NamespaceUris.Count; ii++)
                    {
                        buffer.Append(template.NewLine)
                            .Append("  ")
                            .AppendFormat(
                            CultureInfo.InvariantCulture,
                            "xmlns:s{0}=\"{1}\"",
                            ii - 1,
                            NamespaceUris[ii]);
                    }
                }

                template.Replacements.Add("xmlns:s0=\"ListOfNamespaces\"", buffer.ToString());

                List<string> imports = [Namespaces.OpcUaBuiltInTypes];

                if (!m_exportAll)
                {
                    for (int ii = 1; ii < NamespaceUris.Count; ii++)
                    {
                        imports.Add(NamespaceUris[ii]);
                    }
                }

                AddTemplate(
                    template,
                    "<!-- Imports -->",
                    null,
                    imports,
                    new LoadTemplateEventHandler(LoadTemplate_Imports),
                    null);

                AddTemplate(
                     template,
                     "<!-- ListOfTypes -->",
                     TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_OpaqueType_xml,
                     GetListOfTypes(m_exportAll),
                     new LoadTemplateEventHandler(LoadTemplate_DataType),
                     new WriteTemplateEventHandler(WriteTemplate_DataType));

                template.WriteTemplate(null);
            }
            finally
            {
                writer.Close();
            }
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
                "<xs:import namespace=\"{0}\" schemaLocation=\"{1}.xsd\" />",
                uri,
                location);
        }

        /// <summary>
        /// Writes the import statements.
        /// </summary>
        private string LoadTemplate_Imports(Template template, Context context)
        {
            if (context.Target is not string namespaceUri)
            {
                return null;
            }

            if (!m_exportAll)
            {
                template.WriteLine(string.Empty);
                template.Write(context.Prefix);

                if (namespaceUri == Namespaces.OpcUaBuiltInTypes)
                {
                    template.Write(
                        "<xs:import namespace=\"{0}\" schemaLocation=\"BuiltInTypes.xsd\" />",
                        Namespaces.OpcUaBuiltInTypes);
                }
                else
                {
                    template.Write(GetImportStatment(namespaceUri));
                }

                return null;
            }

            return TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_BuiltInTypes_xsd;
        }

        /// <summary>
        /// Writes the attributes for a node.
        /// </summary>
        private string LoadTemplate_DataType(Template template, Context context)
        {
            // do not publish type declarations in OPC BinarySchema files.
            if (typeof(TypeDeclaration).IsInstanceOfType(context.Target))
            {
                return null;
            }

            if (typeof(ComplexType).IsInstanceOfType(context.Target))
            {
                if (!((ComplexType)context.Target).BaseType.IsNull())
                {
                    return TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_DerivedType_xml;
                }

                return TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_ComplexType_xml;
            }

            if (typeof(EnumeratedType).IsInstanceOfType(context.Target))
            {
                return TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_EnumeratedType_xml;
            }

            if (typeof(ServiceType).IsInstanceOfType(context.Target))
            {
                return TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_ServiceType_xml;
            }

            // do not publish unrecognized sub-types.
            return null;
        }

        /// <summary>
        /// Writes a datatype to the stream.
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        private bool WriteTemplate_DataType(Template template, Context context)
        {
            if (context.Target is not DataType datatype)
            {
                return false;
            }

            template.AddReplacement("_TypeName_", datatype.QName.Name);
            CreateDescription(template, "_Description_", datatype.Documentation);

            AddTemplate(
                template,
                "<!-- ArrayDeclaration -->",
                TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Array_xml,
                new DataType[] { datatype },
                null,
                new WriteTemplateEventHandler(WriteTemplate_Array));

            if (datatype is ComplexType complexType)
            {
                if (!complexType.BaseType.IsNull())
                {
                    DataType basetype = Validator.ResolveType(complexType.BaseType) ??
                        throw new InvalidOperationException(CoreUtils.Format(
                            "Could not find base type '{0}' for complex type '{1}'.",
                            complexType.BaseType,
                            complexType.QName));

                    template.AddReplacement("_BaseType_", GetXmlSchemaTypeName(basetype.QName, -1));
                }

                List<FieldType> fields = [];

                foreach (FieldType field in complexType.Field)
                {
                    if (!TypeDictionaryValidator.IsExcluded(Exclusions, field))
                    {
                        fields.Add(field);
                    }
                }

                AddTemplate(
                    template,
                    "<!-- ListOfFields -->",
                    TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Field_xml,
                    fields,
                    new LoadTemplateEventHandler(LoadTemplate_Field),
                    null);
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

                AddTemplate(
                    template,
                    "<!-- ListOfValues -->",
                    TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_EnumeratedValue_xml,
                    values,
                    new LoadTemplateEventHandler(LoadTemplate_EnumeratedValue),
                    null);
            }

            if (datatype is ServiceType serviceType)
            {
                AddTemplate(
                    template,
                    "<!-- ListOfRequestParameters -->",
                    TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Field_xml,
                    serviceType.Request,
                    new LoadTemplateEventHandler(LoadTemplate_Field),
                    null);

                AddTemplate(
                    template,
                    "<!-- ListOfResponseParameters -->",
                    TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Field_xml,
                    serviceType.Response,
                    new LoadTemplateEventHandler(LoadTemplate_Field),
                    null);
            }

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes an array declaration to the stream.
        /// </summary>
        private bool WriteTemplate_Array(Template template, Context context)
        {
            if (context.Target is not DataType datatype)
            {
                return false;
            }

            if (!datatype.AllowArrays)
            {
                return false;
            }

            template.WriteLine(string.Empty);
            template.AddReplacement("_TypeName_", datatype.QName.Name);

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes a field in an OPCBinary schema.
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        private string LoadTemplate_Field(Template template, Context context)
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

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write("<xs:element name=\"{0}\"", fieldType.Name);

            if (datatype.Name == "XmlElement" && fieldType.ValueRank < 0)
            {
                template.WriteLine(">");
                template.WriteLine("{0}  <xs:complexType>", context.Prefix);
                template.WriteLine("{0}    <xs:sequence>", context.Prefix);
                template.WriteLine("{0}      <xs:any minOccurs=\"0\" processContents=\"lax\" />", context.Prefix);
                template.WriteLine("{0}    </xs:sequence>", context.Prefix);
                template.WriteLine("{0}  </xs:complexType>", context.Prefix);

                template.Write("{0}</xs:element>", context.Prefix);
            }
            else
            {
                template.Write(" type=\"{0}\" minOccurs=\"0\"", GetXmlSchemaTypeName(datatype.QName, fieldType.ValueRank));

                if (datatype.Name is "String" or "ByteString")
                {
                    template.Write(" nillable=\"true\"");
                }

                template.Write(" />");
            }

            return null;
        }

        /// <summary>
        /// Writes an enumerated value in an OPCBinary schema.
        /// </summary>
        private string LoadTemplate_EnumeratedValue(Template template, Context context)
        {
            if (context.Target is not EnumeratedValue valueType)
            {
                return null;
            }

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write("<xs:enumeration value=\"{0}_{1}\" />", valueType.Name, valueType.Value);

            /*
            if (valueType.Value != 1)
            {
                template.WriteLine(">");
                template.WriteLine("{0}  <xs:annotation>", context.Prefix);
                template.WriteLine("{0}    <xs:appinfo>", context.Prefix);
                template.WriteLine("{0}      <EnumerationValue xmlns=\"http://schemas.microsoft.com/2003/10/Serialization/\">{1}</EnumerationValue>", context.Prefix, valueType.Value);
                template.WriteLine("{0}    </xs:appinfo>", context.Prefix);
                template.WriteLine("{0}  </xs:annotation>", context.Prefix);
                template.WriteLine("{0}</xs:enumeration>", context.Prefix);
            }
            else
            {
                template.Write(" />");
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
