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
    public class BinarySchemaGenerator : SchemaGenerator
    {
        /// <summary>
        /// Generates the code from the contents of the address space.
        /// </summary>
        public BinarySchemaGenerator(
            string inputPath,
            string outputDirectory,
            Dictionary<string, string> knownFiles,
            string resourcePath,
            IReadOnlyList<string> exclusions)
        :
            base(inputPath, outputDirectory, knownFiles, exclusions)
        {
        }

        /// <summary>
        /// Generates the datatype files.
        /// </summary>
        public virtual void Generate(string fileName, bool exportAll, string targetNamespace)
        {
            TargetNamespace = targetNamespace;
            m_exportAll = exportAll;

            WriteTemplate_BinarySchema(fileName);
        }

        /// <summary>
        /// Writes the address space declaration file.
        /// </summary>
        private void WriteTemplate_BinarySchema(string fileName)
        {
            var writer = new StreamWriter(CoreUtils.Format(@"{0}\{1}.bsd", OutputDirectory, fileName), false);

            try
            {
                var template = new Template(writer, TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_File_xml);

                template.Replacements.Add("_BuildDate_", CoreUtils.Format("{0:yyyy-MM-dd}", DateTime.UtcNow));
                template.Replacements.Add("_Version_", CoreUtils.Format(
                    "{0}.{1}",
                    CoreUtils.GetAssemblySoftwareVersion(),
                    CoreUtils.GetAssemblyBuildNumber()));
                template.Replacements.Add("_DictionaryUri_", TargetNamespace);

                var buffer = new StringBuilder();

                buffer.AppendFormat(CultureInfo.InvariantCulture, "xmlns=\"{0}\"", NamespaceUris[0]);

                if (!m_exportAll)
                {
                    for (int ii = 1; ii < NamespaceUris.Count; ii++)
                    {
                        buffer.Append(template.NewLine)
                            .Append("  ")
                            .AppendFormat(CultureInfo.InvariantCulture, "xmlns:s{0}=\"{1}\"", ii - 1, NamespaceUris[ii]);
                    }
                }

                template.Replacements.Add("xmlns:s0=\"ListOfNamespaces\"", buffer.ToString());

                if (!m_exportAll)
                {
                    for (int ii = 1; ii < NamespaceUris.Count; ii++)
                    {
                        ((List<string>)[Namespaces.OpcUaBuiltInTypes]).Add(NamespaceUris[ii]);
                    }
                }

                AddTemplate(
                    template,
                    "<!-- Imports -->",
                    null,
                    (List<string>)[Namespaces.OpcUaBuiltInTypes],
                    new LoadTemplateEventHandler(LoadTemplate_Imports),
                    null);

                AddTemplate(
                    template,
                    "<!-- ListOfTypes -->",
                    TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_OpaqueType_xml,
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

            return CoreUtils.Format("<opc:Import Namespace=\"{0}\" Location=\"{1}.bsd\" />", uri, location);
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
                    template.Write("<opc:Import Namespace=\"{0}\" />", Namespaces.OpcUaBuiltInTypes);
                }
                else
                {
                    template.Write(GetImportStatment(namespaceUri));
                }

                return null;
            }

            return TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_BuiltInTypes_bsd;
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
                var complexType = context.Target as ComplexType;

                // do not publish types with no fields.
                if (complexType.Field == null || complexType.Field.Length == 0)
                {
                    return null;
                }

                return TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_ComplexType_xml;
            }

            if (typeof(EnumeratedType).IsInstanceOfType(context.Target))
            {
                return TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_EnumeratedType_xml;
            }

            if (typeof(ServiceType).IsInstanceOfType(context.Target))
            {
                return TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_ServiceType_xml;
            }

            // do not publish unrecognized sub-types.
            return null;
        }

        /// <summary>
        /// Writes the
        /// </summary>
        private bool WriteTemplate_DataType(Template template, Context context)
        {
            if (context.Target is not DataType datatype)
            {
                return false;
            }

            template.AddReplacement("_TypeName_", datatype.QName.Name);
            CreateDescription(template, "_Description_", datatype.Documentation);

            if (datatype is ComplexType complexType)
            {
                List<FieldType> fields = [];
                GetFields(complexType, fields);

                AddTemplate(
                    template,
                    "<!-- ListOfFields -->",
                    TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_Field_xml,
                    fields,
                    new LoadTemplateEventHandler(LoadTemplate_Field),
                    null);
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

                template.AddReplacement("_LengthInBits_", lengthInBits);
                template.AddReplacement("_IsOptionSet_", isOptionSet ? " IsOptionSet=\"true\"" : string.Empty);

                AddTemplate(
                    template,
                    "<!-- ListOfValues -->",
                    TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_EnumeratedValue_xml,
                    values,
                    new LoadTemplateEventHandler(LoadTemplate_EnumeratedValue),
                    null);
            }

            if (datatype is ServiceType serviceType)
            {
                AddTemplate(
                    template,
                    "<!-- ListOfRequestParameters -->",
                    TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_Field_xml,
                    serviceType.Request,
                    new LoadTemplateEventHandler(LoadTemplate_Field),
                    null);

                AddTemplate(
                    template,
                    "<!-- ListOfResponseParameters -->",
                    TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_Field_xml,
                    serviceType.Response,
                    new LoadTemplateEventHandler(LoadTemplate_Field),
                    null);
            }

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

            if (fieldType.ValueRank == 0)
            {
                template.WriteLine("<opc:Field Name=\"NoOf{0}\" TypeName=\"opc:Int32\" />", fieldType.Name);
                template.Write(context.Prefix);
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
        private string LoadTemplate_EnumeratedValue(Template template, Context context)
        {
            if (context.Target is not EnumeratedValue valueType)
            {
                return null;
            }

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write("<opc:EnumeratedValue Name=\"{0}\" Value=\"{1}\" />", valueType.Name, valueType.Value);

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
