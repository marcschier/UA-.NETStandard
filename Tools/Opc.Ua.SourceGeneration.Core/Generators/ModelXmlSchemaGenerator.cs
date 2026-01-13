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
using System.Linq;
using System.Xml;
using Opc.Ua.Schema.Model;
using Opc.Ua.Types;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Generates XML schema files from model designs.
    /// </summary>
    internal sealed class ModelXmlSchemaGenerator
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ModelXmlSchemaGenerator"/> class.
        /// </summary>
        public ModelXmlSchemaGenerator(
            IFileSystem fileSystem,
            string outputFolder,
            ModelDesignValidator validator)
        {
            m_fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
            m_outputFolder = outputFolder ?? throw new ArgumentNullException(nameof(outputFolder));
            m_validator = validator ?? throw new ArgumentNullException(nameof(validator));
        }

        /// <summary>
        /// Generates the XML schema file for the supplied nodes.
        /// </summary>
        public void Emit()
        {
            using TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(
                m_outputFolder,
                CoreUtils.Format("{0}.Types.xsd", m_validator.Dictionary.TargetNamespaceInfo.Prefix)));

            using var templateWriter = new TemplateWriter(writer);
            var template = new Template(templateWriter, SchemaTemplates.XmlSchema_File_xml);

            if (!string.IsNullOrEmpty(m_validator.Dictionary.TargetNamespaceInfo.XmlNamespace))
            {
                template.AddReplacement(Tokens.Namespace, m_validator.Dictionary.TargetNamespaceInfo.XmlNamespace);
            }
            else
            {
                template.AddReplacement(Tokens.Namespace, m_validator.Dictionary.TargetNamespaceInfo.Value);
            }

            template.AddReplacement(Tokens.TargetVersion, m_validator.Dictionary.TargetVersion);
            template.AddReplacement(Tokens.ModelUri, m_validator.Dictionary.TargetNamespaceInfo.Value);
            template.AddReplacement(Tokens.TargetPublicationDate, XmlConvert.ToString(
                m_validator.Dictionary.TargetPublicationDate,
                XmlDateTimeSerializationMode.Utc));

            template.AddReplacement(
                Tokens.XmlnsS0ListOfNamespaces,
                m_validator.Dictionary.Namespaces,
                LoadTemplate_XmlNamespaceImports);

            template.AddReplacement(
                Tokens.Imports,
                m_validator.Dictionary.Namespaces,
                LoadTemplate_XmlNamespaceImports);

            template.AddReplacement(
                Tokens.BuiltInTypes,
                SchemaTemplates.Stack_XmlSchema_BuiltInTypes_xsd,
                [m_validator.Dictionary],
                LoadTemplate_XmlType,
                WriteTemplate_XmlType);

            template.AddReplacement(
                Tokens.ListOfTypes,
                m_validator.GetNodeDesigns().ToArray(),
                LoadTemplate_XmlType,
                WriteTemplate_XmlType);

            template.Render();
        }

        private TemplateString LoadTemplate_XmlNamespaceImports(ILoadContext context)
        {
            if (context.Target is not Namespace ns)
            {
                return null;
            }

            if (ns.Value == m_validator.Dictionary.TargetNamespace)
            {
                return null;
            }

            string uri = ns.Value;

            if (!string.IsNullOrEmpty(ns.XmlNamespace))
            {
                uri = ns.XmlNamespace;
            }

            if (context.Token == Tokens.XmlnsS0ListOfNamespaces)
            {
                if (ns.Value == Namespaces.OpcUa)
                {
                    return null;
                }

                context.Out.WriteLine(
                    "xmlns:{0}=\"{1}\"",
                    m_validator.Dictionary.Namespaces.GetXmlNamespacePrefix(ns.Value),
                    uri);

                return null;
            }

            context.Out.WriteLine("<xs:import namespace=\"{0}\" />", uri);

            return null;
        }

        private TemplateString LoadTemplate_XmlType(ILoadContext context)
        {
            if (context.Target is ModelDesign)
            {
                if (m_validator.Dictionary.TargetNamespace == Namespaces.OpcUa)
                {
                    return context.TemplateString;
                }

                return null;
            }

            if (context.Target is not DataTypeDesign dataType)
            {
                return null;
            }

            // don't write built-in types.
            if (dataType.NumericId < 256 && dataType.SymbolicId.Namespace == Namespaces.OpcUa)
            {
                switch (dataType.NumericId)
                {
                    case DataTypes.PermissionType:
                    case DataTypes.RolePermissionType:
                    case DataTypes.DataTypeDefinition:
                    case DataTypes.StructureDefinition:
                    case DataTypes.StructureField:
                    case DataTypes.StructureType:
                    case DataTypes.EnumDefinition:
                    case DataTypes.EnumField:
                        break;
                    default:
                        return null;
                }
            }

            BasicDataType basicType = dataType.BasicDataType;

            if (basicType == BasicDataType.Enumeration)
            {
                var baseType = dataType.BaseTypeNode as DataTypeDesign;

                if (baseType?.SymbolicId == new XmlQualifiedName("OptionSet", Namespaces.OpcUa))
                {
                    return SchemaTemplates.XmlSchema_DerivedType_xml;
                }

                return SchemaTemplates.XmlSchema_EnumeratedType_xml;
            }
            else if (basicType == BasicDataType.UserDefined)
            {
                if (dataType.BaseTypeNode.SymbolicName.Name == "Union")
                {
                    return SchemaTemplates.XmlSchema_Union_xml;
                }
                else if (dataType.BaseTypeNode.SymbolicName.Name == "Structure")
                {
                    return SchemaTemplates.XmlSchema_ComplexType_xml;
                }
                else
                {
                    return SchemaTemplates.XmlSchema_DerivedType_xml;
                }
            }

            return SchemaTemplates.XmlSchema_SimpleType_xml;
        }

        private bool WriteTemplate_XmlType(IWriteContext context)
        {
            if (context.Target is ModelDesign model)
            {
                if (m_validator.Dictionary.TargetNamespace == Namespaces.OpcUa)
                {
                    return context.Template.Render();
                }

                return false;
            }

            if (context.Target is not DataTypeDesign dataType)
            {
                return false;
            }

            var baseType = dataType.BaseTypeNode as DataTypeDesign;

            if (baseType != null)
            {
                context.Template.AddReplacement(Tokens.BaseType, baseType.GetXmlDataType(
                    ValueRank.Scalar,
                    m_validator.Dictionary.TargetNamespace,
                    m_validator.Dictionary.Namespaces));
            }

            context.Template.AddReplacement(Tokens.TypeName, dataType.SymbolicName.Name);

            if (dataType.BasicDataType == BasicDataType.Enumeration && dataType.IsOptionSet)
            {
                context.Template.AddReplacement(Tokens.XsRestrictionBaseType,
                    baseType.GetXmlDataType(
                        ValueRank.Scalar,
                        m_validator.Dictionary.TargetNamespace,
                        m_validator.Dictionary.Namespaces));
            }
            else
            {
                context.Template.AddReplacement(Tokens.XsRestrictionBaseType, "xs:string");
            }

            context.Template.AddReplacement(
                Tokens.Documentation,
                SchemaTemplates.XmlSchema_Documentation_xml,
                new object[] { dataType },
                LoadTemplate_XmlDocumentation,
                WriteTemplate_XmlDocumentation);

            context.Template.AddReplacement(
                Tokens.CollectionType,
                SchemaTemplates.XmlSchema_CollectionType_xml,
                new object[] { dataType },
                LoadTemplate_XmlCollectionType,
                WriteTemplate_XmlCollectionType);

            context.Template.AddReplacement(
                Tokens.ListOfFields,
                dataType.Fields,
                LoadTemplate_XmlTypeFields);

            return context.Template.Render();
        }

        private TemplateString LoadTemplate_XmlTypeFields(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            if (field.Parent is not DataTypeDesign dataType)
            {
                return null;
            }

            BasicDataType basicType = dataType.BasicDataType;

            if (basicType == BasicDataType.Enumeration)
            {
                if (dataType.IsOptionSet)
                {
                    return null;
                }

                if (field.IdentifierInName)
                {
                    context.Out.WriteLine(
                        "<xs:enumeration value=\"{0}\" />",
                        field.Name);
                    return null;
                }

                context.Out.WriteLine(
                    "<xs:enumeration value=\"{0}_{1}\" />",
                    field.Name,
                    field.Identifier);
                return null;
            }

            basicType = field.DataTypeNode.BasicDataType;

            if (basicType == BasicDataType.XmlElement &&
                field.ValueRank == ValueRank.Scalar)
            {
                context.Out.WriteLine("<xs:element name=\"{0}\" minOccurs=\"0\" nillable=\"true\">", field.Name);
                context.Out.WriteLine("  <xs:complexType>");
                context.Out.WriteLine("    <xs:sequence>");
                context.Out.WriteLine("      <xs:any minOccurs=\"0\" processContents=\"lax\" />");
                context.Out.WriteLine("    </xs:sequence>");
                context.Out.WriteLine("  </xs:complexType>");
                context.Out.WriteLine("</xs:element>");
                return null;
            }

            if (field.ValueRank != ValueRank.Scalar)
            {
                string fieldDataType = field.DataTypeNode.GetXmlDataType(
                    field.ValueRank,
                    m_validator.Dictionary.TargetNamespace,
                    m_validator.Dictionary.Namespaces);

                if (basicType == BasicDataType.UserDefined && field.AllowSubTypes)
                {
                    fieldDataType = "ua:ListOfExtensionObject";
                }

                context.Out.WriteLine(
                    "<xs:element name=\"{0}\" type=\"{1}\" minOccurs=\"0\" nillable=\"true\" />",
                    field.Name,
                    fieldDataType);
            }
            else
            {
                switch (basicType)
                {
                    case BasicDataType.String:
                    case BasicDataType.ByteString:
                    case BasicDataType.DiagnosticInfo:
                    case BasicDataType.ExpandedNodeId:
                    case BasicDataType.LocalizedText:
                    case BasicDataType.NodeId:
                    case BasicDataType.QualifiedName:
                    case BasicDataType.Structure:
                    case BasicDataType.DataValue:
                        context.Out.WriteLine(
                                "<xs:element name=\"{0}\" type=\"{1}\" minOccurs=\"0\" nillable=\"true\" />",
                                field.Name,
                                field.DataTypeNode.GetXmlDataType(
                                    field.ValueRank,
                                    m_validator.Dictionary.TargetNamespace,
                                    m_validator.Dictionary.Namespaces));
                        break;
                    case BasicDataType.Guid:
                    case BasicDataType.StatusCode:
                        context.Out.WriteLine(
                                "<xs:element name=\"{0}\" type=\"{1}\" minOccurs=\"0\" />",
                                field.Name,
                                field.DataTypeNode.GetXmlDataType(
                                    field.ValueRank,
                                    m_validator.Dictionary.TargetNamespace,
                                    m_validator.Dictionary.Namespaces));
                        break;
                    case BasicDataType.UserDefined:
                        string fieldDataType = field.DataTypeNode.GetXmlDataType(
                                field.ValueRank,
                                m_validator.Dictionary.TargetNamespace,
                                m_validator.Dictionary.Namespaces);

                        if (field.AllowSubTypes)
                        {
                            fieldDataType = "ua:ExtensionObject";
                        }

                        context.Out.WriteLine(
                            "<xs:element name=\"{0}\" type=\"{1}\" minOccurs=\"0\" nillable=\"true\" />",
                            field.Name,
                            fieldDataType);
                        break;
                    default:
                        context.Out.WriteLine("<xs:element name=\"{0}\" type=\"{1}\" minOccurs=\"0\" />",
                                field.Name,
                                field.DataTypeNode.GetXmlDataType(
                                    field.ValueRank,
                                    m_validator.Dictionary.TargetNamespace,
                                    m_validator.Dictionary.Namespaces));
                        break;
                }
            }

            return null;
        }

        private TemplateString LoadTemplate_XmlDocumentation(ILoadContext context)
        {
            if (context.Target is not DataTypeDesign dataType)
            {
                return null;
            }

            if (dataType.Description == null || dataType.Description.IsAutogenerated)
            {
                return null;
            }

            return context.TemplateString;
        }

        private bool WriteTemplate_XmlDocumentation(IWriteContext context)
        {
            if (context.Target is not DataTypeDesign dataType)
            {
                return false;
            }

            context.Template.AddReplacement(Tokens.Description, dataType.Description.Value);

            return context.Template.Render();
        }

        private TemplateString LoadTemplate_XmlCollectionType(ILoadContext context)
        {
            if (context.Target is not DataTypeDesign dataType)
            {
                return null;
            }

            if (dataType.NoArraysAllowed)
            {
                return null;
            }

            return context.TemplateString;
        }

        private bool WriteTemplate_XmlCollectionType(IWriteContext context)
        {
            if (context.Target is not DataTypeDesign dataType)
            {
                return false;
            }

            context.Template.AddReplacement(Tokens.TypeName, dataType.SymbolicName.Name);
            context.Template.AddReplacement(
                Tokens.Nillable,
                !dataType.BasicDataType.IsXmlNillable() ?
                    string.Empty : "nillable=\"true\" ");

            return context.Template.Render();
        }

        private readonly IFileSystem m_fileSystem;
        private readonly string m_outputFolder;
        private readonly ModelDesignValidator m_validator;
    }
}
