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
    /// Generates binary schema files from model designs.
    /// </summary>
    internal sealed class ModelBinarySchemaGenerator
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ModelBinarySchemaGenerator"/> class.
        /// </summary>
        public ModelBinarySchemaGenerator(
            IFileSystem fileSystem,
            string outputFolder,
            ModelDesignValidator validator)
        {
            m_fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
            m_outputFolder = outputFolder ?? throw new ArgumentNullException(nameof(outputFolder));
            m_validator = validator ?? throw new ArgumentNullException(nameof(validator));
        }

        /// <summary>
        /// Generates the binary schema file for the supplied nodes.
        /// </summary>
        public void Emit()
        {
            using TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(
                m_outputFolder,
                CoreUtils.Format("{0}.Types.bsd", m_validator.Dictionary.TargetNamespaceInfo.Prefix)));

            using var templateWriter = new TemplateWriter(writer);
            var template = new Template(templateWriter, SchemaTemplates.BinarySchema_File_xml);

            template.AddReplacement(Tokens.DictionaryUri, m_validator.Dictionary.TargetNamespace);

            template.AddReplacement(
                Tokens.XmlnsS0ListOfNamespaces,
                m_validator.Dictionary.Namespaces,
                LoadTemplate_BinaryNamespaceImports);

            template.AddReplacement(
                Tokens.Imports,
                m_validator.Dictionary.Namespaces,
                LoadTemplate_BinaryNamespaceImports);

            template.AddReplacement(
                Tokens.BuiltInTypes,
                SchemaTemplates.BinarySchema_BuiltInTypes_bsd,
                new[] { m_validator.Dictionary },
                LoadTemplate_BinaryType,
                WriteTemplate_BinaryType);

            template.AddReplacement(
                Tokens.ListOfTypes,
                m_validator.GetNodeDesigns().ToArray(),
                LoadTemplate_BinaryType,
                WriteTemplate_BinaryType);

            template.Render();
        }

        private TemplateString LoadTemplate_BinaryNamespaceImports(ILoadContext context)
        {
            if (context.Target is not Namespace ns)
            {
                return null;
            }

            if (ns.Value == m_validator.Dictionary.TargetNamespace)
            {
                return null;
            }

            if (context.Token == Tokens.XmlnsS0ListOfNamespaces)
            {
                if (ns.Value == Namespaces.OpcUa)
                {
                    return null;
                }

                context.Out.WriteLine(
                    "\nxmlns:{0}=\"{1}\"\n",
                    m_validator.Dictionary.Namespaces.GetXmlNamespacePrefix(ns.Value),
                    ns.Value);
                return null;
            }

            context.Out.WriteLine(
                "<opc:Import Namespace=\"{0}\" Location=\"{1}.BinarySchema.bsd\"/>",
                ns.Value,
                m_validator.Dictionary.Namespaces.GetNamespacePrefix(ns.Value));

            return null;
        }

        private TemplateString LoadTemplate_BinaryType(ILoadContext context)
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
                    case DataTypes.AccessRestrictionType:
                    case DataTypes.RolePermissionType:
                    case DataTypes.StructureDefinition:
                    case DataTypes.StructureField:
                    case DataTypes.StructureType:
                    case DataTypes.EnumDefinition:
                    case DataTypes.EnumField:
                    case DataTypes.DataTypeDefinition:
                    case DataTypes.Enumeration:
                    case DataTypes.Union:
                        break;
                    default:
                        return null;
                }
            }

            if (dataType.Purpose == Schema.Model.DataTypePurpose.CodeGenerator)
            {
                return null;
            }

            BasicDataType basicType = dataType.BasicDataType;

            if (basicType == BasicDataType.Enumeration)
            {
                return SchemaTemplates.BinarySchema_EnumeratedType_xml;
            }
            else if (basicType == BasicDataType.UserDefined)
            {
                return SchemaTemplates.BinarySchema_ComplexType_xml;
            }

            return SchemaTemplates.BinarySchema_OpaqueType_xml;
        }

        private bool WriteTemplate_BinaryType(IWriteContext context)
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

            context.Template.AddReplacement(Tokens.TypeName, dataType.SymbolicName.Name);

            if (dataType.BasicDataType == BasicDataType.UserDefined)
            {
                context.Template.AddReplacement(Tokens.BaseType,
                    (dataType.BaseTypeNode as DataTypeDesign).GetBinaryDataType(
                        m_validator.Dictionary.TargetNamespace,
                        m_validator.Dictionary.Namespaces));
            }

            List<Parameter> fields = new();
            var parents = new Stack<DataTypeDesign>();

            for (DataTypeDesign parent = dataType;
                parent != null;
                parent = parent.BaseTypeNode as DataTypeDesign)
            {
                if (parent.Fields != null)
                {
                    parents.Push(parent);
                }
            }

            while (parents.Count > 0)
            {
                DataTypeDesign parent = parents.Pop();

                foreach (Parameter field in parent.Fields)
                {
                    if (m_validator.IsExcluded(field))
                    {
                        continue;
                    }

                    if (ReferenceEquals(dataType, parent))
                    {
                        fields.Add(field);
                        continue;
                    }

                    fields.Add(new Parameter
                    {
                        DataType = field.DataType,
                        DataTypeNode = field.DataTypeNode,
                        Description = field.Description,
                        Identifier = field.Identifier,
                        IdentifierInName = field.IdentifierInName,
                        IdentifierSpecified = field.IdentifierSpecified,
                        IsInherited = true,
                        Name = field.Name,
                        Parent = field.Parent,
                        ValueRank = field.ValueRank,
                        ArrayDimensions = field.ArrayDimensions,
                        AllowSubTypes = field.AllowSubTypes,
                        IsOptional = field.IsOptional,
                        BitMask = field.BitMask,
                        DefaultValue = field.DefaultValue,
                        ReleaseStatus = field.ReleaseStatus
                    });
                }
            }

            if (dataType.BasicDataType == BasicDataType.Enumeration)
            {
                uint lengthInBits = 32;
                bool isOptionSet = false;

                if (dataType.IsOptionSet)
                {
                    isOptionSet = true;

                    switch (dataType.BaseType.Name)
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

                    fields.Insert(0, new Parameter
                    {
                        Name = "None",
                        Identifier = 0,
                        IdentifierSpecified = true,
                        DataType = fields[0].DataType,
                        DataTypeNode = fields[0].DataTypeNode,
                        Parent = fields[0].Parent
                    });
                }

                context.Template.AddReplacement(Tokens.LengthInBits, lengthInBits);
                context.Template.AddReplacement(
                    Tokens.IsOptionSet,
                    isOptionSet ? " IsOptionSet=\"true\"" : string.Empty);
            }

            context.Template.AddReplacement(
                Tokens.Documentation,
                new object[] { dataType },
                LoadTemplate_BinaryDocumentation);

            context.Template.AddReplacement(
                Tokens.ListOfFields,
                fields,
                LoadTemplate_BinaryTypeFields);

            return context.Template.Render();
        }

        private TemplateString LoadTemplate_BinaryTypeFields(ILoadContext context)
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

            string fieldDataType = field.DataTypeNode.GetBinaryDataType(
                m_validator.Dictionary.TargetNamespace,
                m_validator.Dictionary.Namespaces);

            if (field.AllowSubTypes)
            {
                fieldDataType = "ua:ExtensionObject";
            }

            if (basicType == BasicDataType.Enumeration)
            {
                context.Out.WriteLine(
                    "<opc:EnumeratedValue Name=\"{0}\" Value=\"{1}\" />",
                    field.Name,
                    field.Identifier);
                return null;
            }

            if (field.ValueRank != ValueRank.Scalar)
            {
                context.Out.WriteLine(
                    "<opc:Field Name=\"NoOf{0}\" TypeName=\"opc:Int32\" />",
                    field.Name);
                context.Out.WriteLine(
                    "<opc:Field Name=\"{0}\" TypeName=\"{1}\" LengthField=\"NoOf{0}\" />",
                    field.Name,
                    fieldDataType);
                return null;
            }
            if (field.IsInherited)
            {
                context.Out.WriteLine(
                    "<opc:Field Name=\"{0}\" TypeName=\"{1}\" SourceType=\"{2}\" />",
                    field.Name,
                    fieldDataType,
                    (field.Parent as DataTypeDesign).GetBinaryDataType(
                        m_validator.Dictionary.TargetNamespace,
                        m_validator.Dictionary.Namespaces));
            }
            else
            {
                context.Out.WriteLine(
                    "<opc:Field Name=\"{0}\" TypeName=\"{1}\" />",
                    field.Name,
                    fieldDataType);
            }

            return null;
        }

        private TemplateString LoadTemplate_BinaryDocumentation(ILoadContext context)
        {
            if (context.Target is not DataTypeDesign dataType)
            {
                return null;
            }

            if (dataType.Description == null ||
                dataType.Description.IsAutogenerated)
            {
                return null;
            }

            context.Out.WriteLine(
                "<opc:Documentation>{0}</opc:Documentation>",
                dataType.Description.Value);

            return context.TemplateString;
        }

        private readonly IFileSystem m_fileSystem;
        private readonly string m_outputFolder;
        private readonly ModelDesignValidator m_validator;
    }
}
