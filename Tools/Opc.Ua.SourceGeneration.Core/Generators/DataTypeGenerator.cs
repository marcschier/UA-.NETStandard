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
    /// Generates data type model classes
    /// </summary>
    internal sealed class DataTypeGenerator : IGenerator
    {
        public DataTypeGenerator(GeneratorContext context, bool useXmlInitializers = false)
        {
            m_context = context;
            m_messageContext = new ServiceMessageContext(context.Telemetry);
            m_useXmlInitializers = useXmlInitializers;
        }

        /// <inheritdoc/>
        public void Emit()
        {
            List<DataTypeDesign> datatypes = GetDataTypes();
            if (datatypes.Count == 0)
            {
                return;
            }

            using TextWriter writer = m_context.FileSystem.CreateTextWriter(
                Path.Combine(m_context.OutputFolder, CoreUtils.Format(
                    "{0}.DataTypes.g.cs",
                    m_context.Validator.Dictionary.TargetNamespaceInfo.Prefix)));

            using var templateWriter = new TemplateWriter(writer);
            var template = new Template(templateWriter, CodeTemplates.TypesFile_cs);
            template.AddReplacement(
                Tokens.Namespace,
                m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(
                    m_context.Validator.Dictionary.TargetNamespace));
            template.AddReplacement(
                Tokens.NamespaceUri,
                m_context.Validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(
                    m_context.Validator.Dictionary.TargetNamespace));

            template.AddReplacement(
                Tokens.ListOfImports,
                m_context.Validator.Dictionary.Namespaces,
                LoadTemplate_NamespaceImports);
            template.AddReplacement(
                Tokens.ListOfTypes,
                datatypes,
                LoadTemplate_ListOfTypes,
                WriteTemplate_ListOfTypes);

            template.Render();
        }

        private TemplateString LoadTemplate_NamespaceImports(ILoadContext context)
        {
            if (context.Target is not Namespace ns)
            {
                return null;
            }

            if (ns.Value == m_context.Validator.Dictionary.TargetNamespace)
            {
                return null;
            }

            if (ns.FilePath == null && ns.Value != Namespaces.OpcUa)
            {
                return null;
            }

            string externalPrefix = m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(ns.Value);

            context.Out.WriteLine("using {0};", externalPrefix);

            return null;
        }

        private TemplateString LoadTemplate_ListOfTypes(ILoadContext context)
        {
            if (context.Target is not DataTypeDesign datatype)
            {
                return null;
            }

            switch (datatype.BasicDataType)
            {
                case BasicDataType.Structure:
                    return null;
                case BasicDataType.UserDefined:
                    if (datatype.IsUnion)
                    {
                        return CodeTemplates.DataTypes_Union_cs;
                    }

                    if (datatype.HasFields && datatype.Fields.Any(x => x.IsOptional))
                    {
                        if (datatype.IsDerivedDataType())
                        {
                            return CodeTemplates.DataTypes_DerivedClassWithOptionalFields_cs;
                        }

                        return CodeTemplates.DataTypes_ClassWithOptionalFields_cs;
                    }

                    if (!datatype.IsDerivedDataType())
                    {
                        return CodeTemplates.DataTypes_Class_cs;
                    }

                    return CodeTemplates.DataTypes_DerivedClass_cs;
                case BasicDataType.Enumeration:
                    var baseType = datatype.BaseTypeNode as DataTypeDesign;

                    if (baseType?.SymbolicId == new XmlQualifiedName("OptionSet", Namespaces.OpcUa))
                    {
                        return CodeTemplates.DataTypes_DerivedClass_cs;
                    }

                    return CodeTemplates.DataTypes_Enumeration_cs;
                default:
                    if (datatype.IsOptionSet)
                    {
                        return CodeTemplates.DataTypes_Enumeration_cs;
                    }

                    return null;
            }
        }

        private bool WriteTemplate_ListOfTypes(IWriteContext context)
        {
            if (context.Target is not DataTypeDesign dataType)
            {
                return false;
            }

            Parameter[] fields = GetFields(dataType);

            context.Template.AddReplacement(Tokens.NodeClass, dataType.GetNodeClassString());
            context.Template.AddReplacement(
                Tokens.Description,
                dataType.Description != null ? dataType.Description.Value : string.Empty);
            context.Template.AddReplacement(Tokens.Encoding, EncodingString);
            context.Template.AddReplacement(Tokens.TypeName, dataType.SymbolicName.Name);
            context.Template.AddReplacement(
                Tokens.NamespaceUri,
                m_context.Validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(
                    dataType.SymbolicName.Namespace));
            context.Template.AddReplacement(
                Tokens.NamespacePrefix,
                m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(
                    dataType.SymbolicId.Namespace));
            context.Template.AddReplacement(
                Tokens.XmlNamespaceUri,
                m_context.Validator.Dictionary.Namespaces.GetConstantForXmlNamespace(
                    dataType.SymbolicId.Namespace));

            context.Template.AddReplacement(
                Tokens.BrowseName,
                dataType.SymbolicName.Name);
            context.Template.AddReplacement(
                Tokens.BrowseNameNamespacePrefix,
                m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(
                    dataType.SymbolicName.Namespace));
            context.Template.AddReplacement(
                Tokens.BrowseNameNamespaceUri,
                m_context.Validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(
                    dataType.SymbolicName.Namespace));

            context.Template.AddReplacement(
                  Tokens.ClassName,
                  dataType.ClassName);
            context.Template.AddReplacement(
                Tokens.BaseType,
                dataType.GetBaseClassName(m_context.Validator.Dictionary.Namespaces));
            context.Template.AddReplacement(
                Tokens.BaseTypeNamespacePrefix,
                m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(
                    dataType.BaseTypeNode.SymbolicId.Namespace));
            context.Template.AddReplacement(
                Tokens.BaseTypeNamespaceUri,
                m_context.Validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(
                    dataType.BaseTypeNode.SymbolicId.Namespace));
            context.Template.AddReplacement(
                Tokens.BaseClassName,
                dataType.BaseTypeNode.FixClassName());

            List<Parameter> completeListOfFields = null;

            if (dataType.IsStructure)
            {
                List<DataTypeDesign> inheritanceTree = [dataType];
                var parentDataType = dataType.BaseTypeNode as DataTypeDesign;

                while (parentDataType != null &&
                    parentDataType.SymbolicId != new XmlQualifiedName("Structure", Namespaces.OpcUa) &&
                    parentDataType.SymbolicId != new XmlQualifiedName("Union", Namespaces.OpcUa)
                )
                {
                    inheritanceTree.Add(parentDataType);
                    parentDataType = parentDataType.BaseTypeNode as DataTypeDesign;
                }

                completeListOfFields = [];

                for (int ii = inheritanceTree.Count - 1; ii >= 0; ii--)
                {
                    foreach (object field in GetFields(inheritanceTree[ii]))
                    {
                        var parameter = (Parameter)field;

                        if (parameter.IsOptional)
                        {
                            completeListOfFields.Add(parameter);
                        }
                    }
                }
            }

            context.Template.AddReplacement(
                Tokens.IsAbstract,
                dataType.IsAbstract ? string.Empty : string.Empty);

            if (!dataType.IsOptionSet)
            {
                context.Template.AddReplacement(Tokens.Flags, string.Empty);
                context.Template.AddReplacement(Tokens.BasicType, string.Empty);
            }
            else
            {
                context.Template.AddReplacement(Tokens.Flags, "[global::System.FlagsAttribute]");
                context.Template.AddReplacement(
                    Tokens.BasicType,
                    CoreUtils.Format(" : global::System.{0}", dataType.BaseType.Name));

                var baseType = dataType.BaseTypeNode as DataTypeDesign;

                List<Parameter> clone = [];

                if (baseType?.SymbolicId != new XmlQualifiedName("OptionSet", Namespaces.OpcUa))
                {
                    var first = (Parameter)fields.GetValue(0);

                    clone.Add(new Parameter
                    {
                        Name = "None",
                        Identifier = 0,
                        IdentifierSpecified = true,
                        DataTypeNode = first.DataTypeNode,
                        DataType = first.DataType,
                        Parent = first.Parent,
                        Description = new Schema.Model.LocalizedText
                        {
                            Value = "No value specified."
                        }
                    });

                    clone.AddRange(fields.Cast<Parameter>());
                }

                fields = [.. clone];
            }

            Dictionary<string, string> encodings = new()
                {
                    { Tokens.BinaryEncodingId,
                        CoreUtils.Format("{0}_Encoding_DefaultBinary", dataType.SymbolicName.Name) },
                    { Tokens.XmlEncodingId,
                        CoreUtils.Format("{0}_Encoding_DefaultXml", dataType.SymbolicName.Name) },
                    { Tokens.JsonEncodingId,
                        CoreUtils.Format("{0}_Encoding_DefaultJson", dataType.SymbolicName.Name) }
                };
            foreach (KeyValuePair<string, string> kv in encodings)
            {
                bool isEncodingPartOfModel = m_context.Validator.Dictionary.Items.Any(x =>
                    x.SymbolicId.Name == kv.Value &&
                    x.SymbolicId.Namespace == dataType.SymbolicName.Namespace);
                if (!isEncodingPartOfModel)
                {
                    context.Template.AddReplacement(
                        kv.Key,
                        "global::Opc.Ua.NodeId.Null");
                }
                else
                {
                    context.Template.AddReplacement(
                        kv.Key,
                        CoreUtils.Format("ObjectIds.{0}", kv.Value));
                }
            }

            context.Template.AddReplacement(
                Tokens.ListOfSwitchFields,
                fields,
                LoadTemplate_ListOfSwitchFields);

            context.Template.AddReplacement(
                Tokens.ListOfEncodingMaskFields,
                completeListOfFields?.ToArray() ?? fields,
                LoadTemplate_ListOfEncodingMaskFields);

            context.Template.AddReplacement(
                Tokens.ListOfEncodedFields,
                fields,
                LoadTemplate_ListOfEncodedFields);

            context.Template.AddReplacement(
                Tokens.ListOfDecodedFields,
                fields,
                LoadTemplate_ListOfDecodedFields);

            context.Template.AddReplacement(
                Tokens.ListOfComparedFields,
                fields,
                LoadTemplate_ListOfComparedFields);

            context.Template.AddReplacement(
                Tokens.ListOfClonedFields,
                fields,
                LoadTemplate_ListOfClonedFields);

            context.Template.AddReplacement(
                Tokens.ListOfSwitchFieldNames,
                fields,
                LoadTemplate_ListOfSwitchFields);

            context.Template.AddReplacement(
                Tokens.ListOfEncodingMaskFieldNames,
                completeListOfFields?.ToArray() ?? fields,
                LoadTemplate_ListOfEncodingMaskFields);

            context.Template.AddReplacement(
                Tokens.CollectionClass,
                CodeTemplates.DataTypes_CollectionClass_cs,
                [dataType],
                LoadTemplate_CollectionClass,
                WriteTemplate_CollectionClass);

            context.Template.AddReplacement(
                Tokens.ListOfFieldInitializers,
                fields,
                LoadTemplate_ListOfFieldInitializers);

            context.Template.AddReplacement(
                Tokens.ListOfFields,
                fields,
                LoadTemplate_ListOfFields);

            context.Template.AddReplacement(
                Tokens.ListOfProperties,
                fields,
                LoadTemplate_ListOfProperties,
                WriteTemplate_ListOfProperties);

            return context.Template.Render();
        }

        private TemplateString LoadTemplate_CollectionClass(ILoadContext context)
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

        private bool WriteTemplate_CollectionClass(IWriteContext context)
        {
            if (context.Target is not DataTypeDesign dataType)
            {
                return false;
            }

            context.Template.AddReplacement(
                Tokens.XmlNamespaceUri,
                m_context.Validator.Dictionary.Namespaces.GetConstantForXmlNamespace(
                    dataType.SymbolicId.Namespace));
            context.Template.AddReplacement(Tokens.BrowseName, dataType.SymbolicName.Name);

            return context.Template.Render();
        }

        private TemplateString LoadTemplate_ListOfFields(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            context.Out.WriteLine(
                "private {0} {1};",
                field.DataTypeNode.GetDotNetTypeName(
                    field.ValueRank,
                    m_context.Validator.Dictionary.TargetNamespace,
                    m_context.Validator.Dictionary.Namespaces,
                    nullable: NullableAnnotation.NullableExceptDataTypes),
                field.GetChildFieldName());

            return null;
        }

        private TemplateString LoadTemplate_ListOfSwitchFields(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            var dataType = (DataTypeDesign)field.Parent;

            int index = context.Index + 1;
            bool isLast = index == dataType.Fields.Length;

            if (context.Token == Tokens.ListOfSwitchFieldNames)
            {
                context.Out.Write('"');
                context.Out.Write(field.Name);
                context.Out.Write('"');
            }
            else
            {
                context.Out.Write(field.Name);
                context.Out.Write(" = ");
                context.Out.Write(index.ToString(CultureInfo.InvariantCulture));
            }
            if (!isLast)
            {
                context.Out.Write(",");
            }
            context.Out.WriteLine();
            return null;
        }

        private TemplateString LoadTemplate_ListOfEncodingMaskFields(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            int index = context.Index;
            if (field.IsOptional)
            {
                if (context.Token == Tokens.ListOfEncodingMaskFieldNames)
                {
                    context.Out.Write('"');
                    context.Out.Write(field.Name);
                    context.Out.Write('"');
                }
                else
                {
                    context.Out.Write(field.Name);
                    context.Out.Write(" = 0x{0:X}", 1 << index);
                }
                context.Out.WriteLine(",");
            }
            return null;
        }

        private TemplateString LoadTemplate_ListOfEncodedFields(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            var dataType = (DataTypeDesign)field.Parent;
            bool isUnion = dataType.IsUnion;

            if (isUnion)
            {
                context.Out.WriteLine($"case {dataType.ClassName}Fields.{field.Name}:");
                context.Out.WriteLine("{");
            }

            if (field.IsOptional)
            {
                context.Out.WriteLine($"if ((EncodingMask & (uint){dataType.ClassName}Fields.{field.Name}) != 0) ");
            }

            string functionName = field.DataTypeNode.BasicDataType.ToString();
            string elementName = null;
            string fieldName = isUnion ? $"fieldName ?? \"{field.Name}\"" : $"\"{field.Name}\"";

            switch (field.DataTypeNode.BasicDataType)
            {
                case BasicDataType.Number:
                case BasicDataType.Integer:
                case BasicDataType.UInteger:
                case BasicDataType.BaseDataType:
                    functionName = "Variant";
                    break;
                case BasicDataType.Structure:
                    functionName = "ExtensionObject";
                    break;
                case BasicDataType.Enumeration:
                    if (field.DataType == new XmlQualifiedName("Enumeration", Namespaces.OpcUa))
                    {
                        functionName = "Int32";
                        break;
                    }

                    if (field.DataTypeNode.IsOptionSet)
                    {
                        if (field.DataTypeNode.BaseTypeNode.SymbolicId ==
                            new XmlQualifiedName("OptionSet", Namespaces.OpcUa))
                        {
                            functionName = "Encodeable";
                            elementName = field.DataTypeNode.GetDotNetTypeName(
                                ValueRank.Scalar,
                                m_context.Validator.Dictionary.TargetNamespace,
                                m_context.Validator.Dictionary.Namespaces,
                                nullable: NullableAnnotation.NonNullable);
                            break;
                        }

                        var baseTypeNode = (DataTypeDesign)field.DataTypeNode.BaseTypeNode;
                        functionName = baseTypeNode.BasicDataType.ToString();
                        break;
                    }

                    functionName = "Enumerated";

                    if (field.ValueRank == ValueRank.Array)
                    {
                        elementName = field.DataTypeNode.GetDotNetTypeName(
                            ValueRank.Scalar,
                            m_context.Validator.Dictionary.TargetNamespace,
                            m_context.Validator.Dictionary.Namespaces,
                            nullable: NullableAnnotation.NonNullable);
                        context.Out.WriteLine(
                            "encoder.WriteEnumeratedArray({0}, {1}.ToArray(), typeof({2}));",
                            fieldName,
                            field.Name,
                            elementName);
                        if (isUnion)
                        {
                            context.Out.WriteLine("break;");
                            context.Out.WriteLine("}");
                        }

                        return null;
                    }

                    break;
                case BasicDataType.UserDefined:
                    if (field.AllowSubTypes)
                    {
                        if (field.ValueRank == ValueRank.Array)
                        {
                            context.Out.WriteLine(
                                "encoder.WriteExtensionObjectArray({0}, global::Opc.Ua.ExtensionObjectCollection.ToExtensionObjects({1}));",
                                fieldName,
                                field.Name);

                            if (isUnion)
                            {
                                context.Out.WriteLine("break;");
                                context.Out.WriteLine("}");
                            }

                            return null;
                        }

                        if (field.ValueRank == ValueRank.Scalar)
                        {
                            context.Out.WriteLine(
                                "encoder.WriteExtensionObject({0}, new ExtensionObject({1}));",
                                fieldName,
                                field.Name);

                            if (isUnion)
                            {
                                context.Out.WriteLine("break;");
                                context.Out.WriteLine("}");
                            }

                            return null;
                        }

                        context.Out.WriteLine("encoder.WriteVariant({0}, {1});", fieldName, field.Name);

                        if (isUnion)
                        {
                            context.Out.WriteLine("break;");
                            context.Out.WriteLine("}");
                        }

                        return null;
                    }

                    functionName = "Encodeable";
                    elementName = field.DataTypeNode.GetDotNetTypeName(
                        ValueRank.Scalar,
                        m_context.Validator.Dictionary.TargetNamespace,
                        m_context.Validator.Dictionary.Namespaces,
                        nullable: NullableAnnotation.NonNullable);

                    if (field.ValueRank == ValueRank.Array)
                    {
                        context.Out.WriteLine("encoder.WriteEncodeableArray({0}, {1}.ToArray(), typeof({2}));",
                            fieldName,
                            field.Name,
                            elementName);

                        if (isUnion)
                        {
                            context.Out.WriteLine("break;");
                            context.Out.WriteLine("}");
                        }

                        return null;
                    }
                    break;
            }

            if (field.ValueRank == ValueRank.Array)
            {
                functionName += "Array";
            }
            else if (field.ValueRank != ValueRank.Scalar)
            {
                functionName = "Variant";
                elementName = null;
            }

            context.Out.Write($"encoder.Write{functionName}({fieldName}, {field.Name}");

            if (elementName != null)
            {
                context.Out.Write($", typeof({elementName})");
            }

            context.Out.WriteLine(");");

            if (isUnion)
            {
                context.Out.WriteLine("break;");
                context.Out.WriteLine("}");
            }
            return null;
        }

        private TemplateString LoadTemplate_ListOfDecodedFields(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            var dataType = (DataTypeDesign)field.Parent;
            bool isUnion = dataType.IsUnion;

            if (isUnion)
            {
                context.Out.WriteLine($"case {dataType.ClassName}Fields.{field.Name}:");
                context.Out.WriteLine("{");
            }

            if (field.IsOptional)
            {
                context.Out.WriteLine(
                    $"if ((EncodingMask & (uint){dataType.ClassName}Fields.{field.Name}) != 0) ");
            }

            string functionName = field.DataTypeNode.BasicDataType.ToString();
            string valueName = field.Name;
            string elementName = null;
            string fieldName = isUnion ? $"fieldName ?? \"{field.Name}\"" : $"\"{field.Name}\"";

            switch (field.DataTypeNode.BasicDataType)
            {
                case BasicDataType.Number:
                case BasicDataType.Integer:
                case BasicDataType.UInteger:
                case BasicDataType.BaseDataType:
                    functionName = "Variant";
                    break;
                case BasicDataType.Structure:
                    functionName = "ExtensionObject";
                    break;
                case BasicDataType.Enumeration:
                    if (field.DataType ==
                        new XmlQualifiedName("Enumeration", Namespaces.OpcUa))
                    {
                        functionName = "Int32";
                        break;
                    }

                    if (field.DataTypeNode.IsOptionSet)
                    {
                        if (field.DataTypeNode.BaseTypeNode.SymbolicId ==
                            new XmlQualifiedName("OptionSet", Namespaces.OpcUa))
                        {
                            functionName = "Encodeable";
                            elementName = field.DataTypeNode.GetDotNetTypeName(
                                ValueRank.Scalar,
                                m_context.Validator.Dictionary.TargetNamespace,
                                m_context.Validator.Dictionary.Namespaces,
                                nullable: NullableAnnotation.NonNullable);
                            break;
                        }

                        functionName = ((DataTypeDesign)field.DataTypeNode.BaseTypeNode).BasicDataType.ToString();
                        break;
                    }

                    functionName = "Enumerated";
                    elementName = field.DataTypeNode.GetDotNetTypeName(
                        ValueRank.Scalar,
                        m_context.Validator.Dictionary.TargetNamespace,
                        m_context.Validator.Dictionary.Namespaces,
                        nullable: NullableAnnotation.NonNullable);
                    break;
                case BasicDataType.UserDefined:
                    if (field.AllowSubTypes)
                    {
                        context.Out.Write($"{valueName} = ");
                        elementName = field.DataTypeNode.GetDotNetTypeName(
                            ValueRank.Scalar,
                            m_context.Validator.Dictionary.TargetNamespace,
                            m_context.Validator.Dictionary.Namespaces,
                            nullable: NullableAnnotation.NonNullable);

                        if (field.ValueRank == ValueRank.Array)
                        {
                            context.Out.WriteLine(
                                $"({elementName}[])ExtensionObject.ToArray(decoder.ReadExtensionObjectArray({fieldName}), typeof({elementName}));");

                            if (isUnion)
                            {
                                context.Out.WriteLine("break;");
                                context.Out.WriteLine("}");
                            }

                            return null;
                        }

                        if (field.ValueRank == ValueRank.Scalar)
                        {
                            context.Out.WriteLine($"({elementName})ExtensionObject.ToEncodeable(decoder.ReadExtensionObject({fieldName}));");

                            if (isUnion)
                            {
                                context.Out.WriteLine("break;");
                                context.Out.WriteLine("}");
                            }

                            return null;
                        }

                        context.Out.WriteLine($"decoder.ReadVariant({fieldName});");

                        if (isUnion)
                        {
                            context.Out.WriteLine("break;");
                            context.Out.WriteLine("}");
                        }

                        return null;
                    }

                    functionName = "Encodeable";
                    elementName = field.DataTypeNode.GetDotNetTypeName(
                        ValueRank.Scalar,
                        m_context.Validator.Dictionary.TargetNamespace,
                        m_context.Validator.Dictionary.Namespaces,
                        nullable: NullableAnnotation.NonNullable);
                    break;
            }

            if (field.ValueRank == ValueRank.Array)
            {
                functionName += "Array";
            }
            else if (field.ValueRank != ValueRank.Scalar)
            {
                functionName = "Variant";
                elementName = null;
            }

            context.Out.Write("{0} = ", valueName);

            if (elementName != null)
            {
                if (field.ValueRank == ValueRank.Array)
                {
                    context.Out.Write("({0}Collection)", elementName);
                }
                else
                {
                    context.Out.Write("({0})", elementName);
                }

                context.Out.WriteLine($"decoder.Read{functionName}({fieldName}, typeof({elementName}));");
            }
            else
            {
                context.Out.WriteLine($"decoder.Read{functionName}({fieldName});");
            }

            if (isUnion)
            {
                context.Out.WriteLine("break;");
                context.Out.WriteLine("}");
            }

            return null;
        }

        private TemplateString LoadTemplate_ListOfComparedFields(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            var dataType = (DataTypeDesign)field.Parent;
            if (dataType.IsUnion)
            {
                context.Out.WriteLine($"case {dataType.ClassName}Fields.{field.Name}:");
                context.Out.WriteLine("{");
            }

            if (field.IsOptional)
            {
                context.Out.WriteLine($"if ((EncodingMask & (uint){dataType.ClassName}Fields.{field.Name}) != 0) ");
            }

            if (dataType.IsDotNetEqualityComparable(field.ValueRank))
            {
                context.Out.WriteLine("if ({0} != value.{0})", field.GetChildFieldName());
            }
            else
            {
                context.Out.WriteLine("if (!global::Opc.Ua.CoreUtils.IsEqual({0}, value.{0}))", field.GetChildFieldName());
            }
            context.Out.WriteLine("{");
            context.Out.WriteLine("    return false;");
            context.Out.WriteLine("}");

            if (dataType.IsUnion)
            {
                context.Out.WriteLine("break;");
                context.Out.WriteLine("}");
            }

            return null;
        }

        private TemplateString LoadTemplate_ListOfClonedFields(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            var dataType = (DataTypeDesign)field.Parent;

            if (dataType.IsUnion)
            {
                context.Out.WriteLine($"case {dataType.ClassName}Fields.{field.Name}:");
                context.Out.WriteLine("{");
            }

            if (field.IsOptional)
            {
                context.Out.WriteLine($"if ((EncodingMask & (uint){dataType.ClassName}Fields.{field.Name}) != 0) ");
            }

            context.Out.WriteLine("clone.{0} = ({1})global::Opc.Ua.CoreUtils.Clone(this.{0});",
                field.GetChildFieldName(),
                field.DataTypeNode.GetDotNetTypeName(
                    field.ValueRank,
                    m_context.Validator.Dictionary.TargetNamespace,
                    m_context.Validator.Dictionary.Namespaces,
                    nullable: NullableAnnotation.NullableExceptDataTypes));

            if (dataType.IsUnion)
            {
                context.Out.WriteLine("break;");
                context.Out.WriteLine("}");
            }

            return null;
        }

        private TemplateString LoadTemplate_ListOfFieldInitializers(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            string value = field.DataTypeNode.GetDefaultDotNetValue(
                field.ValueRank,
                field.DefaultValue,
                null,
                true,
                m_context.Validator.Dictionary.TargetNamespace,
                m_context.Validator.Dictionary.Namespaces,
                m_messageContext);

            context.Out.WriteLine("{0} = {1};", field.GetChildFieldName(), value);
            return null;
        }

        private TemplateString LoadTemplate_ListOfProperties(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }
            var dataType = field.Parent as DataTypeDesign;

            if (dataType.BasicDataType != BasicDataType.Enumeration)
            {
                if (field.DataTypeNode.BasicDataType == BasicDataType.UserDefined ||
                    field.ValueRank == ValueRank.Array)
                {
                    if (field.AllowSubTypes ||
                        (field.ValueRank != ValueRank.Array && field.ValueRank != ValueRank.Scalar))
                    {
                        return CodeTemplates.DataTypes_Property_cs;
                    }

                    return CodeTemplates.DataTypes_ArrayProperty_cs;
                }

                return CodeTemplates.DataTypes_Property_cs;
            }

            return CodeTemplates.DataTypes_EnumerationValue_cs;
        }

        private bool WriteTemplate_ListOfProperties(IWriteContext context)
        {
            if (context.Target is not Parameter field)
            {
                return false;
            }

            const bool isRequired = false;
            bool emitDefaultValue = !field.DataTypeNode.IsDotNetReferenceType(field.ValueRank);

            context.Template.AddReplacement(
                Tokens.Description,
                field.Description != null ? field.Description.Value : string.Empty);
            context.Template.AddReplacement(Tokens.BrowseName, field.Name);
            context.Template.AddReplacement(Tokens.EnumerationName, field.EnsureUniqueEnumName());
            context.Template.AddReplacement(Tokens.TypeName, field.DataTypeNode.GetDotNetTypeName(
                field.ValueRank,
                m_context.Validator.Dictionary.TargetNamespace,
                m_context.Validator.Dictionary.Namespaces,
                nullable: NullableAnnotation.NullableExceptDataTypes));
            context.Template.AddReplacement(Tokens.FieldName, field.GetChildFieldName());
            context.Template.AddReplacement(Tokens.IsRequired, isRequired ? "true" : "false");
            context.Template.AddReplacement(Tokens.EmitDefaultValue, emitDefaultValue ? "true" : "false");
            context.Template.AddReplacement(Tokens.FieldIndex, CoreUtils.Format("{0}", context.Index + 1));
            context.Template.AddReplacement(Tokens.DefaultValue, field.DataTypeNode.GetDefaultDotNetValue(
                field.ValueRank,
                null,
                null,
                true,
                m_context.Validator.Dictionary.TargetNamespace,
                m_context.Validator.Dictionary.Namespaces,
                m_messageContext));
            context.Template.AddReplacement(Tokens.Identifier, field.Identifier.ToString(CultureInfo.InvariantCulture));

            if (field.IdentifierInName)
            {
                context.Template.AddReplacement(Tokens.XmlIdentifier, field.Name);
            }
            else
            {
                context.Template.AddReplacement(Tokens.XmlIdentifier,
                    CoreUtils.Format("{0}_{1}", field.Name, field.Identifier));
            }

            if (field.Name == "NodeId" &&
                field.Parent is DataTypeDesign dt &&
                dt.BaseTypeNode.SymbolicName.Name == BrowseNames.HistoryUpdateDetails)
            {
                context.Template.AddReplacement(Tokens.PropertyAccessor, "public override");
            }
            else
            {
                context.Template.AddReplacement(Tokens.PropertyAccessor, "public");
            }

            return context.Template.Render();
        }

        private Parameter[] GetFields(DataTypeDesign dataType)
        {
            List<Parameter> fields = [];

            if (dataType.Fields == null)
            {
                return [.. fields];
            }

            foreach (Parameter child in dataType.Fields)
            {
                if (!m_context.Validator.IsExcluded(child))
                {
                    fields.Add(child);
                }
            }

            return [.. fields];
        }

        private List<DataTypeDesign> GetDataTypes()
        {
            List<DataTypeDesign> datatypes = [];
            foreach (NodeDesign node in m_context.Validator.GetNodeDesigns())
            {
                if (node is DataTypeDesign dataTypeDesign &&
                    !dataTypeDesign.IsPartOfOpcUaTypesLibrary())
                {
                    datatypes.Add(dataTypeDesign);
                }
            }
            return datatypes;
        }

        private string EncodingString => m_useXmlInitializers ? "Xml" : "Binary";

        private readonly IServiceMessageContext m_messageContext;
        private readonly GeneratorContext m_context;
        private readonly bool m_useXmlInitializers;
    }
}
