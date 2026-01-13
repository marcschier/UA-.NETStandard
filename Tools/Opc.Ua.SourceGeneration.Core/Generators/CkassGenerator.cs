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
    /// Generates data types and node state classes.
    /// </summary>
    internal sealed class CkassGenerator
    {
        public CkassGenerator(
            IFileSystem fileSystem,
            string outputFolder,
            ModelDesignValidator validator,
            ITelemetryContext telemetry,
            IServiceMessageContext context,
            GeneratorOptions options,
            bool useXmlInitializers)
        {
            m_fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
            m_outputFolder = outputFolder ?? throw new ArgumentNullException(nameof(outputFolder));
            m_validator = validator ?? throw new ArgumentNullException(nameof(validator));
            m_telemetry = telemetry ?? throw new ArgumentNullException(nameof(telemetry));
            m_context = context ?? throw new ArgumentNullException(nameof(context));
            m_options = options ?? throw new ArgumentNullException(nameof(options));
            m_useXmlInitializers = useXmlInitializers;
        }

        public void Emit()
        {
            GenerateDataTypes();
            GenerateNodeStateClasses();
        }

        private void GenerateDataTypes()
        {
            List<DataTypeDesign> datatypes = [];
            foreach (NodeDesign node in m_validator.GetNodeDesigns())
            {
                if (node is DataTypeDesign dataTypeDesign &&
                    !dataTypeDesign.IsPartOfOpcUaTypesLibrary())
                {
                    datatypes.Add(dataTypeDesign);
                }
            }

            if (datatypes.Count == 0)
            {
                return;
            }

            using TextWriter writer = GenerateFile(
                m_outputFolder,
                "DataTypes",
                CodeTemplates.TypesFile_cs,
                out Template template,
                out List<string> namespaces);

            template.AddReplacement(
                Tokens.ListOfTypes,
                datatypes,
                LoadTemplate_ListOfTypes,
                WriteTemplate_ListOfTypes);

            template.Render();
        }

        private void GenerateNodeStateClasses()
        {
            m_initializers.Clear();

            List<NodeDesign> nodeClasses = [];
            foreach (NodeDesign node in m_validator.GetNodeDesigns())
            {
                if (node is not DataTypeDesign)
                {
                    if (node is MethodDesign &&
                        !node.SymbolicName.Name.EndsWith("MethodType", StringComparison.Ordinal))
                    {
                        continue;
                    }
                    nodeClasses.Add(node);
                }
            }

            if (nodeClasses.Count == 0)
            {
                return;
            }

            using TextWriter writer = GenerateFile(
                m_outputFolder,
                "NodeStates",
                CodeTemplates.TypesFile_cs,
                out Template template,
                out List<string> namespaces);

            template.AddReplacement(
                Tokens.ListOfTypes,
                nodeClasses,
                LoadTemplate_ListOfTypes,
                WriteTemplate_ListOfTypes);

            template.Render();

            EmbedInitializers();
        }

        private TextWriter GenerateFile(
            string outputFolder,
            string file,
            TemplateString templateString,
            out Template template,
            out List<string> namespaces)
        {
            TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(
                outputFolder,
                CoreUtils.Format("{0}.{1}.g.cs", m_validator.Dictionary.TargetNamespaceInfo.Prefix, file)));

            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);
            template.AddReplacement(
                Tokens.Namespace,
                m_validator.Dictionary.Namespaces.GetNamespacePrefix(m_validator.Dictionary.TargetNamespace));
            template.AddReplacement(
                Tokens.NamespaceUri,
                m_validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(m_validator.Dictionary.TargetNamespace));

            template.AddReplacement(
                Tokens.ListOfImports,
                m_validator.Dictionary.Namespaces,
                LoadTemplate_NamespaceImports);

            namespaces = [];
            for (int ii = 0; ii < m_validator.Dictionary.Namespaces.Length; ii++)
            {
                namespaces.Add(m_validator.Dictionary.Namespaces[ii].Value);

                if (!string.IsNullOrEmpty(m_validator.Dictionary.Namespaces[ii].XmlNamespace))
                {
                    namespaces.Add(m_validator.Dictionary.Namespaces[ii].XmlNamespace);
                }
            }
            return writer;
        }

        private TemplateString LoadTemplate_NamespaceImports(ILoadContext context)
        {
            if (context.Target is not Namespace ns)
            {
                return null;
            }

            if (ns.Value == m_validator.Dictionary.TargetNamespace)
            {
                return null;
            }

            if (ns.FilePath == null && ns.Value != Namespaces.OpcUa)
            {
                return null;
            }

            string externalPrefix = m_validator.Dictionary.Namespaces.GetNamespacePrefix(ns.Value);

            context.Out.WriteLine("using {0};", externalPrefix);

            return null;
        }

        private TemplateString LoadTemplate_ListOfTypes(ILoadContext context)
        {
            var node = context.Target as NodeDesign;

            if (context.Target is DataTypeDesign datatype)
            {
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
                            if (datatype.IsDerivedDataType(m_validator.Dictionary.Namespaces))
                            {
                                return CodeTemplates.DataTypes_DerivedClassWithOptionalFields_cs;
                            }

                            return CodeTemplates.DataTypes_ClassWithOptionalFields_cs;
                        }

                        if (!datatype.IsDerivedDataType(m_validator.Dictionary.Namespaces))
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

            if (node.NumericId < 256 && node.SymbolicId.Namespace == Namespaces.OpcUa)
            {
                return null;
            }

            if (context.Target is ObjectTypeDesign objectType)
            {
                AddInitializers(objectType, forInstance: true);
                return CodeTemplates.ObjectType_cs;
            }

            if (context.Target is VariableTypeDesign variableType)
            {
                AddInitializers(variableType, forInstance: true);
                return CodeTemplates.VariableType_cs;
            }

            if (context.Target is MethodDesign method && method.HasArguments)
            {
                AddInitializers(method, forInstance: true);
                return CodeTemplates.MethodType_cs;
            }

            return null;
        }

        private bool WriteTemplate_ListOfTypes(IWriteContext context)
        {
            if (context.Target is not NodeDesign node)
            {
                return false;
            }

            object[] children = GetFields(node);

            context.Template.AddReplacement(Tokens.NodeClass, node.GetNodeClassString());
            context.Template.AddReplacement(
                Tokens.Description,
                node.Description != null ? node.Description.Value : string.Empty);
            context.Template.AddReplacement(Tokens.Encoding, EncodingString);
            context.Template.AddReplacement(Tokens.TypeName, node.SymbolicName.Name);
            context.Template.AddReplacement(
                Tokens.NamespaceUri,
                m_validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(node.SymbolicName.Namespace));
            context.Template.AddReplacement(
                Tokens.NamespacePrefix,
                m_validator.Dictionary.Namespaces.GetNamespacePrefix(node.SymbolicId.Namespace));
            context.Template.AddReplacement(
                Tokens.XmlNamespaceUri,
                m_validator.Dictionary.Namespaces.GetConstantForXmlNamespace(node.SymbolicId.Namespace));

            context.Template.AddReplacement(
                Tokens.BrowseName,
                node.SymbolicName.Name);
            context.Template.AddReplacement(
                Tokens.BrowseNameNamespacePrefix,
                m_validator.Dictionary.Namespaces.GetNamespacePrefix(node.SymbolicName.Namespace));
            context.Template.AddReplacement(
                Tokens.BrowseNameNamespaceUri,
                m_validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(node.SymbolicName.Namespace));

            var type = context.Target as TypeDesign;

            if (type != null)
            {
                context.Template.AddReplacement(
                    Tokens.ClassName,
                    type.ClassName);
                context.Template.AddReplacement(
                    Tokens.BaseType,
                    type.GetBaseClassName(m_validator.Dictionary.Namespaces));
                context.Template.AddReplacement(
                    Tokens.BaseTypeNamespacePrefix,
                    m_validator.Dictionary.Namespaces.GetNamespacePrefix(type.BaseTypeNode.SymbolicId.Namespace));
                context.Template.AddReplacement(
                    Tokens.BaseTypeNamespaceUri,
                    m_validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(type.BaseTypeNode.SymbolicId.Namespace));
                context.Template.AddReplacement(
                    Tokens.BaseClassName,
                    type.BaseTypeNode.FixClassName());
            }

            if (context.Target is MethodDesign method)
            {
                context.Template.AddReplacement(
                    Tokens.ClassName,
                    method.GetClassName(m_validator.Dictionary.TargetNamespace, m_validator.Dictionary.Namespaces));

                context.Template.AddReplacement(
                    Tokens.ListOfInputArguments,
                    method.InputArguments,
                    LoadTemplate_ListOfInputArguments);

                context.Template.AddReplacement(
                    Tokens.OnCallDeclaration,
                    [method],
                    LoadTemplate_OnCallDeclaration);

                context.Template.AddReplacement(
                    Tokens.OnCallAsyncDeclaration,
                    [method],
                    LoadTemplate_OnCallAsyncDeclaration);

                context.Template.AddReplacement(
                    Tokens.OnCallImplementation,
                    [method],
                    LoadTemplate_OnCallImplementation);

                context.Template.AddReplacement(
                    Tokens.OnCallAsyncImplementation,
                    [method],
                    LoadTemplate_OnCallAsyncImplementation);

                context.Template.AddReplacement(
                    Tokens.ListOfOutputDeclarations,
                    method.OutputArguments,
                    LoadTemplate_ListOfOutputDeclarations);

                context.Template.AddReplacement(
                    Tokens.ListOfOutputArgumentsFromResult,
                    method.OutputArguments,
                    LoadTemplate_ListOfOutputArgumentsFromResult);

                context.Template.AddReplacement(
                    Tokens.ListOfOutputArguments,
                    method.OutputArguments,
                    LoadTemplate_ListOfOutputArguments);

                context.Template.AddReplacement(
                    Tokens.ListOfResultProperties,
                    method.OutputArguments,
                    LoadTemplate_ListOfResultProperties);
            }

            if (node is DataTypeDesign dataType)
            {
                List<Parameter> completeListOfFields = null;

                if (dataType.IsStructure)
                {
                    List<DataTypeDesign> inheiritanceTree = [dataType];
                    var parentDataType = dataType.BaseTypeNode as DataTypeDesign;

                    while (parentDataType != null &&
                        parentDataType.SymbolicId != new XmlQualifiedName("Structure", Namespaces.OpcUa) &&
                        parentDataType.SymbolicId != new XmlQualifiedName("Union", Namespaces.OpcUa)
                    )
                    {
                        inheiritanceTree.Add(parentDataType);
                        parentDataType = parentDataType.BaseTypeNode as DataTypeDesign;
                    }

                    completeListOfFields = [];

                    for (int ii = inheiritanceTree.Count - 1; ii >= 0; ii--)
                    {
                        foreach (object field in GetFields(inheiritanceTree[ii]))
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
                        var first = (Parameter)children.GetValue(0);

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

                        clone.AddRange(children.Cast<Parameter>());
                    }

                    children = [.. clone];
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
                    bool isEncodingPartOfModel = m_validator.Dictionary.Items.Any(x =>
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
                    children,
                    LoadTemplate_ListOfSwitchFields);

                context.Template.AddReplacement(
                    Tokens.ListOfEncodingMaskFields,
                    completeListOfFields?.ToArray() ?? children,
                    LoadTemplate_ListOfEncodingMaskFields);

                context.Template.AddReplacement(
                    Tokens.ListOfEncodedFields,
                    children,
                    LoadTemplate_ListOfEncodedFields);

                context.Template.AddReplacement(
                    Tokens.ListOfDecodedFields,
                    children,
                    LoadTemplate_ListOfDecodedFields);

                context.Template.AddReplacement(
                    Tokens.ListOfComparedFields,
                    children,
                    LoadTemplate_ListOfComparedFields);

                context.Template.AddReplacement(
                    Tokens.ListOfClonedFields,
                    children,
                    LoadTemplate_ListOfClonedFields);

                context.Template.AddReplacement(
                    Tokens.ListOfSwitchFieldNames,
                    children,
                    LoadTemplate_ListOfSwitchFields);

                context.Template.AddReplacement(
                    Tokens.ListOfEncodingMaskFieldNames,
                    completeListOfFields?.ToArray() ?? children,
                    LoadTemplate_ListOfEncodingMaskFields);

                context.Template.AddReplacement(
                    Tokens.CollectionClass,
                    CodeTemplates.DataTypes_CollectionClass_cs,
                    [dataType],
                    LoadTemplate_CollectionClass,
                    WriteTemplate_CollectionClass);
            }

            if (context.Target is ObjectTypeDesign objectType)
            {
                context.Template.AddReplacement(Tokens.BaseT, string.Empty);
                context.Template.AddReplacement(Tokens.IsAbstract,
                    objectType.IsAbstract.AsBooleanString());
                context.Template.AddReplacement(Tokens.EventNotifier,
                    objectType.GetEventNotifierString());
            }

            if (context.Target is VariableTypeDesign variableType)
            {
                BasicDataType basicType = variableType.DataTypeNode.BasicDataType;

                if (variableType.SymbolicName.Name == "TwoStateDiscreteType")
                {
                    variableType.ValueRank = ValueRank.Scalar;
                }

                if (!variableType.DataTypeNode.IsRequiredParameterInTemplates(variableType.ValueRank))
                {
                    context.Template.AddReplacement(Tokens.BaseT, string.Empty);
                }
                else
                {
                    string parameter = GetTemplateParameter(variableType);

                    if (parameter == "<T>" && variableType.ValueRank != ValueRank.Scalar)
                    {
                        parameter = "<global::Opc.Ua.Variant>";
                    }

                    context.Template.AddReplacement(Tokens.BaseT, GetTemplateParameter(variableType));
                }

                string valueRank = variableType.ValueRank.GetValueRankString(variableType.ArrayDimensions);

                if (variableType.ValueRank == ValueRank.ScalarOrArray)
                {
                    for (TypeDesign baseType = variableType.BaseTypeNode;
                        baseType != null;
                        baseType = baseType.BaseTypeNode)
                    {
                        if (baseType.SymbolicId == new XmlQualifiedName("DataItemType", Namespaces.OpcUa))
                        {
                            valueRank = $"global::Opc.Ua.ValueRanks.{ValueRank.Scalar}";
                        }
                    }
                }

                context.Template.AddReplacement(Tokens.DefaultValue,
                    variableType.DataTypeNode.GetDefaultDotNetValue(
                        variableType.ValueRank,
                        variableType.DefaultValue,
                        variableType.DecodedValue,
                        false,
                        m_validator.Dictionary.TargetNamespace,
                        m_validator.Dictionary.Namespaces,
                        m_context));
                context.Template.AddReplacement(Tokens.ValueRank, valueRank);
                context.Template.AddReplacement(
                    Tokens.ArrayDimensions,
                    variableType.ValueRank.GetArrayDimensionsString(variableType.ArrayDimensions));
                context.Template.AddReplacement(
                    Tokens.IsAbstract,
                    variableType.IsAbstract.AsBooleanString());
                context.Template.AddReplacement(
                    Tokens.AccessLevel,
                    variableType.AccessLevel.GetAccessLevelString());
                context.Template.AddReplacement(
                    Tokens.MinimumSamplingInterval,
                    variableType.GetMinimumSamplingIntervalString());
                context.Template.AddReplacement(
                    Tokens.Historizing,
                    variableType.Historizing.AsBooleanString());

                context.Template.AddReplacement(
                    Tokens.DataType,
                    variableType.DataTypeNode.SymbolicName.Name);
                context.Template.AddReplacement(
                    Tokens.DataTypeNamespacePrefix,
                    m_validator.Dictionary.Namespaces.GetNamespacePrefix(variableType.DataTypeNode.SymbolicId.Namespace));
                context.Template.AddReplacement(
                    Tokens.DataTypeNamespaceUri,
                    m_validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(variableType.DataTypeNode.SymbolicId.Namespace));

                context.Template.AddReplacement(
                    Tokens.TypedVariableType,
                    CodeTemplates.TypedVariableType_cs,
                    [variableType],
                    LoadTemplate_TypedVariableType,
                    WriteTemplate_TypedVariableType);

                context.Template.AddReplacement(
                    Tokens.VariableTypeValue,
                    CodeTemplates.VariableTypeValue_cs,
                    [variableType],
                    LoadTemplate_VariableTypeValue,
                    WriteTemplate_VariableTypeValue);
            }

            context.Template.AddReplacement(
                Tokens.InitializeOptionalChildren,
                CodeTemplates.InitializeOptionalChild_cs,
                children,
                LoadTemplate_InitializeOptionalChildren,
                WriteTemplate_InitializeOptionalChildren);

            context.Template.AddReplacement(
                Tokens.ListOfFieldInitializers,
                children,
                LoadTemplate_ListOfFieldInitializers);

            context.Template.AddReplacement(
                Tokens.ListOfFields,
                children,
                LoadTemplate_ListOfFields);

            context.Template.AddReplacement(
                Tokens.ListOfProperties,
                children,
                LoadTemplate_ListOfProperties,
                WriteTemplate_ListOfProperties);

            context.Template.AddReplacement(
                Tokens.FindChildMethods,
                CodeTemplates.FindChildMethods_cs,
                [type],
                LoadTemplate_FindChildMethods,
                WriteTemplate_FindChildMethods);

            return context.Template.Render();
        }

        private TemplateString LoadTemplate_TypedVariableType(ILoadContext context)
        {
            if (context.Target is not VariableTypeDesign variableType)
            {
                return null;
            }

            if (variableType.DataTypeNode.IsRequiredParameterInTemplates(variableType.ValueRank))
            {
                return null;
            }

            return context.TemplateString;
        }

        private bool WriteTemplate_TypedVariableType(IWriteContext context)
        {
            if (context.Target is not VariableTypeDesign type)
            {
                return false;
            }

            context.Template.AddReplacement(Tokens.NodeClass, type.GetNodeClassString());
            context.Template.AddReplacement(Tokens.ClassName, type.ClassName);
            context.Template.AddReplacement(Tokens.TypeName, type.SymbolicName.Name);
            context.Template.AddReplacement(Tokens.BrowseName, type.SymbolicName.Name);

            return context.Template.Render();
        }

        private TemplateString LoadTemplate_VariableTypeValue(ILoadContext context)
        {
            if (context.Target is not VariableTypeDesign variableType)
            {
                return null;
            }

            Dictionary<string, Parameter> fields = [];
            CollectMatchingFields(variableType, fields);

            if (fields.Count == 0)
            {
                return null;
            }

            return context.TemplateString;
        }

        private bool WriteTemplate_VariableTypeValue(IWriteContext context)
        {
            if (context.Target is not VariableTypeDesign type)
            {
                return false;
            }

            Dictionary<string, Parameter> fields = [];
            CollectMatchingFields(type, fields);

            if (fields.Count == 0)
            {
                return false;
            }

            context.Template.AddReplacement(Tokens.ClassName, type.ClassName);
            context.Template.AddReplacement(Tokens.DataType, type.DataTypeNode.GetDotNetTypeName(
                ValueRank.Scalar,
                m_validator.Dictionary.TargetNamespace,
                m_validator.Dictionary.Namespaces,
                nullable: NullableAnnotation.NonNullable));

            context.Template.AddReplacement(
                Tokens.ListOfChildInitializers,
                fields,
                LoadTemplate_VariableTypeValueInitializers);

            context.Template.AddReplacement(
                Tokens.ListOfUpdateChildrenChangeMasks,
                fields,
                LoadTemplate_VariableTypeValueUpdateChildrenChangeMasks);

            context.Template.AddReplacement(
                Tokens.ListOfChildMethods,
                CodeTemplates.VariableTypeValueField_cs,
                fields,
                WriteTemplate_VariableTypeValueField);

            return context.Template.Render();
        }

        private TemplateString LoadTemplate_VariableTypeValueInitializers(ILoadContext context)
        {
            if (context.Target is not KeyValuePair<string, Parameter> field ||
                field.Value == null)
            {
                return null;
            }

            string name = field.Key;
            string path = field.Key;

            context.Out.WriteLine("instance = m_variable.{0};", path);
            context.Out.WriteLine("if (instance != null)");
            context.Out.WriteLine("{");
            context.Out.WriteLine("    instance.OnReadValue = OnRead_{0};", name);
            context.Out.WriteLine("    instance.OnWriteValue = OnWrite_{0};", name);
            context.Out.WriteLine("    updateList.Add(instance);");
            context.Out.WriteLine("}");

            return null;
        }

        private TemplateString LoadTemplate_VariableTypeValueUpdateChildrenChangeMasks(ILoadContext context)
        {
            if (context.Target is not KeyValuePair<string, Parameter> field ||
                field.Value == null)
            {
                return null;
            }

            var dataType = field.Value.Parent as DataTypeDesign;

            string path = field.Key;

            if (dataType.IsDotNetEqualityComparable(field.Value.ValueRank))
            {
                context.Out.WriteLine("if (m_value.{0} != newValue.{0})", path);
            }
            else
            {
                context.Out.WriteLine("if (!global::Opc.Ua.CoreUtils.IsEqual(m_value.{0}, newValue.{0}))", path);
            }
            context.Out.WriteLine("{");
            context.Out.WriteLine("    UpdateChildVariableStatus(m_variable.{0}, ref statusCode, ref timestamp);", path);
            context.Out.WriteLine("}");

            return null;
        }

        private bool WriteTemplate_VariableTypeValueField(IWriteContext context)
        {
            if (context.Target is not KeyValuePair<string, Parameter> field ||
                field.Value == null)
            {
                return false;
            }

            context.Template.AddReplacement(Tokens.ChildName, field.Key);
            context.Template.AddReplacement(Tokens.ChildPath, field.Key);
            context.Template.AddReplacement(Tokens.ChildDataType,
                field.Value.DataTypeNode.GetDotNetTypeName(
                    field.Value.ValueRank,
                    m_validator.Dictionary.TargetNamespace,
                    m_validator.Dictionary.Namespaces,
                    nullable: NullableAnnotation.NonNullable));

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
                m_validator.Dictionary.Namespaces.GetConstantForXmlNamespace(dataType.SymbolicId.Namespace));
            context.Template.AddReplacement(Tokens.BrowseName, dataType.SymbolicName.Name);

            return context.Template.Render();
        }

        private TemplateString LoadTemplate_ListOfFields(ILoadContext context)
        {
            if (context.Target is not InstanceDesign instance)
            {
                if (context.Target is not Parameter field)
                {
                    return null;
                }

                context.Out.WriteLine(
                    "private {0} {1};",
                    field.DataTypeNode.GetDotNetTypeName(
                        field.ValueRank,
                        m_validator.Dictionary.TargetNamespace,
                        m_validator.Dictionary.Namespaces,
                        nullable: NullableAnnotation.NullableExceptDataTypes),
                    field.GetChildFieldName());

                return null;
            }

            if (instance.IsOverridden())
            {
                return null;
            }

            if (instance.ModellingRule
                is ModellingRule.ExposesItsArray
                or ModellingRule.MandatoryPlaceholder
                or ModellingRule.OptionalPlaceholder)
            {
                return null;
            }

            if (instance.ModellingRule == ModellingRule.None)
            {
                return null;
            }

            if (instance is MethodDesign method &&
                method.ModellingRule != ModellingRule.Mandatory &&
                method.ModellingRule != ModellingRule.Optional)
            {
                return null;
            }

            if (instance.IsBuiltInProperty())
            {
                return null;
            }

            context.Out.WriteLine(
                "private {0} {1};",
                instance.GetClassName(m_validator.Dictionary.TargetNamespace, m_validator.Dictionary.Namespaces),
                instance.GetChildFieldName());

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
                                m_validator.Dictionary.TargetNamespace,
                                m_validator.Dictionary.Namespaces,
                                nullable: NullableAnnotation.NonNullable);
                            break;
                        }

                        functionName = ((DataTypeDesign)field.DataTypeNode.BaseTypeNode).BasicDataType.ToString();
                        break;
                    }

                    functionName = "Enumerated";

                    if (field.ValueRank == ValueRank.Array)
                    {
                        elementName = field.DataTypeNode.GetDotNetTypeName(
                            ValueRank.Scalar,
                            m_validator.Dictionary.TargetNamespace,
                            m_validator.Dictionary.Namespaces,
                            nullable: NullableAnnotation.NonNullable);
                        context.Out.WriteLine(
                            "encoder.WriteEnumeratedArray({0}, {1}.ToArray(), typeof({2}));",
                            fieldName,
                            field.Name,
                            elementName);
                        if (isUnion)
                        {
                            context.Out.WriteLine(" break; }");
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
                                context.Out.WriteLine(" break; }");
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
                                context.Out.WriteLine(" break; }");
                            }

                            return null;
                        }

                        context.Out.WriteLine("encoder.WriteVariant({0}, {1});", fieldName, field.Name);

                        if (isUnion)
                        {
                            context.Out.WriteLine(" break; }");
                        }

                        return null;
                    }

                    functionName = "Encodeable";
                    elementName = field.DataTypeNode.GetDotNetTypeName(
                        ValueRank.Scalar,
                        m_validator.Dictionary.TargetNamespace,
                        m_validator.Dictionary.Namespaces,
                        nullable: NullableAnnotation.NonNullable);

                    if (field.ValueRank == ValueRank.Array)
                    {
                        context.Out.WriteLine("encoder.WriteEncodeableArray({0}, {1}.ToArray(), typeof({2}));",
                            fieldName,
                            field.Name,
                            elementName);

                        if (isUnion)
                        {
                            context.Out.WriteLine(" break; }");
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
                context.Out.WriteLine(" break; }");
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
                                m_validator.Dictionary.TargetNamespace,
                                m_validator.Dictionary.Namespaces,
                                nullable: NullableAnnotation.NonNullable);
                            break;
                        }

                        functionName = ((DataTypeDesign)field.DataTypeNode.BaseTypeNode).BasicDataType.ToString();
                        break;
                    }

                    functionName = "Enumerated";
                    elementName = field.DataTypeNode.GetDotNetTypeName(
                        ValueRank.Scalar,
                        m_validator.Dictionary.TargetNamespace,
                        m_validator.Dictionary.Namespaces,
                        nullable: NullableAnnotation.NonNullable);
                    break;
                case BasicDataType.UserDefined:
                    if (field.AllowSubTypes)
                    {
                        context.Out.Write($"{valueName} = ");
                        elementName = field.DataTypeNode.GetDotNetTypeName(
                            ValueRank.Scalar,
                            m_validator.Dictionary.TargetNamespace,
                            m_validator.Dictionary.Namespaces,
                            nullable: NullableAnnotation.NonNullable);

                        if (field.ValueRank == ValueRank.Array)
                        {
                            context.Out.WriteLine(
                                $"({elementName}[])ExtensionObject.ToArray(decoder.ReadExtensionObjectArray({fieldName}), typeof({elementName}));");

                            if (isUnion)
                            {
                                context.Out.WriteLine(" break; }");
                            }

                            return null;
                        }

                        if (field.ValueRank == ValueRank.Scalar)
                        {
                            context.Out.WriteLine($"({elementName})ExtensionObject.ToEncodeable(decoder.ReadExtensionObject({fieldName}));");

                            if (isUnion)
                            {
                                context.Out.WriteLine(" break; }");
                            }

                            return null;
                        }

                        context.Out.WriteLine($"decoder.ReadVariant({fieldName});");

                        if (isUnion)
                        {
                            context.Out.WriteLine(" break; }");
                        }

                        return null;
                    }

                    functionName = "Encodeable";
                    elementName = field.DataTypeNode.GetDotNetTypeName(
                        ValueRank.Scalar,
                        m_validator.Dictionary.TargetNamespace,
                        m_validator.Dictionary.Namespaces,
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
                context.Out.WriteLine(" break; }");
            }

            return null;
        }

        private TemplateString LoadTemplate_ListOfComparedFields(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            var dataType = field.Parent as DataTypeDesign;

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

            var dataType = field.Parent as DataTypeDesign;

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
                    m_validator.Dictionary.TargetNamespace,
                    m_validator.Dictionary.Namespaces,
                    nullable: NullableAnnotation.NullableExceptDataTypes));

            if (dataType.IsUnion)
            {
                context.Out.WriteLine(" break; }");
            }

            return null;
        }

        private TemplateString LoadTemplate_ListOfInputArguments(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            string format = "{1} {0} = ({1})_inputArguments[{2}];";

            if (field.DataTypeNode.BasicDataType == BasicDataType.UserDefined)
            {
                if (field.ValueRank == ValueRank.Scalar)
                {
                    format = "{1} {0} = ({1})global::Opc.Ua.ExtensionObject.ToEncodeable((ExtensionObject)_inputArguments[{2}]);";
                }
                else
                {
                    format = "{1} {0} = ({1})global::Opc.Ua.ExtensionObject.ToArray(_inputArguments[{2}], typeof(" +
                        field.DataTypeNode.GetMethodArgumentDotNetType(
                            ValueRank.Scalar,
                            m_validator.Dictionary.TargetNamespace,
                            m_validator.Dictionary.Namespaces,
                            false) +
                        "));";
                }
            }

            context.Out.WriteLine(
                format,
                field.GetChildFieldName()[2..],
                field.DataTypeNode.GetMethodArgumentDotNetType(
                    field.ValueRank,
                    m_validator.Dictionary.TargetNamespace,
                    m_validator.Dictionary.Namespaces,
                    false),
                context.Index);

            return null;
        }

        private TemplateString LoadTemplate_ListOfOutputDeclarations(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            context.Out.WriteLine(
                "{1} {0} = ({1})_outputArguments[{2}];",
                field.GetChildFieldName()[2..],
                field.DataTypeNode.GetMethodArgumentDotNetType(
                    field.ValueRank,
                    m_validator.Dictionary.TargetNamespace,
                    m_validator.Dictionary.Namespaces,
                    field.IsOptional),
                context.Index);

            return null;
        }

        private TemplateString LoadTemplate_ListOfOutputArguments(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            context.Out.WriteLine(
                "_outputArguments[{1}] = {0};",
                field.GetChildFieldName()[2..],
                context.Index);

            return null;
        }

        private TemplateString LoadTemplate_OnCallDeclaration(ILoadContext context)
        {
            if (context.Target is not MethodDesign method)
            {
                return null;
            }

            context.Out.WriteLine("global::Opc.Ua.ISystemContext _context,");
            context.Out.WriteLine("global::Opc.Ua.MethodState _method,");
            context.Out.Write("global::Opc.Ua.NodeId _objectId");

            if (method.InputArguments != null)
            {
                for (int ii = 0; ii < method.InputArguments.Length; ii++)
                {
                    Parameter argument = method.InputArguments[ii];

                    context.Out.WriteLine(",");
                    context.Out.Write("{1} {0}", argument.GetChildFieldName()[2..],
                        argument.DataTypeNode.GetMethodArgumentDotNetType(
                            argument.ValueRank,
                            m_validator.Dictionary.TargetNamespace,
                            m_validator.Dictionary.Namespaces,
                            argument.IsOptional));
                }
            }

            if (method.OutputArguments != null)
            {
                for (int ii = 0; ii < method.OutputArguments.Length; ii++)
                {
                    Parameter argument = method.OutputArguments[ii];

                    context.Out.WriteLine(",");
                    context.Out.Write("ref {1} {0}", argument.GetChildFieldName()[2..],
                        argument.DataTypeNode.GetMethodArgumentDotNetType(
                            argument.ValueRank,
                            m_validator.Dictionary.TargetNamespace,
                            m_validator.Dictionary.Namespaces,
                            argument.IsOptional));
                }
            }

            context.Out.WriteLine(");");

            return null;
        }

        private TemplateString LoadTemplate_OnCallAsyncDeclaration(ILoadContext context)
        {
            if (context.Target is not MethodDesign method)
            {
                return null;
            }

            context.Out.WriteLine("global::Opc.Ua.ISystemContext _context,");
            context.Out.WriteLine("global::Opc.Ua.MethodState _method,");
            context.Out.Write("global::Opc.Ua.NodeId _objectId");

            if (method.InputArguments != null)
            {
                for (int ii = 0; ii < method.InputArguments.Length; ii++)
                {
                    Parameter argument = method.InputArguments[ii];

                    context.Out.WriteLine(",");
                    context.Out.Write("{1} {0}", argument.GetChildFieldName()[2..],
                        argument.DataTypeNode.GetMethodArgumentDotNetType(
                            argument.ValueRank,
                            m_validator.Dictionary.TargetNamespace,
                            m_validator.Dictionary.Namespaces,
                            argument.IsOptional));
                }
            }

            context.Out.WriteLine(",");
            context.Out.Write("global::System.Threading.CancellationToken cancellationToken");
            context.Out.WriteLine(");");

            return null;
        }

        private TemplateString LoadTemplate_ListOfOutputArgumentsFromResult(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            string fieldName = field.GetChildFieldName();

            context.Out.WriteLine(
                "_outputArguments[{1}] = _result.{2}{0};",
                fieldName[3..],
                context.Index,
                fieldName.Substring(2, 1).ToUpperInvariant());

            return null;
        }

        private TemplateString LoadTemplate_ListOfResultProperties(ILoadContext context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            string fieldName = field.GetChildFieldName();

            context.Out.WriteLine(
               "public {1} {2}{0} {{ get; set; }}",
               fieldName[3..],
               field.DataTypeNode.GetMethodArgumentDotNetType(
                   field.ValueRank,
                   m_validator.Dictionary.TargetNamespace,
                   m_validator.Dictionary.Namespaces,
                   field.IsOptional),
               fieldName.Substring(2, 1).ToUpperInvariant());

            return null;
        }

        private TemplateString LoadTemplate_OnCallImplementation(ILoadContext context)
        {
            if (context.Target is not MethodDesign method)
            {
                return null;
            }

            context.Out.WriteLine("_result = OnCall(");
            context.Out.WriteLine("    _context,");
            context.Out.WriteLine("    this,");
            context.Out.Write("    _objectId");

            if (method.InputArguments != null)
            {
                for (int ii = 0; ii < method.InputArguments.Length; ii++)
                {
                    context.Out.WriteLine(",");
                    context.Out.Write("    {0}", method.InputArguments[ii].GetChildFieldName()[2..]);
                }
            }

            if (method.OutputArguments != null)
            {
                for (int ii = 0; ii < method.OutputArguments.Length; ii++)
                {
                    context.Out.WriteLine(",");
                    context.Out.Write("    ref {0}", method.OutputArguments[ii].GetChildFieldName()[2..]);
                }
            }

            context.Out.WriteLine(");");

            return null;
        }

        private TemplateString LoadTemplate_OnCallAsyncImplementation(ILoadContext context)
        {
            if (context.Target is not MethodDesign method)
            {
                return null;
            }

            context.Out.WriteLine("_result = await OnCallAsync(");
            context.Out.WriteLine("    _context,");
            context.Out.WriteLine("    this,");
            context.Out.Write("    _objectId");

            if (method.InputArguments != null)
            {
                for (int ii = 0; ii < method.InputArguments.Length; ii++)
                {
                    context.Out.WriteLine(",");
                    context.Out.Write("    {0}", method.InputArguments[ii].GetChildFieldName()[2..]);
                }
            }

            context.Out.WriteLine(",");
            context.Out.WriteLine("    cancellationToken).ConfigureAwait(false);");
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
                m_validator.Dictionary.TargetNamespace,
                m_validator.Dictionary.Namespaces,
                m_context);

            context.Out.WriteLine("{0} = {1};", field.GetChildFieldName(), value);

            return null;
        }

        private TemplateString LoadTemplate_InitializeOptionalChildren(ILoadContext context)
        {
            if (context.Target is not InstanceDesign instance)
            {
                return null;
            }

            if (instance.ModellingRule != ModellingRule.Optional)
            {
                return null;
            }

            if (instance.IsBuiltInProperty())
            {
                return null;
            }

            return context.TemplateString;
        }

        private bool WriteTemplate_InitializeOptionalChildren(IWriteContext context)
        {
            if (context.Target is not InstanceDesign instance)
            {
                return context.Template.Render();
            }

            context.Template.AddReplacement(Tokens.Encoding, EncodingString);
            context.Template.AddReplacement(Tokens.ChildName, instance.SymbolicName.Name);
            if (instance.Parent is MethodDesign method)
            {
                context.Template.AddReplacement(Tokens.ClassName, method.GetClassName(
                    m_validator.Dictionary.TargetNamespace,
                    m_validator.Dictionary.Namespaces));
            }
            else if (instance.Parent is TypeDesign type)
            {
                context.Template.AddReplacement(
                    Tokens.ClassName,
                    type.ClassName);
            }

            return context.Template.Render();
        }

        private TemplateString LoadTemplate_ListOfProperties(ILoadContext context)
        {
            if (context.Target is not InstanceDesign instance)
            {
                if (context.Target is Parameter field)
                {
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

                return null;
            }

            if (instance.ModellingRule
                is ModellingRule.ExposesItsArray
                or ModellingRule.MandatoryPlaceholder
                or ModellingRule.OptionalPlaceholder)
            {
                return null;
            }

            if (instance.ModellingRule == ModellingRule.None)
            {
                return null;
            }

            if (instance is MethodDesign method &&
                method.ModellingRule != ModellingRule.Mandatory &&
                method.ModellingRule != ModellingRule.Optional)
            {
                return null;
            }

            if (instance.IsOverridden())
            {
                if (instance.IsOverriddenWithSameClass(
                    m_validator.Dictionary.TargetNamespace,
                    m_validator.Dictionary.Namespaces))
                {
                    return null;
                }
                return CodeTemplates.PropertyOverride_cs;
            }

            if (instance.IsBuiltInProperty())
            {
                return null;
            }

            return CodeTemplates.Property_cs;
        }

        private bool WriteTemplate_ListOfProperties(IWriteContext context)
        {
            if (context.Target is not InstanceDesign instance)
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
                    m_validator.Dictionary.TargetNamespace,
                    m_validator.Dictionary.Namespaces,
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
                    m_validator.Dictionary.TargetNamespace,
                    m_validator.Dictionary.Namespaces,
                    m_context));
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

            context.Template.AddReplacement(Tokens.PropertyAccessor, "public new");
            if (!instance.IsOverridden())
            {
                if (!s_builtInPropertyNames.Contains(instance.SymbolicName.Name) ||
                    (instance is VariableDesign && instance.SymbolicName.Name == "Value"))
                {
                    context.Template.AddReplacement(Tokens.PropertyAccessor, "public");
                }
            }
            else
            {
                instance = instance.GetMergedInstance();
            }

            context.Template.AddReplacement(Tokens.Description,
                instance.Description != null ? instance.Description.Value : string.Empty);
            context.Template.AddReplacement(Tokens.ClassName, instance.GetClassName(
                m_validator.Dictionary.TargetNamespace,
                m_validator.Dictionary.Namespaces));
            context.Template.AddReplacement(Tokens.ChildName, instance.SymbolicName.Name);
            context.Template.AddReplacement(Tokens.FieldName, instance.GetChildFieldName());

            return context.Template.Render();
        }

        private TemplateString LoadTemplate_FindChildMethods(ILoadContext context)
        {
            if (context.Target is not TypeDesign type)
            {
                return null;
            }

            if (type is DataTypeDesign)
            {
                return null;
            }

            object[] children = GetChildren(type.Children);

            if (children.Length == 0)
            {
                return null;
            }

            int count = 0;

            for (int ii = 0; ii < children.Length; ii++)
            {
                var instance = (InstanceDesign)children.GetValue(ii);

                if (instance.ModellingRule is
                    ModellingRule.ExposesItsArray or
                    ModellingRule.MandatoryPlaceholder or
                    ModellingRule.OptionalPlaceholder)
                {
                    continue;
                }

                if (instance.ModellingRule is
                    ModellingRule.None or
                    ModellingRule.OptionalPlaceholder or
                    ModellingRule.MandatoryPlaceholder)
                {
                    continue;
                }

                if (instance.IsOverriddenWithSameClass(
                    m_validator.Dictionary.TargetNamespace,
                    m_validator.Dictionary.Namespaces))
                {
                    continue;
                }

                count++;
            }

            if (count == 0)
            {
                return null;
            }

            return context.TemplateString;
        }

        private bool WriteTemplate_FindChildMethods(IWriteContext context)
        {
            if (context.Target is not TypeDesign type)
            {
                return false;
            }

            object[] children = GetChildren(type.Children);

            List<InstanceDesign> childrenToUse = [];

            for (int ii = 0; ii < children.Length; ii++)
            {
                var instance = (InstanceDesign)children.GetValue(ii);

                if (instance.ModellingRule is not ModellingRule.Mandatory and not ModellingRule.Optional)
                {
                    continue;
                }

                if (instance.IsOverriddenWithSameClass(
                    m_validator.Dictionary.TargetNamespace,
                    m_validator.Dictionary.Namespaces))
                {
                    continue;
                }

                childrenToUse.Add(instance);
            }

            context.Template.AddReplacement(
                Tokens.ListOfFindChildCase,
                CodeTemplates.FindChildCase_cs,
                childrenToUse,
                LoadTemplate_ListOfFindChildCase,
                WriteTemplate_ListOfChildren);

            childrenToUse = [];

            for (int ii = 0; ii < children.Length; ii++)
            {
                var instance = (InstanceDesign)children.GetValue(ii);

                if (instance.ModellingRule is not ModellingRule.Mandatory and not ModellingRule.Optional)
                {
                    continue;
                }

                if (instance.IsOverridden())
                {
                    continue;
                }

                childrenToUse.Add(instance);
            }

            context.Template.AddReplacement(
                Tokens.ListOfFindChildren,
                CodeTemplates.FindChildren_cs,
                childrenToUse,
                LoadTemplate_ListOfFindChildCase,
                WriteTemplate_ListOfChildren);

            context.Template.AddReplacement(
                Tokens.ListOfRemoveChild,
                CodeTemplates.RemoveChild_cs,
                childrenToUse,
                context => context.Target is InstanceDesign ? context.TemplateString : null,
                WriteTemplate_ListOfChildren);

            return context.Template.Render();
        }

        private TemplateString LoadTemplate_ListOfFindChildCase(ILoadContext context)
        {
            if (context.Target is not InstanceDesign)
            {
                return null;
            }

            return context.TemplateString;
        }

        private bool WriteTemplate_ListOfChildren(IWriteContext context)
        {
            if (context.Target is not InstanceDesign instance)
            {
                return false;
            }

            if (instance.Parent is TypeDesign type)
            {
                context.Template.AddReplacement(Tokens.TypeName, type.SymbolicName.Name);
            }

            context.Template.AddReplacement(
                Tokens.ClassName,
                instance.GetClassName(m_validator.Dictionary.TargetNamespace, m_validator.Dictionary.Namespaces));
            context.Template.AddReplacement(Tokens.ChildName, instance.SymbolicName.Name);
            context.Template.AddReplacement(Tokens.FieldName, instance.GetChildFieldName());
            context.Template.AddReplacement(Tokens.NodeClass, instance.GetNodeClassString());
            context.Template.AddReplacement(Tokens.BrowseName, instance.SymbolicName.Name);
            context.Template.AddReplacement(
                Tokens.BrowseNameNamespacePrefix,
                m_validator.Dictionary.Namespaces.GetNamespacePrefix(instance.SymbolicName.Namespace));
            context.Template.AddReplacement(
                Tokens.BrowseNameNamespaceUri,
                m_validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(instance.SymbolicName.Namespace));

            return context.Template.Render();
        }

        private string GetTemplateParameter(TypeDesign type)
        {
            if (type is not VariableTypeDesign variableType)
            {
                return string.Empty;
            }

            if (type.BaseTypeNode == null)
            {
                return CoreUtils.Format("<T>");
            }

            if (GetTemplateParameter(type.BaseTypeNode) != "<T>")
            {
                return string.Empty;
            }

            BasicDataType basicType = variableType.DataTypeNode.BasicDataType;

            if (basicType == BasicDataType.BaseDataType)
            {
                return "<T>";
            }

            string scalarName;
            switch (basicType)
            {
                case BasicDataType.UserDefined:
                    string ns = m_validator.Dictionary.Namespaces.GetNamespacePrefix(
                        variableType.DataTypeNode.SymbolicId.Namespace);
                    scalarName = ns + "." + variableType.DataTypeNode.FixClassName();
                    break;
                case BasicDataType.Structure:
                    scalarName = "ExtensionObject";
                    break;
                default:
                    scalarName = variableType.DataTypeNode.GetDotNetTypeName(
                        m_validator.Dictionary.TargetNamespace,
                        m_validator.Dictionary.Namespaces,
                        nullable: NullableAnnotation.NonNullable);
                    break;
            }

            if (variableType.ValueRank != ValueRank.Scalar)
            {
                return variableType.ValueRank == ValueRank.Array ? $"<{scalarName}[]>" : "<Variant>";
            }

            return $"<{scalarName}>";
        }

        private object[] GetFields(NodeDesign node)
        {
            if (node is DataTypeDesign dataType)
            {
                List<Parameter> fields = [];

                if (dataType.Fields == null)
                {
                    return [.. fields];
                }

                foreach (Parameter child in dataType.Fields)
                {
                    if (!m_validator.IsExcluded(child))
                    {
                        fields.Add(child);
                    }
                }

                return [.. fields];
            }
            return GetChildren(node.Children);
        }

        private InstanceDesign[] GetChildren(ListOfChildren children)
        {
            List<InstanceDesign> selectedChildren = [];

            if (children == null)
            {
                return [.. selectedChildren];
            }

            if (children.Items != null)
            {
                foreach (InstanceDesign child in children.Items)
                {
                    if (!m_validator.IsExcluded(child))
                    {
                        selectedChildren.Add(child);
                    }
                }
            }

            return [.. selectedChildren];
        }

        private static void CollectMatchingFields(
            VariableTypeDesign variableType,
            Dictionary<string, Parameter> fields)
        {
            CollectFields(variableType.DataTypeNode, variableType.ValueRank, string.Empty, fields);

            List<string> availablePaths = [.. fields.Keys];

            for (int ii = 0; ii < availablePaths.Count; ii++)
            {
                if (!variableType.Hierarchy.Nodes.ContainsKey(availablePaths[ii]))
                {
                    fields.Remove(availablePaths[ii]);
                }
            }
        }

        private static void CollectFields(
            DataTypeDesign dataType,
            ValueRank valueRank,
            string basePath,
            Dictionary<string, Parameter> fields)
        {
            if (dataType.BasicDataType != BasicDataType.UserDefined || valueRank != ValueRank.Scalar)
            {
                return;
            }

            for (DataTypeDesign parent = dataType; parent != null; parent = parent.BaseTypeNode as DataTypeDesign)
            {
                if (parent.Fields != null)
                {
                    for (int ii = 0; ii < parent.Fields.Length; ii++)
                    {
                        Parameter parameter = parent.Fields[ii];
                        string fieldPath = parameter.Name;

                        if (!string.IsNullOrEmpty(basePath))
                        {
                            fieldPath = CoreUtils.Format("{0}_{1}", basePath, parameter.Name);
                        }

                        fields[fieldPath] = parameter;
                    }
                }
            }
        }

        private void AddInitializers(NodeDesign node, bool forInstance)
        {
            if (node is TypeDesign type)
            {
                AddInitializer(type.ClassName, type, forInstance);

                if (type.Children != null && type.Children.Items != null)
                {
                    for (int ii = 0; ii < type.Children.Items.Length; ii++)
                    {
                        InstanceDesign instance = type.Children.Items[ii];

                        if (instance.ModellingRule != ModellingRule.Optional)
                        {
                            continue;
                        }

                        foreach (HierarchyNode current in type.Hierarchy.NodeList)
                        {
                            if (current.RelativePath != instance.SymbolicName.Name)
                            {
                                continue;
                            }

                            AddInitializer(
                                type.ClassName,
                                type,
                                false,
                                current.Instance);
                            break;
                        }
                    }
                }
            }
            else if (node is MethodDesign method)
            {
                AddInitializer(
                    method.GetClassName(m_validator.Dictionary.TargetNamespace, m_validator.Dictionary.Namespaces),
                    method,
                    false);
            }
        }

        internal void AddInitializer(
            string forClass,
            NodeDesign node,
            bool forInstance,
            NodeDesign child = null)
        {
            var context = new SystemContext(m_telemetry)
            {
                NamespaceUris = m_validator.Dictionary.NamespaceUris
            };

            NodeState state = child != null ? child.State : node.State;
            if (forInstance)
            {
                state = node.InstanceState;
            }

            if (state == null)
            {
                return;
            }

            List<BaseInstanceState> list = [];
            state.GetChildren(context, list);

            using var ostrm = new MemoryStream();
            if (m_useXmlInitializers)
            {
                state.SaveAsXml(context, ostrm);
            }
            else
            {
                state.SaveAsBinary(context, ostrm);
            }

            string resourceName = CoreUtils.Format(
                "{0}Initializers.{1}{2}",
                forClass,
                child?.SymbolicName.Name ?? string.Empty,
                EncodingString);

            if (!m_initializers.TryAdd(resourceName, new BinaryResource(
                resourceName,
                ostrm.ToArray(),
                m_useXmlInitializers)))
            {
                throw new InvalidOperationException($"Duplicate resource name {resourceName}");
            }
        }

        /// <summary>
        /// Embed all initializers as source code
        /// </summary>
        private void EmbedInitializers()
        {
            var initializers = new ResourceGenerator(m_fileSystem, m_outputFolder, m_options);
            initializers.Embed(
                m_validator.Dictionary.TargetNamespaceInfo.Prefix,
                "NodeStates.i",
                internalAccess: true,
                [.. m_initializers.Values]);
        }

        private string EncodingString => m_useXmlInitializers ? "Xml" : "Binary";

        private static readonly string[] s_builtInPropertyNames =
        [
            "Description",
            "Save",
            "Handle",
            "Specification",
            "Update",
            "Delete"
        ];

        private readonly Dictionary<string, Resource> m_initializers = [];
        private readonly IServiceMessageContext m_context;
        private readonly GeneratorOptions m_options;
        private readonly ITelemetryContext m_telemetry;
        private readonly ModelDesignValidator m_validator;
        private readonly IFileSystem m_fileSystem;
        private readonly string m_outputFolder;
        private readonly bool m_useXmlInitializers;
    }
}
