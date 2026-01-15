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
    internal sealed class NodeStateGenerator : IGenerator
    {
        /// <summary>
        /// Create node state generator
        /// </summary>
        public NodeStateGenerator(
            GeneratorContext context,
            bool useXmlInitializers = false)
        {
            m_context = context;
            m_messageContext = new ServiceMessageContext(context.Telemetry);
            m_useXmlInitializers = useXmlInitializers;
        }

        /// <inheritdoc/>
        public void Emit()
        {
            m_initializers.Clear();
            List<NodeDesign> nodeStateClasses = GetNodeStateClasses();
            if (nodeStateClasses.Count == 0)
            {
                return;
            }
            using TextWriter writer = m_context.FileSystem.CreateTextWriter(
                Path.Combine(m_context.OutputFolder, CoreUtils.Format(
                    "{0}.NodeStates.g.cs",
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
                nodeStateClasses,
                LoadTemplate_ListOfTypes,
                WriteTemplate_ListOfTypes);

            template.Render();
            EmbedInitializers();
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

            string externalPrefix =
                m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(ns.Value);
            context.Out.WriteLine("using {0};", externalPrefix);
            return null;
        }

        private TemplateString LoadTemplate_ListOfTypes(ILoadContext context)
        {
            var node = context.Target as NodeDesign;

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
            if (context.Target is not NodeDesign node ||
                node is DataTypeDesign)
            {
                return false;
            }

            InstanceDesign[] children = GetChildren(node.Children);

            context.Template.AddReplacement(Tokens.NodeClass, node.GetNodeClassString());
            context.Template.AddReplacement(
                Tokens.Description,
                node.Description != null ? node.Description.Value : string.Empty);
            context.Template.AddReplacement(Tokens.Encoding, EncodingString);
            context.Template.AddReplacement(Tokens.TypeName, node.SymbolicName.Name);
            context.Template.AddReplacement(
                Tokens.NamespaceUri,
                m_context.Validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(node.SymbolicName.Namespace));
            context.Template.AddReplacement(
                Tokens.NamespacePrefix,
                m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(node.SymbolicId.Namespace));
            context.Template.AddReplacement(
                Tokens.XmlNamespaceUri,
                m_context.Validator.Dictionary.Namespaces.GetConstantForXmlNamespace(node.SymbolicId.Namespace));

            context.Template.AddReplacement(
                Tokens.BrowseName,
                node.SymbolicName.Name);
            context.Template.AddReplacement(
                Tokens.BrowseNameNamespacePrefix,
                m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(node.SymbolicName.Namespace));
            context.Template.AddReplacement(
                Tokens.BrowseNameNamespaceUri,
                m_context.Validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(node.SymbolicName.Namespace));

            if (context.Target is TypeDesign type)
            {
                context.Template.AddReplacement(
                    Tokens.ClassName,
                    type.ClassName);
                context.Template.AddReplacement(
                    Tokens.BaseType,
                    type.GetBaseClassName(m_context.Validator.Dictionary.Namespaces));
                context.Template.AddReplacement(
                    Tokens.BaseTypeNamespacePrefix,
                    m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(type.BaseTypeNode.SymbolicId.Namespace));
                context.Template.AddReplacement(
                    Tokens.BaseTypeNamespaceUri,
                    m_context.Validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(type.BaseTypeNode.SymbolicId.Namespace));
                context.Template.AddReplacement(
                    Tokens.BaseClassName,
                    type.BaseTypeNode.FixClassName());
            }

            if (context.Target is MethodDesign method)
            {
                context.Template.AddReplacement(
                    Tokens.ClassName,
                    method.GetClassName(m_context.Validator.Dictionary.TargetNamespace, m_context.Validator.Dictionary.Namespaces));

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
                        m_context.Validator.Dictionary.TargetNamespace,
                        m_context.Validator.Dictionary.Namespaces,
                        m_messageContext));
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
                    m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(
                        variableType.DataTypeNode.SymbolicId.Namespace));
                context.Template.AddReplacement(
                    Tokens.DataTypeNamespaceUri,
                    m_context.Validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(
                        variableType.DataTypeNode.SymbolicId.Namespace));

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
                [context.Target],
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
                m_context.Validator.Dictionary.TargetNamespace,
                m_context.Validator.Dictionary.Namespaces,
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
                    m_context.Validator.Dictionary.TargetNamespace,
                    m_context.Validator.Dictionary.Namespaces,
                    nullable: NullableAnnotation.NonNullable));

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
                        m_context.Validator.Dictionary.TargetNamespace,
                        m_context.Validator.Dictionary.Namespaces,
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
                instance.GetClassName(m_context.Validator.Dictionary.TargetNamespace, m_context.Validator.Dictionary.Namespaces),
                instance.GetChildFieldName());

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
                            m_context.Validator.Dictionary.TargetNamespace,
                            m_context.Validator.Dictionary.Namespaces,
                            false) +
                        "));";
                }
            }

            context.Out.WriteLine(
                format,
                field.GetChildFieldName()[2..],
                field.DataTypeNode.GetMethodArgumentDotNetType(
                    field.ValueRank,
                    m_context.Validator.Dictionary.TargetNamespace,
                    m_context.Validator.Dictionary.Namespaces,
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
                    m_context.Validator.Dictionary.TargetNamespace,
                    m_context.Validator.Dictionary.Namespaces,
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
                            m_context.Validator.Dictionary.TargetNamespace,
                            m_context.Validator.Dictionary.Namespaces,
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
                            m_context.Validator.Dictionary.TargetNamespace,
                            m_context.Validator.Dictionary.Namespaces,
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
                            m_context.Validator.Dictionary.TargetNamespace,
                            m_context.Validator.Dictionary.Namespaces,
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
                   m_context.Validator.Dictionary.TargetNamespace,
                   m_context.Validator.Dictionary.Namespaces,
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
                m_context.Validator.Dictionary.TargetNamespace,
                m_context.Validator.Dictionary.Namespaces,
                m_messageContext);

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
                    m_context.Validator.Dictionary.TargetNamespace,
                    m_context.Validator.Dictionary.Namespaces));
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
                    m_context.Validator.Dictionary.TargetNamespace,
                    m_context.Validator.Dictionary.Namespaces))
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
                m_context.Validator.Dictionary.TargetNamespace,
                m_context.Validator.Dictionary.Namespaces));
            context.Template.AddReplacement(Tokens.ChildName, instance.SymbolicName.Name);
            context.Template.AddReplacement(Tokens.FieldName, instance.GetChildFieldName());

            return context.Template.Render();
        }

        private TemplateString LoadTemplate_FindChildMethods(ILoadContext context)
        {
            if (context.Target is not TypeDesign type || type is DataTypeDesign)
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
                    m_context.Validator.Dictionary.TargetNamespace,
                    m_context.Validator.Dictionary.Namespaces))
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
                    m_context.Validator.Dictionary.TargetNamespace,
                    m_context.Validator.Dictionary.Namespaces))
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

            context.Template.AddReplacement(Tokens.ClassName, instance.GetClassName(
                m_context.Validator.Dictionary.TargetNamespace,
                m_context.Validator.Dictionary.Namespaces));
            context.Template.AddReplacement(Tokens.ChildName, instance.SymbolicName.Name);
            context.Template.AddReplacement(Tokens.FieldName, instance.GetChildFieldName());
            context.Template.AddReplacement(Tokens.NodeClass, instance.GetNodeClassString());
            context.Template.AddReplacement(Tokens.BrowseName, instance.SymbolicName.Name);
            context.Template.AddReplacement(
                Tokens.BrowseNameNamespacePrefix,
                m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(
                    instance.SymbolicName.Namespace));
            context.Template.AddReplacement(
                Tokens.BrowseNameNamespaceUri,
                m_context.Validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(
                    instance.SymbolicName.Namespace));

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
                    string ns = m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(
                        variableType.DataTypeNode.SymbolicId.Namespace);
                    scalarName = ns + "." + variableType.DataTypeNode.FixClassName();
                    break;
                case BasicDataType.Structure:
                    scalarName = "ExtensionObject";
                    break;
                default:
                    scalarName = variableType.DataTypeNode.GetDotNetTypeName(
                        m_context.Validator.Dictionary.TargetNamespace,
                        m_context.Validator.Dictionary.Namespaces,
                        nullable: NullableAnnotation.NonNullable);
                    break;
            }

            if (variableType.ValueRank != ValueRank.Scalar)
            {
                return variableType.ValueRank == ValueRank.Array ? $"<{scalarName}[]>" : "<Variant>";
            }

            return $"<{scalarName}>";
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
                    if (!m_context.Validator.IsExcluded(child))
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
                    method.GetClassName(m_context.Validator.Dictionary.TargetNamespace, m_context.Validator.Dictionary.Namespaces),
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
            var context = new SystemContext(m_context.Telemetry)
            {
                NamespaceUris = m_context.Validator.Dictionary.NamespaceUris
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
            var initializers = new ResourceGenerator(m_context);
            initializers.Embed(
                m_context.Validator.Dictionary.TargetNamespaceInfo.Prefix,
                "NodeStates.i",
                internalAccess: true,
                [.. m_initializers.Values]);
        }

        private List<NodeDesign> GetNodeStateClasses()
        {
            List<NodeDesign> nodeStateClasses = [];
            foreach (NodeDesign node in m_context.Validator.GetNodeDesigns())
            {
                if (node is not DataTypeDesign)
                {
                    if (node is MethodDesign &&
                        !node.SymbolicName.Name.EndsWith("MethodType", StringComparison.Ordinal))
                    {
                        continue;
                    }
                    nodeStateClasses.Add(node);
                }
            }
            return nodeStateClasses;
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
        private readonly IServiceMessageContext m_messageContext;
        private readonly GeneratorContext m_context;
        private readonly bool m_useXmlInitializers;
    }
}
