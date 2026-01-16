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
    /// Generates C# code that creates the server address space for a model design
    /// at runtime and makes server AOT compatible.
    /// TODO: Tie into node state factory pattern.
    /// </summary>
    internal sealed class AddressSpaceGenerator : IGenerator
    {
        /// <summary>
        /// Creates the generator
        /// </summary>
        public AddressSpaceGenerator(GeneratorContext context)
        {
            m_context = context;
        }

        /// <inheritdoc/>
        public void Emit()
        {
            List<NodeDesign> nodesToGenerate = GetNodesToGenerate();
            if (nodesToGenerate.Count == 0)
            {
                return;
            }

            using TextWriter writer = m_context.FileSystem.CreateTextWriter(
                Path.Combine(m_context.OutputFolder, CoreUtils.Format(
                    "{0}.AddressSpace.g.cs",
                    m_context.Validator.Dictionary.TargetNamespaceInfo.Prefix)));

            using var templateWriter = new TemplateWriter(writer);
            var template = new Template(templateWriter, CodeTemplates.AddressSpaceFile_cs);

            template.AddReplacement(
                Tokens.Namespace,
                m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(
                    m_context.Validator.Dictionary.TargetNamespace));

            template.AddReplacement(
                Tokens.ListOfImports,
                m_context.Validator.Dictionary.Namespaces,
                LoadTemplate_NamespaceImports);

            // Write the nodes.Add() calls
            template.AddReplacement(
                Tokens.ListOfNodeStateInitializers,
                nodesToGenerate,
                LoadTemplate_NodeStateAddCall);

            // Write the Create_XXX methods at class level
            template.AddReplacement(
                Tokens.ListOfTypes,
                nodesToGenerate,
                LoadTemplate_NodeStateCreateMethod);

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

            string externalPrefix =
                m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(ns.Value);
            context.Out.WriteLine("using {0};", externalPrefix);
            return null;
        }

        private TemplateString LoadTemplate_NodeStateAddCall(ILoadContext context)
        {
            if (context.Target is not NodeDesign node)
            {
                return null;
            }

            // Skip excluded nodes
            if (m_context.Validator.IsExcluded(node))
            {
                return null;
            }

            // Write only the nodes.Add() call
            context.Out.WriteLine("nodes.Add(Create_{0}(context));", GetSafeSymbolicName(node));
            return null;
        }

        private TemplateString LoadTemplate_NodeStateCreateMethod(ILoadContext context)
        {
            if (context.Target is not NodeDesign node)
            {
                return null;
            }

            // Skip excluded nodes
            if (m_context.Validator.IsExcluded(node))
            {
                return null;
            }

            // Write the node creation method
            WriteNodeCreationMethod(context.Out, node, string.Empty);
            return null;
        }

        private void WriteNodeCreationMethod(
            ITemplateWriter writer,
            NodeDesign node,
            string parentSymbolicName)
        {
            string symbolicName = GetSafeSymbolicName(node);
            string methodSuffix = string.IsNullOrEmpty(parentSymbolicName)
                ? symbolicName
                : CoreUtils.Format("{0}_{1}", parentSymbolicName, node.SymbolicName.Name);
            bool isChild = !string.IsNullOrEmpty(parentSymbolicName);

            switch (node)
            {
                case ObjectTypeDesign objectType:
                    WriteObjectTypeCreation(writer, objectType, methodSuffix);
                    break;
                case VariableTypeDesign variableType:
                    WriteVariableTypeCreation(writer, variableType, methodSuffix);
                    break;
                case ReferenceTypeDesign referenceType:
                    WriteReferenceTypeCreation(writer, referenceType, methodSuffix);
                    break;
                case DataTypeDesign dataType:
                    WriteDataTypeCreation(writer, dataType, methodSuffix);
                    break;
                case ObjectDesign objectDesign:
                    WriteObjectCreation(writer, objectDesign, methodSuffix, isChild);
                    break;
                case VariableDesign variableDesign:
                    WriteVariableCreation(writer, variableDesign, methodSuffix, isChild);
                    break;
                case MethodDesign methodDesign:
                    WriteMethodCreation(writer, methodDesign, methodSuffix, isChild);
                    break;
                case ViewDesign viewDesign:
                    WriteViewCreation(writer, viewDesign, methodSuffix);
                    break;
            }
        }

        private void WriteObjectTypeCreation(
            ITemplateWriter writer,
            ObjectTypeDesign node,
            string methodSuffix)
        {
            writer.WriteLine();
            writer.WriteLine("/// <summary>");
            writer.WriteLine("/// Creates the {0} ObjectType node state.", node.SymbolicName.Name);
            writer.WriteLine("/// </summary>");
            writer.WriteLine("private static global::Opc.Ua.BaseObjectTypeState Create_{0}(", methodSuffix);
            writer.WriteLine("    global::Opc.Ua.ISystemContext context)");
            writer.WriteLine("{");
            writer.WriteLine("    var state = new global::Opc.Ua.BaseObjectTypeState();");

            WriteCommonNodeProperties(writer, node);

            // SuperTypeId
            if (node.BaseTypeNode != null)
            {
                writer.WriteLine("    state.SuperTypeId = {0};", GetNodeIdConstant(node.BaseTypeNode));
            }
            else
            {
                writer.WriteLine("    state.SuperTypeId = global::Opc.Ua.NodeId.Null;");
            }

            writer.WriteLine("    state.IsAbstract = {0};", node.IsAbstract.AsBooleanString());

            WriteTypeNodeOptionalProperties(writer, node);
            WriteChildNodes(writer, node, methodSuffix);

            writer.WriteLine("    return state;");
            writer.WriteLine("}");

            // Write child methods after parent method closes
            WriteChildNodeMethods(writer, node, methodSuffix);
        }

        private void WriteVariableTypeCreation(
            ITemplateWriter writer,
            VariableTypeDesign node,
            string methodSuffix)
        {
            writer.WriteLine();
            writer.WriteLine("/// <summary>");
            writer.WriteLine("/// Creates the {0} VariableType node state.", node.SymbolicName.Name);
            writer.WriteLine("/// </summary>");
            writer.WriteLine("private static global::Opc.Ua.BaseDataVariableTypeState Create_{0}(", methodSuffix);
            writer.WriteLine("    global::Opc.Ua.ISystemContext context)");
            writer.WriteLine("{");
            writer.WriteLine("    var state = new global::Opc.Ua.BaseDataVariableTypeState();");

            WriteCommonNodeProperties(writer, node);

            // SuperTypeId
            if (node.BaseTypeNode != null)
            {
                writer.WriteLine("    state.SuperTypeId = {0};", GetNodeIdConstant(node.BaseTypeNode));
            }
            else
            {
                writer.WriteLine("    state.SuperTypeId = global::Opc.Ua.NodeId.Null;");
            }

            writer.WriteLine("    state.IsAbstract = {0};", node.IsAbstract.AsBooleanString());

            // DataType, ValueRank, ArrayDimensions
            if (node.DataTypeNode != null)
            {
                writer.WriteLine("    state.DataType = {0};", GetNodeIdConstant(node.DataTypeNode));
            }

            writer.WriteLine("    state.ValueRank = {0};",
                node.ValueRank.GetValueRankString(node.ArrayDimensions));

            string arrayDims = GetArrayDimensionsCode(node.ValueRank, node.ArrayDimensions);
            if (!string.IsNullOrEmpty(arrayDims))
            {
                writer.WriteLine("    state.ArrayDimensions = {0};", arrayDims);
            }

            // Value
            if (node.DecodedValue != null)
            {
                string valueCode = GetValueCode(node.DecodedValue);
                if (!string.IsNullOrEmpty(valueCode))
                {
                    writer.WriteLine("    state.Value = {0};", valueCode);
                }
            }

            WriteTypeNodeOptionalProperties(writer, node);
            WriteChildNodes(writer, node, methodSuffix);

            writer.WriteLine("    return state;");
            writer.WriteLine("}");

            // Write child methods after parent method closes
            WriteChildNodeMethods(writer, node, methodSuffix);
        }

        private void WriteReferenceTypeCreation(
            ITemplateWriter writer,
            ReferenceTypeDesign node,
            string methodSuffix)
        {
            writer.WriteLine();
            writer.WriteLine("/// <summary>");
            writer.WriteLine("/// Creates the {0} ReferenceType node state.", node.SymbolicName.Name);
            writer.WriteLine("/// </summary>");
            writer.WriteLine("private static global::Opc.Ua.ReferenceTypeState Create_{0}(", methodSuffix);
            writer.WriteLine("    global::Opc.Ua.ISystemContext context)");
            writer.WriteLine("{");
            writer.WriteLine("    var state = new global::Opc.Ua.ReferenceTypeState();");

            WriteCommonNodeProperties(writer, node);

            // SuperTypeId
            if (node.BaseTypeNode != null)
            {
                writer.WriteLine("    state.SuperTypeId = {0};", GetNodeIdConstant(node.BaseTypeNode));
            }
            else
            {
                writer.WriteLine("    state.SuperTypeId = global::Opc.Ua.NodeId.Null;");
            }

            writer.WriteLine("    state.IsAbstract = {0};", node.IsAbstract.AsBooleanString());
            writer.WriteLine("    state.Symmetric = {0};", node.Symmetric.AsBooleanString());

            // InverseName
            if (!node.Symmetric && node.InverseName != null)
            {
                writer.WriteLine("    state.InverseName = new global::Opc.Ua.LocalizedText(\"{0}\", string.Empty, \"{1}\");",
                    EscapeString(node.InverseName.Key ?? string.Empty),
                    EscapeString(node.InverseName.Value ?? string.Empty));
            }
            else if (node.Symmetric)
            {
                writer.WriteLine("    state.InverseName = global::Opc.Ua.LocalizedText.Null;");
            }

            WriteTypeNodeOptionalProperties(writer, node);

            writer.WriteLine("    return state;");
            writer.WriteLine("}");
        }

        private void WriteDataTypeCreation(
            ITemplateWriter writer,
            DataTypeDesign node,
            string methodSuffix)
        {
            writer.WriteLine();
            writer.WriteLine("/// <summary>");
            writer.WriteLine("/// Creates the {0} DataType node state.", node.SymbolicName.Name);
            writer.WriteLine("/// </summary>");
            writer.WriteLine("private static global::Opc.Ua.DataTypeState Create_{0}(", methodSuffix);
            writer.WriteLine("    global::Opc.Ua.ISystemContext context)");
            writer.WriteLine("{");
            writer.WriteLine("    var state = new global::Opc.Ua.DataTypeState();");

            WriteCommonNodeProperties(writer, node);

            // SuperTypeId
            if (node.BaseTypeNode != null)
            {
                writer.WriteLine("    state.SuperTypeId = {0};", GetNodeIdConstant(node.BaseTypeNode));
            }
            else
            {
                writer.WriteLine("    state.SuperTypeId = global::Opc.Ua.NodeId.Null;");
            }

            writer.WriteLine("    state.IsAbstract = {0};", node.IsAbstract.AsBooleanString());

            WriteTypeNodeOptionalProperties(writer, node);
            WriteChildNodes(writer, node, methodSuffix);

            writer.WriteLine("    return state;");
            writer.WriteLine("}");

            // Write child methods after parent method closes
            WriteChildNodeMethods(writer, node, methodSuffix);
        }

        private void WriteObjectCreation(
            ITemplateWriter writer,
            ObjectDesign node,
            string methodSuffix,
            bool isChild)
        {
            writer.WriteLine();
            writer.WriteLine("/// <summary>");
            writer.WriteLine("/// Creates the {0} Object node state.", node.SymbolicName.Name);
            writer.WriteLine("/// </summary>");

            if (isChild)
            {
                writer.WriteLine("private static global::Opc.Ua.BaseObjectState Create_{0}(", methodSuffix);
                writer.WriteLine("    global::Opc.Ua.ISystemContext context,");
                writer.WriteLine("    global::Opc.Ua.NodeState parent)");
                writer.WriteLine("{");
                writer.WriteLine("    var state = new global::Opc.Ua.BaseObjectState(parent);");
            }
            else
            {
                writer.WriteLine("private static global::Opc.Ua.BaseObjectState Create_{0}(", methodSuffix);
                writer.WriteLine("    global::Opc.Ua.ISystemContext context)");
                writer.WriteLine("{");
                writer.WriteLine("    var state = new global::Opc.Ua.BaseObjectState(null);");
            }

            WriteCommonNodeProperties(writer, node);

            // TypeDefinitionId
            if (node.TypeDefinitionNode != null)
            {
                writer.WriteLine("    state.TypeDefinitionId = {0};", GetNodeIdConstant(node.TypeDefinitionNode));
            }

            // ReferenceTypeId
            writer.WriteLine("    state.ReferenceTypeId = {0};", GetReferenceTypeIdConstant(node.ReferenceType));

            // ModellingRuleId
            WriteModellingRuleId(writer, node.ModellingRule);

            // EventNotifier
            writer.WriteLine("    state.EventNotifier = {0};",
                node.SupportsEvents ? "global::Opc.Ua.EventNotifiers.SubscribeToEvents" : "global::Opc.Ua.EventNotifiers.None");

            WriteInstanceNodeOptionalProperties(writer, node);
            WriteChildNodes(writer, node, methodSuffix);

            writer.WriteLine("    return state;");
            writer.WriteLine("}");

            // Write child methods after parent method closes
            WriteChildNodeMethods(writer, node, methodSuffix);
        }

        private void WriteVariableCreation(
            ITemplateWriter writer,
            VariableDesign node,
            string methodSuffix,
            bool isChild)
        {
            bool isProperty = node is PropertyDesign;
            string stateClassName = isProperty
                ? "global::Opc.Ua.PropertyState"
                : "global::Opc.Ua.BaseDataVariableState";

            writer.WriteLine();
            writer.WriteLine("/// <summary>");
            writer.WriteLine("/// Creates the {0} Variable node state.", node.SymbolicName.Name);
            writer.WriteLine("/// </summary>");

            if (isChild)
            {
                writer.WriteLine("private static global::Opc.Ua.BaseVariableState Create_{0}(", methodSuffix);
                writer.WriteLine("    global::Opc.Ua.ISystemContext context,");
                writer.WriteLine("    global::Opc.Ua.NodeState parent)");
                writer.WriteLine("{");
                writer.WriteLine("    var state = new {0}(parent);", stateClassName);
            }
            else
            {
                writer.WriteLine("private static global::Opc.Ua.BaseVariableState Create_{0}(", methodSuffix);
                writer.WriteLine("    global::Opc.Ua.ISystemContext context)");
                writer.WriteLine("{");
                writer.WriteLine("    var state = new {0}(null);", stateClassName);
            }

            WriteCommonNodeProperties(writer, node);

            // TypeDefinitionId
            if (node.TypeDefinitionNode != null)
            {
                writer.WriteLine("    state.TypeDefinitionId = {0};", GetNodeIdConstant(node.TypeDefinitionNode));
            }

            // ReferenceTypeId
            writer.WriteLine("    state.ReferenceTypeId = {0};", GetReferenceTypeIdConstant(node.ReferenceType));

            // ModellingRuleId
            WriteModellingRuleId(writer, node.ModellingRule);

            // DataType
            if (node.DataTypeNode != null)
            {
                writer.WriteLine("    state.DataType = {0};", GetNodeIdConstant(node.DataTypeNode));
            }

            // ValueRank, ArrayDimensions
            writer.WriteLine("    state.ValueRank = {0};",
                node.ValueRank.GetValueRankString(node.ArrayDimensions));

            string arrayDims = GetArrayDimensionsCode(node.ValueRank, node.ArrayDimensions);
            if (!string.IsNullOrEmpty(arrayDims))
            {
                writer.WriteLine("    state.ArrayDimensions = {0};", arrayDims);
            }

            // AccessLevel
            writer.WriteLine("    state.AccessLevel = {0};", GetAccessLevelCode(node.AccessLevel));
            writer.WriteLine("    state.UserAccessLevel = state.AccessLevel;");

            // MinimumSamplingInterval
            writer.WriteLine("    state.MinimumSamplingInterval = {0};",
                node.MinimumSamplingInterval.ToString(CultureInfo.InvariantCulture));

            // Historizing
            writer.WriteLine("    state.Historizing = {0};", node.Historizing.AsBooleanString());

            // Value
            if (node.DecodedValue != null)
            {
                string valueCode = GetValueCode(node.DecodedValue);
                if (!string.IsNullOrEmpty(valueCode))
                {
                    writer.WriteLine("    state.Value = {0};", valueCode);
                }
            }

            WriteInstanceNodeOptionalProperties(writer, node);
            WriteChildNodes(writer, node, methodSuffix);

            writer.WriteLine("    return state;");
            writer.WriteLine("}");

            // Write child methods after parent method closes
            WriteChildNodeMethods(writer, node, methodSuffix);
        }

        private void WriteMethodCreation(
            ITemplateWriter writer,
            MethodDesign node,
            string methodSuffix,
            bool isChild)
        {
            writer.WriteLine();
            writer.WriteLine("/// <summary>");
            writer.WriteLine("/// Creates the {0} Method node state.", node.SymbolicName.Name);
            writer.WriteLine("/// </summary>");

            if (isChild)
            {
                writer.WriteLine("private static global::Opc.Ua.MethodState Create_{0}(", methodSuffix);
                writer.WriteLine("    global::Opc.Ua.ISystemContext context,");
                writer.WriteLine("    global::Opc.Ua.NodeState parent)");
                writer.WriteLine("{");
                writer.WriteLine("    var state = new global::Opc.Ua.MethodState(parent);");
            }
            else
            {
                writer.WriteLine("private static global::Opc.Ua.MethodState Create_{0}(", methodSuffix);
                writer.WriteLine("    global::Opc.Ua.ISystemContext context)");
                writer.WriteLine("{");
                writer.WriteLine("    var state = new global::Opc.Ua.MethodState(null);");
            }

            WriteCommonNodeProperties(writer, node);

            // ReferenceTypeId
            writer.WriteLine("    state.ReferenceTypeId = {0};", GetReferenceTypeIdConstant(node.ReferenceType));

            // ModellingRuleId
            WriteModellingRuleId(writer, node.ModellingRule);

            // Executable
            bool executable = !node.NonExecutable;
            writer.WriteLine("    state.Executable = {0};", executable.AsBooleanString());
            writer.WriteLine("    state.UserExecutable = {0};", executable.AsBooleanString());

            // MethodDeclarationId
            if (node.MethodDeclarationNode != null)
            {
                writer.WriteLine("    state.MethodDeclarationId = {0};", GetNodeIdConstant(node.MethodDeclarationNode));
            }

            WriteInstanceNodeOptionalProperties(writer, node);
            WriteChildNodes(writer, node, methodSuffix);

            writer.WriteLine("    return state;");
            writer.WriteLine("}");

            // Write child methods after parent method closes
            WriteChildNodeMethods(writer, node, methodSuffix);
        }

        private void WriteViewCreation(
            ITemplateWriter writer,
            ViewDesign node,
            string methodSuffix)
        {
            writer.WriteLine();
            writer.WriteLine("/// <summary>");
            writer.WriteLine("/// Creates the {0} View node state.", node.SymbolicName.Name);
            writer.WriteLine("/// </summary>");
            writer.WriteLine("private static global::Opc.Ua.ViewState Create_{0}(", methodSuffix);
            writer.WriteLine("    global::Opc.Ua.ISystemContext context)");
            writer.WriteLine("{");
            writer.WriteLine("    var state = new global::Opc.Ua.ViewState();");

            WriteCommonNodeProperties(writer, node);

            // EventNotifier
            writer.WriteLine("    state.EventNotifier = {0};",
                node.SupportsEvents ? "global::Opc.Ua.EventNotifiers.SubscribeToEvents" : "global::Opc.Ua.EventNotifiers.None");

            // ContainsNoLoops
            writer.WriteLine("    state.ContainsNoLoops = {0};", node.ContainsNoLoops.AsBooleanString());

            WriteTypeNodeOptionalProperties(writer, node);

            writer.WriteLine("    return state;");
            writer.WriteLine("}");
        }

        private void WriteCommonNodeProperties(
            ITemplateWriter writer,
            NodeDesign node)
        {
            // SymbolicName
            writer.WriteLine("    state.SymbolicName = \"{0}\";", node.SymbolicName.Name);

            // NodeId
            writer.WriteLine("    state.NodeId = {0};", GetNodeIdConstant(node));

            // BrowseName - use literal string for better portability
            string browseNameValue = !string.IsNullOrEmpty(node.BrowseName)
                ? node.BrowseName
                : node.SymbolicName.Name;
            string browseNameUri = m_context.Validator.Dictionary.Namespaces
                .GetConstantSymbolForNamespace(node.SymbolicName.Namespace);
            writer.WriteLine("    state.BrowseName = new global::Opc.Ua.QualifiedName(");
            writer.WriteLine("        \"{0}\",", EscapeString(browseNameValue));
            writer.WriteLine("        context.NamespaceUris.GetIndexOrAppend({0}));", browseNameUri);

            // DisplayName
            if (node.DisplayName != null)
            {
                writer.WriteLine("    state.DisplayName = new global::Opc.Ua.LocalizedText(\"{0}\", string.Empty, \"{1}\");",
                    EscapeString(node.DisplayName.Key ?? string.Empty),
                    EscapeString(node.DisplayName.Value?.Trim() ?? node.SymbolicName.Name));
            }
            else
            {
                writer.WriteLine("    state.DisplayName = new global::Opc.Ua.LocalizedText(\"{0}\");", node.SymbolicName.Name);
            }

            // Description
            if (node.Description != null && !node.Description.IsAutogenerated)
            {
                writer.WriteLine("    state.Description = new global::Opc.Ua.LocalizedText(\"{0}\", string.Empty, \"{1}\");",
                    EscapeString(node.Description.Key ?? string.Empty),
                    EscapeString(node.Description.Value?.Trim() ?? string.Empty));
            }

            // WriteMask/UserWriteMask
            writer.WriteLine("    state.WriteMask = global::Opc.Ua.AttributeWriteMask.None;");
            writer.WriteLine("    state.UserWriteMask = global::Opc.Ua.AttributeWriteMask.None;");
        }

        private void WriteTypeNodeOptionalProperties(
            ITemplateWriter writer,
            NodeDesign node)
        {
            // ReleaseStatus
            Export.ReleaseStatus releaseStatus = node.ReleaseStatus.ToNodeSetReleaseStatus();
            if (releaseStatus != Export.ReleaseStatus.Released)
            {
                writer.WriteLine("    state.ReleaseStatus = global::Opc.Ua.Export.ReleaseStatus.{0};", releaseStatus);
            }

            // Categories
            if (!string.IsNullOrEmpty(node.Category))
            {
                string[] categories = node.Category.Split([',']);
                writer.WriteLine("    state.Categories = new string[] {{ {0} }};",
                    string.Join(", ", categories.Select(c => CoreUtils.Format("\"{0}\"", c.Trim()))));
            }

            // Specification
            if (node.PartNo != 0)
            {
                writer.WriteLine("    state.Specification = \"Part{0}\";", node.PartNo);
            }

            // AccessRestrictions
            WriteAccessRestrictions(writer, node);

            // RolePermissions
            WriteRolePermissions(writer, node);
        }

        private void WriteInstanceNodeOptionalProperties(
            ITemplateWriter writer,
            InstanceDesign node)
        {
            // ReleaseStatus
            Export.ReleaseStatus releaseStatus = node.ReleaseStatus.ToNodeSetReleaseStatus();
            if (releaseStatus != Export.ReleaseStatus.Released)
            {
                writer.WriteLine("    state.ReleaseStatus = global::Opc.Ua.Export.ReleaseStatus.{0};", releaseStatus);
            }

            // Categories
            if (!string.IsNullOrEmpty(node.Category))
            {
                string[] categories = node.Category.Split([',']);
                writer.WriteLine("    state.Categories = new string[] {{ {0} }};",
                    string.Join(", ", categories.Select(c => CoreUtils.Format("\"{0}\"", c.Trim()))));
            }

            // Specification
            if (node.PartNo != 0)
            {
                writer.WriteLine("    state.Specification = \"Part{0}\";", node.PartNo);
            }

            // AccessRestrictions
            WriteAccessRestrictions(writer, node);

            // RolePermissions
            WriteRolePermissions(writer, node);
        }

        private static void WriteAccessRestrictions(
            ITemplateWriter writer,
            NodeDesign node)
        {
            if (!node.AccessRestrictionsSpecified)
            {
                return;
            }

            string accessRestrictionsCode = GetAccessRestrictionsCode(node.AccessRestrictions);
            if (!string.IsNullOrEmpty(accessRestrictionsCode))
            {
                writer.WriteLine("    state.AccessRestrictions = {0};", accessRestrictionsCode);
            }
        }

        private void WriteRolePermissions(
            ITemplateWriter writer,
            NodeDesign node)
        {
            if (node.RolePermissions?.RolePermission == null || node.RolePermissions.RolePermission.Length == 0)
            {
                return;
            }

            writer.WriteLine("    state.RolePermissions = new global::Opc.Ua.RolePermissionTypeCollection();");

            foreach (RolePermission rolePermission in node.RolePermissions.RolePermission)
            {
                ObjectDesign roleNode = m_context.Validator.FindNode<ObjectDesign>(
                    rolePermission.Role,
                    rolePermission.Role.Name,
                    "RoleType");

                if (roleNode != null)
                {
                    string permissionValue = GetPermissionTypeCode(rolePermission.Permission);
                    writer.WriteLine("    state.RolePermissions.Add(new global::Opc.Ua.RolePermissionType");
                    writer.WriteLine("    {");
                    writer.WriteLine("        RoleId = {0},", GetNodeIdConstant(roleNode));
                    writer.WriteLine("        Permissions = (uint)({0})", permissionValue);
                    writer.WriteLine("    });");
                }
            }
        }

        private static void WriteModellingRuleId(
            ITemplateWriter writer,
            ModellingRule modellingRule)
        {
            string constant = modellingRule switch
            {
                ModellingRule.Mandatory => "global::Opc.Ua.Objects.ModellingRule_Mandatory",
                ModellingRule.Optional => "global::Opc.Ua.Objects.ModellingRule_Optional",
                ModellingRule.MandatoryPlaceholder => "global::Opc.Ua.Objects.ModellingRule_MandatoryPlaceholder",
                ModellingRule.OptionalPlaceholder => "global::Opc.Ua.Objects.ModellingRule_OptionalPlaceholder",
                ModellingRule.ExposesItsArray => "global::Opc.Ua.Objects.ModellingRule_ExposesItsArray",
                _ => null
            };

            if (constant != null)
            {
                writer.WriteLine("    state.ModellingRuleId = {0};", constant);
            }
        }

        private void WriteChildNodes(
            ITemplateWriter writer,
            NodeDesign node,
            string parentMethodSuffix)
        {
            if (node.Children?.Items == null || node.Children.Items.Length == 0)
            {
                return;
            }

            // First, write the AddChild calls inside the parent method
            foreach (InstanceDesign child in node.Children.Items)
            {
                if (m_context.Validator.IsExcluded(child))
                {
                    continue;
                }

                // Skip certain modelling rules
                if (child.ModellingRule is ModellingRule.ExposesItsArray
                    or ModellingRule.MandatoryPlaceholder
                    or ModellingRule.OptionalPlaceholder)
                {
                    continue;
                }

                string childMethodSuffix = CoreUtils.Format(
                    "{0}_{1}",
                    parentMethodSuffix,
                    child.SymbolicName.Name);

                writer.WriteLine("    state.AddChild(Create_{0}(context, state));", childMethodSuffix);
            }
        }

        /// <summary>
        /// Write child node creation methods after the parent method completes.
        /// This must be called after the parent method's closing brace.
        /// </summary>
        private void WriteChildNodeMethods(
            ITemplateWriter writer,
            NodeDesign node,
            string parentMethodSuffix)
        {
            if (node.Children?.Items == null || node.Children.Items.Length == 0)
            {
                return;
            }

            // Now write all child creation methods (after the parent method)
            foreach (InstanceDesign child in node.Children.Items)
            {
                if (m_context.Validator.IsExcluded(child))
                {
                    continue;
                }

                if (child.ModellingRule is ModellingRule.ExposesItsArray
                    or ModellingRule.MandatoryPlaceholder
                    or ModellingRule.OptionalPlaceholder)
                {
                    continue;
                }

                WriteNodeCreationMethod(writer, child, parentMethodSuffix);
            }
        }

        private List<NodeDesign> GetNodesToGenerate()
        {
            var nodes = new List<NodeDesign>();

            foreach (NodeDesign node in m_context.Validator.Dictionary.Items)
            {
                if (m_context.Validator.IsExcluded(node))
                {
                    continue;
                }

                // Skip method type nodes that are not top-level
                if (node.IsMethodTypeNode())
                {
                    continue;
                }

                nodes.Add(node);
            }

            return nodes;
        }

        private static string GetSafeSymbolicName(NodeDesign node)
        {
            // Create a safe method name from the symbolic name
            return node.SymbolicId.Name
                .Replace(".", "_", StringComparison.Ordinal)
                .Replace("-", "_", StringComparison.Ordinal);
        }

        private string GetNodeIdConstant(NodeDesign node)
        {
            if (node == null)
            {
                return "global::Opc.Ua.NodeId.Null";
            }

            string namespaceUri = m_context.Validator.Dictionary.Namespaces
                .GetConstantSymbolForNamespace(node.SymbolicId.Namespace);

            // Use numeric ID directly when available for more portable generated code
            if (node.NumericIdSpecified)
            {
                return CoreUtils.Format(
                    "global::Opc.Ua.NodeId.Create({0}u, {1}, context.NamespaceUris)",
                    node.NumericId, namespaceUri);
            }

            // Fall back to string ID if specified
            if (!string.IsNullOrEmpty(node.StringId))
            {
                return CoreUtils.Format(
                    "global::Opc.Ua.NodeId.Create(\"{0}\", {1}, context.NamespaceUris)",
                    EscapeString(node.StringId), namespaceUri);
            }

            // Last resort: use symbolic ID name as string identifier
            // This matches the behavior in NodeIdGenerator for nodes without explicit IDs
            return CoreUtils.Format(
                "global::Opc.Ua.NodeId.Create(\"{0}\", {1}, context.NamespaceUris)",
                EscapeString(node.SymbolicId.Name), namespaceUri);
        }

        private string GetReferenceTypeIdConstant(XmlQualifiedName referenceType)
        {
            if (referenceType == null)
            {
                return "global::Opc.Ua.NodeId.Null";
            }

            NodeDesign node = m_context.Validator.FindNode(
                referenceType,
                referenceType.Name,
                "<ReferenceType>");
            if (node == null)
            {
                return "global::Opc.Ua.NodeId.Null";
            }

            return GetNodeIdConstant(node);
        }

        private static string GetValueCode(object value)
        {
            if (value == null)
            {
                return null;
            }

            return value switch
            {
                bool b => b.AsBooleanString(),
                byte b => CoreUtils.Format("(byte){0}", b),
                sbyte sb => CoreUtils.Format("(sbyte){0}", sb),
                short s => CoreUtils.Format("(short){0}", s),
                ushort us => CoreUtils.Format("(ushort){0}", us),
                int i => i.ToString(CultureInfo.InvariantCulture),
                uint ui => CoreUtils.Format("{0}u", ui),
                long l => CoreUtils.Format("{0}L", l),
                ulong ul => CoreUtils.Format("{0}UL", ul),
                float f => CoreUtils.Format("{0}f", f.ToString(CultureInfo.InvariantCulture)),
                double d => d.ToString(CultureInfo.InvariantCulture),
                string s => CoreUtils.Format("\"{0}\"", EscapeString(s)),
                DateTime dt => CoreUtils.Format(
                    "new global::System.DateTime({0}L, global::System.DateTimeKind.Utc)",
                    dt.Ticks),
                Guid g => CoreUtils.Format("new global::System.Guid(\"{0}\")", g),
                byte[] bytes => CoreUtils.Format("new byte[] {{ {0} }}",
                    string.Join(", ", bytes
                        .Select(b => b.ToString(CultureInfo.InvariantCulture)))),
                LocalizedText lt => CoreUtils.Format(
                    "new global::Opc.Ua.LocalizedText(\"{0}\")",
                    EscapeString(lt.Text ?? string.Empty)),
                QualifiedName qn => CoreUtils.Format(
                    "new global::Opc.Ua.QualifiedName(\"{0}\", {1})",
                    EscapeString(qn.Name),
                    qn.NamespaceIndex),
                _ => null // Complex types would need special handling
            };
        }

        private static string GetAccessLevelCode(AccessLevel accessLevel)
        {
            return accessLevel switch
            {
                AccessLevel.Read => "global::Opc.Ua.AccessLevels.CurrentRead",
                AccessLevel.Write => "global::Opc.Ua.AccessLevels.CurrentWrite",
                AccessLevel.ReadWrite => "global::Opc.Ua.AccessLevels.CurrentReadOrWrite",
                AccessLevel.HistoryRead => "global::Opc.Ua.AccessLevels.HistoryRead",
                AccessLevel.HistoryWrite => "global::Opc.Ua.AccessLevels.HistoryWrite",
                AccessLevel.HistoryReadWrite => "global::Opc.Ua.AccessLevels.HistoryReadOrWrite",
                _ => "global::Opc.Ua.AccessLevels.None"
            };
        }

        private static string GetArrayDimensionsCode(ValueRank valueRank, string arrayDimensions)
        {
            if (valueRank is < 0 and not ValueRank.OneOrMoreDimensions)
            {
                return null;
            }

            if (string.IsNullOrEmpty(arrayDimensions))
            {
                if (valueRank == ValueRank.Array)
                {
                    return "new global::Opc.Ua.ReadOnlyList<uint>(new uint[] { 0 })";
                }

                return null;
            }

            string[] tokens = arrayDimensions.Split([','], StringSplitOptions.RemoveEmptyEntries);

            if (tokens == null || tokens.Length < 1)
            {
                return null;
            }

            return CoreUtils.Format(
                "new global::Opc.Ua.ReadOnlyList<uint>(new uint[] {{ {0} }})",
                string.Join(", ", tokens.Select(t =>
                {
                    if (uint.TryParse(t.Trim(), out uint val))
                    {
                        return val.ToString(CultureInfo.InvariantCulture);
                    }
                    return "0";
                })));
        }

        private static string GetAccessRestrictionsCode(AccessRestrictions restrictions)
        {
            return restrictions switch
            {
                AccessRestrictions.SigningRequired => "global::Opc.Ua.AccessRestrictionType.SigningRequired",
                AccessRestrictions.EncryptionRequired => "global::Opc.Ua.AccessRestrictionType.EncryptionRequired",
                AccessRestrictions.SessionRequired => "global::Opc.Ua.AccessRestrictionType.SessionRequired",
                AccessRestrictions.SessionWithSigningRequired =>
                    "global::Opc.Ua.AccessRestrictionType.SigningRequired | global::Opc.Ua.AccessRestrictionType.SessionRequired",
                AccessRestrictions.SessionWithEncryptionRequired =>
                    "global::Opc.Ua.AccessRestrictionType.EncryptionRequired | global::Opc.Ua.AccessRestrictionType.SessionRequired",
                _ => null
            };
        }

        private static string GetPermissionTypeCode(Permissions[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return "global::Opc.Ua.PermissionType.None";
            }

            var parts = new List<string>();
            foreach (Permissions p in permissions)
            {
                string part = p switch
                {
                    Permissions.Browse => "global::Opc.Ua.PermissionType.Browse",
                    Permissions.Read => "global::Opc.Ua.PermissionType.Read",
                    Permissions.Write => "global::Opc.Ua.PermissionType.Write",
                    Permissions.Call => "global::Opc.Ua.PermissionType.Call",
                    Permissions.ReadHistory => "global::Opc.Ua.PermissionType.ReadHistory",
                    Permissions.InsertHistory => "global::Opc.Ua.PermissionType.InsertHistory",
                    Permissions.ModifyHistory => "global::Opc.Ua.PermissionType.ModifyHistory",
                    Permissions.DeleteHistory => "global::Opc.Ua.PermissionType.DeleteHistory",
                    Permissions.ReceiveEvents => "global::Opc.Ua.PermissionType.ReceiveEvents",
                    Permissions.AddNode => "global::Opc.Ua.PermissionType.AddNode",
                    Permissions.DeleteNode => "global::Opc.Ua.PermissionType.DeleteNode",
                    Permissions.AddReference => "global::Opc.Ua.PermissionType.AddReference",
                    Permissions.RemoveReference => "global::Opc.Ua.PermissionType.RemoveReference",
                    Permissions.ReadRolePermissions => "global::Opc.Ua.PermissionType.ReadRolePermissions",
                    Permissions.WriteRolePermissions => "global::Opc.Ua.PermissionType.WriteRolePermissions",
                    Permissions.WriteAttribute => "global::Opc.Ua.PermissionType.WriteAttribute",
                    Permissions.WriteHistorizing => "global::Opc.Ua.PermissionType.WriteHistorizing",
                    _ => null
                };
                if (part != null)
                {
                    parts.Add(part);
                }
            }

            return parts.Count > 0 ? string.Join(" | ", parts) : "global::Opc.Ua.PermissionType.None";
        }

        private static string EscapeString(string value)
        {
            if (value == null)
            {
                return string.Empty;
            }

            return value
                .Replace("\\", "\\\\", StringComparison.Ordinal)
                .Replace("\"", "\\\"", StringComparison.Ordinal)
                .Replace("\n", "\\n", StringComparison.Ordinal)
                .Replace("\r", "\\r", StringComparison.Ordinal)
                .Replace("\t", "\\t", StringComparison.Ordinal);
        }

        private readonly GeneratorContext m_context;
    }
}
