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
                LoadTemplate_NodeStateAddCall,
                WriteTemplate_NodeStateAddCall);

            // Write the Create_XXX methods at class level
            template.AddReplacement(
                Tokens.ListOfTypes,
                nodesToGenerate,
                LoadTemplate_NodeStateCreateMethod,
                WriteTemplate_NodeStateCreateMethod);

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

            if (m_context.Validator.IsExcluded(node))
            {
                return null;
            }

            return CodeTemplates.NodeState_Create_cs;
        }

        private bool WriteTemplate_NodeStateAddCall(IWriteContext context)
        {
            if (context.Target is not NodeDesign node)
            {
                return false;
            }

            string symbolicName = GetSafeSymbolicName(node);
            context.Template.AddReplacement(Tokens.SymbolicName, symbolicName);
            return context.Template.Render();
        }

        private TemplateString LoadTemplate_NodeStateCreateMethod(ILoadContext context)
        {
            if (context.Target is not NodeDesign node)
            {
                return null;
            }

            if (m_context.Validator.IsExcluded(node))
            {
                return null;
            }

            return node switch
            {
                ObjectTypeDesign => CodeTemplates.NodeState_ObjectType_cs,
                VariableTypeDesign => CodeTemplates.NodeState_VariableType_cs,
                ReferenceTypeDesign => CodeTemplates.NodeState_ReferenceType_cs,
                DataTypeDesign => CodeTemplates.NodeState_DataType_cs,
                ObjectDesign => CodeTemplates.NodeState_Object_cs,
                VariableDesign => CodeTemplates.NodeState_Variable_cs,
                MethodDesign => CodeTemplates.NodeState_Method_cs,
                ViewDesign => CodeTemplates.NodeState_View_cs,
                _ => null
            };
        }

        private bool WriteTemplate_NodeStateCreateMethod(IWriteContext context)
        {
            if (context.Target is not NodeDesign node)
            {
                return false;
            }

            string symbolicName = GetSafeSymbolicName(node);

            // Common replacements for all node types
            context.Template.AddReplacement(Tokens.SymbolicName, symbolicName);
            context.Template.AddReplacement(Tokens.NodeIdConstant, GetNodeIdConstant(node));
            context.Template.AddReplacement(Tokens.BrowseName, node.SymbolicName.Name);
            context.Template.AddReplacement(
                Tokens.BrowseNameValue,
                GetBrowseNameValue(node));
            context.Template.AddReplacement(
                Tokens.BrowseNameNamespaceUri,
                m_context.Validator.Dictionary.Namespaces.GetConstantSymbolForNamespace(
                    node.SymbolicName.Namespace));
            context.Template.AddReplacement(
                Tokens.DisplayNameValue,
                GetDisplayNameValue(node));
            context.Template.AddReplacement(
                Tokens.DescriptionValue,
                GetDescriptionValue(node));
            context.Template.AddReplacement(
                Tokens.WriteMaskValue,
                "global::Opc.Ua.AttributeWriteMask.None");
            context.Template.AddReplacement(
                Tokens.UserWriteMaskValue,
                "global::Opc.Ua.AttributeWriteMask.None");

            // Node type-specific replacements
            switch (node)
            {
                case ObjectTypeDesign objectType:
                    WriteObjectTypeReplacements(context, objectType);
                    break;
                case VariableTypeDesign variableType:
                    WriteVariableTypeReplacements(context, variableType);
                    break;
                case ReferenceTypeDesign referenceType:
                    WriteReferenceTypeReplacements(context, referenceType);
                    break;
                case DataTypeDesign dataType:
                    WriteDataTypeReplacements(context, dataType);
                    break;
                case ObjectDesign objectDesign:
                    WriteObjectReplacements(context, objectDesign);
                    break;
                case VariableDesign variableDesign:
                    WriteVariableReplacements(context, variableDesign);
                    break;
                case MethodDesign methodDesign:
                    WriteMethodReplacements(context, methodDesign);
                    break;
                case ViewDesign viewDesign:
                    WriteViewReplacements(context, viewDesign);
                    break;
            }

            // Common optional properties
            WriteOptionalPropertyReplacements(context, node);

            // Role permissions
            WriteRolePermissionsReplacement(context, node);

            // Child nodes
            WriteChildNodesReplacement(context, node, symbolicName);

            return context.Template.Render();
        }

        private void WriteObjectTypeReplacements(IWriteContext context, ObjectTypeDesign node)
        {
            context.Template.AddReplacement(
                Tokens.SuperTypeIdConstant,
                node.BaseTypeNode != null
                    ? GetNodeIdConstant(node.BaseTypeNode)
                    : "global::Opc.Ua.NodeId.Null");
            context.Template.AddReplacement(Tokens.IsAbstract, node.IsAbstract);
        }

        private void WriteVariableTypeReplacements(IWriteContext context, VariableTypeDesign node)
        {
            context.Template.AddReplacement(
                Tokens.SuperTypeIdConstant,
                node.BaseTypeNode != null
                    ? GetNodeIdConstant(node.BaseTypeNode)
                    : "global::Opc.Ua.NodeId.Null");
            context.Template.AddReplacement(Tokens.IsAbstract, node.IsAbstract);
            context.Template.AddReplacement(
                Tokens.DataTypeIdConstant,
                node.DataTypeNode != null
                    ? GetNodeIdConstant(node.DataTypeNode)
                    : "global::Opc.Ua.NodeId.Null");
            context.Template.AddReplacement(
                Tokens.ValueRank,
                node.ValueRank.GetValueRankString(node.ArrayDimensions));

            string arrayDims = node.ValueRank.GetArrayDimensionsAsCode(node.ArrayDimensions);
            context.Template.AddReplacement(
                Tokens.ArrayDimensions,
                !string.IsNullOrEmpty(arrayDims)
                    ? CoreUtils.Format("state.ArrayDimensions = {0};", arrayDims)
                    : string.Empty);

            context.Template.AddReplacement(
                Tokens.ValueCode,
                GetValueCodeReplacement(node.DecodedValue));
        }

        private void WriteReferenceTypeReplacements(IWriteContext context, ReferenceTypeDesign node)
        {
            context.Template.AddReplacement(
                Tokens.SuperTypeIdConstant,
                node.BaseTypeNode != null
                    ? GetNodeIdConstant(node.BaseTypeNode)
                    : "global::Opc.Ua.NodeId.Null");
            context.Template.AddReplacement(Tokens.IsAbstract, node.IsAbstract);
            context.Template.AddReplacement(Tokens.SymmetricValue, node.Symmetric);

            context.Template.AddReplacement(
                Tokens.InverseNameValue,
                GetInverseNameValue(node));
        }

        private void WriteDataTypeReplacements(IWriteContext context, DataTypeDesign node)
        {
            context.Template.AddReplacement(
                Tokens.SuperTypeIdConstant,
                node.BaseTypeNode != null
                    ? GetNodeIdConstant(node.BaseTypeNode)
                    : "global::Opc.Ua.NodeId.Null");
            context.Template.AddReplacement(Tokens.IsAbstract, node.IsAbstract);
        }

        private void WriteObjectReplacements(IWriteContext context, ObjectDesign node)
        {
            context.Template.AddReplacement(
                Tokens.TypeDefinitionIdConstant,
                node.TypeDefinitionNode != null
                    ? GetNodeIdConstant(node.TypeDefinitionNode)
                    : "global::Opc.Ua.NodeId.Null");
            context.Template.AddReplacement(
                Tokens.ReferenceTypeIdConstant,
                GetReferenceTypeIdConstant(node.ReferenceType));
            context.Template.AddReplacement(
                Tokens.ModellingRuleIdConstant,
                GetModellingRuleReplacement(node.ModellingRule));
            context.Template.AddReplacement(
                Tokens.EventNotifier,
                node.SupportsEvents
                    ? "global::Opc.Ua.EventNotifiers.SubscribeToEvents"
                    : "global::Opc.Ua.EventNotifiers.None");
        }

        private void WriteVariableReplacements(IWriteContext context, VariableDesign node)
        {
            bool isProperty = node is PropertyDesign;
            context.Template.AddReplacement(
                Tokens.StateClassName,
                isProperty
                    ? "global::Opc.Ua.PropertyState"
                    : "global::Opc.Ua.BaseDataVariableState");

            context.Template.AddReplacement(
                Tokens.TypeDefinitionIdConstant,
                node.TypeDefinitionNode != null
                    ? GetNodeIdConstant(node.TypeDefinitionNode)
                    : "global::Opc.Ua.NodeId.Null");
            context.Template.AddReplacement(
                Tokens.ReferenceTypeIdConstant,
                GetReferenceTypeIdConstant(node.ReferenceType));
            context.Template.AddReplacement(
                Tokens.ModellingRuleIdConstant,
                GetModellingRuleReplacement(node.ModellingRule));
            context.Template.AddReplacement(
                Tokens.DataTypeIdConstant,
                node.DataTypeNode != null
                    ? GetNodeIdConstant(node.DataTypeNode)
                    : "global::Opc.Ua.NodeId.Null");
            context.Template.AddReplacement(
                Tokens.ValueRank,
                node.ValueRank.GetValueRankString(node.ArrayDimensions));

            string arrayDims = node.ValueRank.GetArrayDimensionsAsCode(node.ArrayDimensions);
            context.Template.AddReplacement(
                Tokens.ArrayDimensions,
                !string.IsNullOrEmpty(arrayDims)
                    ? CoreUtils.Format("state.ArrayDimensions = {0};", arrayDims)
                    : string.Empty);

            context.Template.AddReplacement(
                Tokens.AccessLevelValue,
                node.AccessLevel.GetAccessLevelAsCode());
            context.Template.AddReplacement(
                Tokens.UserAccessLevelValue,
                node.AccessLevel.GetAccessLevelAsCode());
            context.Template.AddReplacement(
                Tokens.MinimumSamplingIntervalValue,
                node.MinimumSamplingInterval.ToString(CultureInfo.InvariantCulture));
            context.Template.AddReplacement(Tokens.HistorizingValue, node.Historizing);

            context.Template.AddReplacement(
                Tokens.ValueCode,
                GetValueCodeReplacement(node.DecodedValue));
        }

        private void WriteMethodReplacements(IWriteContext context, MethodDesign node)
        {
            context.Template.AddReplacement(
                Tokens.ReferenceTypeIdConstant,
                GetReferenceTypeIdConstant(node.ReferenceType));
            context.Template.AddReplacement(
                Tokens.ModellingRuleIdConstant,
                GetModellingRuleReplacement(node.ModellingRule));

            bool executable = !node.NonExecutable;
            context.Template.AddReplacement(Tokens.ExecutableValue, executable);

            context.Template.AddReplacement(
                Tokens.MethodDeclarationIdConstant,
                node.MethodDeclarationNode != null
                    ? CoreUtils.Format(
                        "state.MethodDeclarationId = {0};",
                        GetNodeIdConstant(node.MethodDeclarationNode))
                    : string.Empty);
        }

        private void WriteViewReplacements(IWriteContext context, ViewDesign node)
        {
            context.Template.AddReplacement(
                Tokens.EventNotifier,
                node.SupportsEvents
                    ? "global::Opc.Ua.EventNotifiers.SubscribeToEvents"
                    : "global::Opc.Ua.EventNotifiers.None");
            context.Template.AddReplacement(Tokens.ContainsNoLoopsValue, node.ContainsNoLoops);
        }

        private void WriteOptionalPropertyReplacements(IWriteContext context, NodeDesign node)
        {
            // Release status
            Export.ReleaseStatus releaseStatus = node.ReleaseStatus.ToNodeSetReleaseStatus();
            context.Template.AddReplacement(
                Tokens.ReleaseStatusValue,
                releaseStatus != Export.ReleaseStatus.Released
                    ? CoreUtils.Format(
                        "state.ReleaseStatus = global::Opc.Ua.Export.ReleaseStatus.{0};",
                        releaseStatus)
                    : string.Empty);

            // Categories
            context.Template.AddReplacement(
                Tokens.CategoriesValue,
                !string.IsNullOrEmpty(node.Category)
                    ? CoreUtils.Format(
                        "state.Categories = new string[] {{ {0} }};",
                        string.Join(
                            ", ",
                            node.Category.Split([',']).Select(c => CoreUtils.Format("\"{0}\"", c.Trim()))))
                    : string.Empty);

            // Specification
            context.Template.AddReplacement(
                Tokens.SpecificationValue,
                node.PartNo != 0
                    ? CoreUtils.Format("state.Specification = \"Part{0}\";", node.PartNo)
                    : string.Empty);

            // Access restrictions
            context.Template.AddReplacement(
                Tokens.AccessRestrictionsValue,
                node.AccessRestrictionsSpecified
                    ? CoreUtils.Format(
                        "state.AccessRestrictions = {0};",
                        node.AccessRestrictions.GetAccessRestrictionsAsCode())
                    : string.Empty);
        }

        private void WriteRolePermissionsReplacement(IWriteContext context, NodeDesign node)
        {
            if (node.RolePermissions?.RolePermission == null ||
                node.RolePermissions.RolePermission.Length == 0)
            {
                context.Template.AddReplacement(Tokens.ListOfRolePermissions, string.Empty);
                return;
            }

            var rolePermissions = new List<RolePermission>();
            foreach (RolePermission rp in node.RolePermissions.RolePermission)
            {
                ObjectDesign roleNode = m_context.Validator.FindNode<ObjectDesign>(
                    rp.Role,
                    rp.Role.Name,
                    "RoleType");

                if (roleNode != null)
                {
                    rolePermissions.Add(rp);
                }
            }

            if (rolePermissions.Count == 0)
            {
                context.Template.AddReplacement(Tokens.ListOfRolePermissions, string.Empty);
                return;
            }

            context.Template.AddReplacement(
                Tokens.ListOfRolePermissions,
                CodeTemplates.NodeState_RolePermissionsInit_cs,
                rolePermissions,
                LoadTemplate_RolePermission,
                WriteTemplate_RolePermission);
        }

        private TemplateString LoadTemplate_RolePermission(ILoadContext context)
        {
            if (context.Target is not RolePermission)
            {
                return null;
            }

            return CodeTemplates.NodeState_RolePermission_cs;
        }

        private bool WriteTemplate_RolePermission(IWriteContext context)
        {
            if (context.Target is not RolePermission rolePermission)
            {
                return false;
            }

            ObjectDesign roleNode = m_context.Validator.FindNode<ObjectDesign>(
                rolePermission.Role,
                rolePermission.Role.Name,
                "RoleType");

            if (roleNode == null)
            {
                return false;
            }

            context.Template.AddReplacement(
                Tokens.RoleIdConstant,
                GetNodeIdConstant(roleNode));
            context.Template.AddReplacement(
                Tokens.PermissionsValue,
                CoreUtils.Format("(uint)({0})", rolePermission.Permission.GetPermissionTypeAsCode()));

            return context.Template.Render();
        }

        private void WriteChildNodesReplacement(
            IWriteContext context,
            NodeDesign node,
            string parentSymbolicName)
        {
            if (node.Children?.Items == null || node.Children.Items.Length == 0)
            {
                context.Template.AddReplacement(Tokens.ListOfChildNodeStates, string.Empty);
                return;
            }

            var childNodes = node.Children.Items
                .Where(child => !m_context.Validator.IsExcluded(child) &&
                    child.ModellingRule is
                    not ModellingRule.ExposesItsArray and
                    not ModellingRule.MandatoryPlaceholder and
                    not ModellingRule.OptionalPlaceholder)
                .ToList();

            if (childNodes.Count == 0)
            {
                context.Template.AddReplacement(Tokens.ListOfChildNodeStates, string.Empty);
                return;
            }

            // For simplicity, we'll write children directly instead of using nested templates
            // This is similar to the original approach but cleaner
            context.Template.AddReplacement(
                Tokens.ListOfChildNodeStates,
                childNodes,
                c => LoadTemplate_AddChildCall(c, parentSymbolicName),
                c => WriteTemplate_AddChildCall(c, parentSymbolicName));

            foreach (var child in childNodes)
            {

            }
        }

        private TemplateString LoadTemplate_AddChildCall(ILoadContext context, string parentSymbolicName)
        {
            if (context.Target is not InstanceDesign child)
            {
                return null;
            }

            string childMethodSuffix = CoreUtils.Format(
                "{0}_{1}",
                parentSymbolicName,
                child.SymbolicName.Name);

            context.Out.WriteLine(
                "state.AddChild(Create_{0}(context, state));",
                childMethodSuffix);

            // Write the child method after the parent
            WriteChildNodeMethod(context.Out, child, parentSymbolicName);

            return null;
        }

        private bool WriteTemplate_AddChildCall(IWriteContext context, string parentSymbolicName)
        {
            if (context.Target is not InstanceDesign child)
            {
                return false;
            }

            context.Template.AddReplacement(Tokens.SymbolicName, parentSymbolicName);
            context.Template.AddReplacement(Tokens.ChildName, child.SymbolicName.Name);
            return context.Template.Render();
        }

        private void WriteChildNodeMethod(
            ITemplateWriter writer,
            InstanceDesign child,
            string parentSymbolicName)
        {
            string childMethodSuffix = CoreUtils.Format(
                "{0}_{1}",
                parentSymbolicName,
                child.SymbolicName.Name);

            switch (child)
            {
                case ObjectDesign objectChild:
                    WriteChildObjectMethod(writer, objectChild, childMethodSuffix);
                    break;
                case VariableDesign variableChild:
                    WriteChildVariableMethod(writer, variableChild, childMethodSuffix);
                    break;
                case MethodDesign methodChild:
                    WriteChildMethodMethod(writer, methodChild, childMethodSuffix);
                    break;
            }
        }

        private void WriteChildObjectMethod(
            ITemplateWriter writer,
            ObjectDesign node,
            string methodSuffix)
        {
            writer.WriteLine();
            writer.WriteLine("private static global::Opc.Ua.BaseObjectState Create_{0}(", methodSuffix);
            writer.WriteLine("    global::Opc.Ua.ISystemContext context,");
            writer.WriteLine("    global::Opc.Ua.NodeState parent)");
            writer.WriteLine("{");
            writer.WriteLine("    var state = new global::Opc.Ua.BaseObjectState(parent);");
            WriteCommonChildProperties(writer, node);
            writer.WriteLine("    state.TypeDefinitionId = {0};",
                node.TypeDefinitionNode != null
                    ? GetNodeIdConstant(node.TypeDefinitionNode)
                    : "global::Opc.Ua.NodeId.Null");
            writer.WriteLine("    state.ReferenceTypeId = {0};",
                GetReferenceTypeIdConstant(node.ReferenceType));
            WriteModellingRuleId(writer, node.ModellingRule);
            writer.WriteLine("    state.EventNotifier = {0};",
                node.SupportsEvents
                    ? "global::Opc.Ua.EventNotifiers.SubscribeToEvents"
                    : "global::Opc.Ua.EventNotifiers.None");
            WriteInstanceOptionalProperties(writer, node);
            WriteChildNodes(writer, node, methodSuffix);
            writer.WriteLine("    return state;");
            writer.WriteLine("}");
            WriteChildNodeMethods(writer, node, methodSuffix);
        }

        private void WriteChildVariableMethod(
            ITemplateWriter writer,
            VariableDesign node,
            string methodSuffix)
        {
            bool isProperty = node is PropertyDesign;
            string stateClassName = isProperty
                ? "global::Opc.Ua.PropertyState"
                : "global::Opc.Ua.BaseDataVariableState";

            writer.WriteLine();
            writer.WriteLine("private static global::Opc.Ua.BaseVariableState Create_{0}(", methodSuffix);
            writer.WriteLine("    global::Opc.Ua.ISystemContext context,");
            writer.WriteLine("    global::Opc.Ua.NodeState parent)");
            writer.WriteLine("{");
            writer.WriteLine("    var state = new {0}(parent);", stateClassName);
            WriteCommonChildProperties(writer, node);
            writer.WriteLine("    state.TypeDefinitionId = {0};",
                node.TypeDefinitionNode != null
                    ? GetNodeIdConstant(node.TypeDefinitionNode)
                    : "global::Opc.Ua.NodeId.Null");
            writer.WriteLine("    state.ReferenceTypeId = {0};",
                GetReferenceTypeIdConstant(node.ReferenceType));
            WriteModellingRuleId(writer, node.ModellingRule);
            writer.WriteLine("    state.DataType = {0};",
                node.DataTypeNode != null
                    ? GetNodeIdConstant(node.DataTypeNode)
                    : "global::Opc.Ua.NodeId.Null");
            writer.WriteLine("    state.ValueRank = {0};",
                node.ValueRank.GetValueRankString(node.ArrayDimensions));
            string arrayDims = node.ValueRank.GetArrayDimensionsAsCode(node.ArrayDimensions);
            if (!string.IsNullOrEmpty(arrayDims))
            {
                writer.WriteLine("    state.ArrayDimensions = {0};", arrayDims);
            }
            writer.WriteLine("    state.AccessLevel = {0};", node.AccessLevel.GetAccessLevelAsCode());
            writer.WriteLine("    state.UserAccessLevel = state.AccessLevel;");
            writer.WriteLine("    state.MinimumSamplingInterval = {0};",
                node.MinimumSamplingInterval.ToString(CultureInfo.InvariantCulture));
            writer.WriteLine("    state.Historizing = {0};", node.Historizing.AsBooleanString());
            if (node.DecodedValue != null)
            {
                string valueCode = GetValueCode(node.DecodedValue);
                if (!string.IsNullOrEmpty(valueCode))
                {
                    writer.WriteLine("    state.Value = {0};", valueCode);
                }
            }
            WriteInstanceOptionalProperties(writer, node);
            WriteChildNodes(writer, node, methodSuffix);
            writer.WriteLine("    return state;");
            writer.WriteLine("}");
            WriteChildNodeMethods(writer, node, methodSuffix);
        }

        private void WriteChildMethodMethod(
            ITemplateWriter writer,
            MethodDesign node,
            string methodSuffix)
        {
            writer.WriteLine();
            writer.WriteLine("private static global::Opc.Ua.MethodState Create_{0}(", methodSuffix);
            writer.WriteLine("    global::Opc.Ua.ISystemContext context,");
            writer.WriteLine("    global::Opc.Ua.NodeState parent)");
            writer.WriteLine("{");
            writer.WriteLine("    var state = new global::Opc.Ua.MethodState(parent);");
            WriteCommonChildProperties(writer, node);
            writer.WriteLine("    state.ReferenceTypeId = {0};",
                GetReferenceTypeIdConstant(node.ReferenceType));
            WriteModellingRuleId(writer, node.ModellingRule);
            bool executable = !node.NonExecutable;
            writer.WriteLine("    state.Executable = {0};", executable.AsBooleanString());
            writer.WriteLine("    state.UserExecutable = {0};", executable.AsBooleanString());
            if (node.MethodDeclarationNode != null)
            {
                writer.WriteLine("    state.MethodDeclarationId = {0};",
                    GetNodeIdConstant(node.MethodDeclarationNode));
            }
            WriteInstanceOptionalProperties(writer, node);
            WriteChildNodes(writer, node, methodSuffix);
            writer.WriteLine("    return state;");
            writer.WriteLine("}");
            WriteChildNodeMethods(writer, node, methodSuffix);
        }

        private void WriteCommonChildProperties(ITemplateWriter writer, NodeDesign node)
        {
            writer.WriteLine("    state.SymbolicName = \"{0}\";", node.SymbolicName.Name);
            writer.WriteLine("    state.NodeId = {0};", GetNodeIdConstant(node));

            string browseNameValue = !string.IsNullOrEmpty(node.BrowseName)
                ? node.BrowseName
                : node.SymbolicName.Name;
            string browseNameUri = m_context.Validator.Dictionary.Namespaces
                .GetConstantSymbolForNamespace(node.SymbolicName.Namespace);
            writer.WriteLine("    state.BrowseName = new global::Opc.Ua.QualifiedName(");
            writer.WriteLine("        \"{0}\",", EscapeString(browseNameValue));
            writer.WriteLine("        context.NamespaceUris.GetIndexOrAppend({0}));", browseNameUri);

            if (node.DisplayName != null)
            {
                writer.WriteLine("    state.DisplayName = new global::Opc.Ua.LocalizedText(\"{0}\", string.Empty, \"{1}\");",
                    EscapeString(node.DisplayName.Key ?? string.Empty),
                    EscapeString(node.DisplayName.Value?.Trim() ?? node.SymbolicName.Name));
            }
            else
            {
                writer.WriteLine("    state.DisplayName = new global::Opc.Ua.LocalizedText(\"{0}\");",
                    node.SymbolicName.Name);
            }

            if (node.Description != null && !node.Description.IsAutogenerated)
            {
                writer.WriteLine("    state.Description = new global::Opc.Ua.LocalizedText(\"{0}\", string.Empty, \"{1}\");",
                    EscapeString(node.Description.Key ?? string.Empty),
                    EscapeString(node.Description.Value?.Trim() ?? string.Empty));
            }

            writer.WriteLine("    state.WriteMask = global::Opc.Ua.AttributeWriteMask.None;");
            writer.WriteLine("    state.UserWriteMask = global::Opc.Ua.AttributeWriteMask.None;");
        }

        private void WriteInstanceOptionalProperties(ITemplateWriter writer, InstanceDesign node)
        {
            Export.ReleaseStatus releaseStatus = node.ReleaseStatus.ToNodeSetReleaseStatus();
            if (releaseStatus != Export.ReleaseStatus.Released)
            {
                writer.WriteLine("    state.ReleaseStatus = global::Opc.Ua.Export.ReleaseStatus.{0};",
                    releaseStatus);
            }

            if (!string.IsNullOrEmpty(node.Category))
            {
                string[] categories = node.Category.Split([',']);
                writer.WriteLine("    state.Categories = new string[] {{ {0} }};",
                    string.Join(", ", categories.Select(c => CoreUtils.Format("\"{0}\"", c.Trim()))));
            }

            if (node.PartNo != 0)
            {
                writer.WriteLine("    state.Specification = \"Part{0}\";", node.PartNo);
            }

            if (node.AccessRestrictionsSpecified)
            {
                string accessRestrictionsCode = node.AccessRestrictions.GetAccessRestrictionsAsCode();
                if (!string.IsNullOrEmpty(accessRestrictionsCode))
                {
                    writer.WriteLine("    state.AccessRestrictions = {0};", accessRestrictionsCode);
                }
            }

            WriteRolePermissions(writer, node);
        }

        private void WriteRolePermissions(ITemplateWriter writer, NodeDesign node)
        {
            if (node.RolePermissions?.RolePermission == null ||
                node.RolePermissions.RolePermission.Length == 0)
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
                    string permissionValue = rolePermission.Permission.GetPermissionTypeAsCode();
                    writer.WriteLine("    state.RolePermissions.Add(new global::Opc.Ua.RolePermissionType");
                    writer.WriteLine("    {");
                    writer.WriteLine("        RoleId = {0},", GetNodeIdConstant(roleNode));
                    writer.WriteLine("        Permissions = (uint)({0})", permissionValue);
                    writer.WriteLine("    });");
                }
            }
        }

        private static void WriteModellingRuleId(ITemplateWriter writer, ModellingRule modellingRule)
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

        private void WriteChildNodes(ITemplateWriter writer, NodeDesign node, string parentMethodSuffix)
        {
            if (node.Children?.Items == null || node.Children.Items.Length == 0)
            {
                return;
            }

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

                string childMethodSuffix = CoreUtils.Format(
                    "{0}_{1}",
                    parentMethodSuffix,
                    child.SymbolicName.Name);

                writer.WriteLine("    state.AddChild(Create_{0}(context, state));", childMethodSuffix);
            }
        }

        private void WriteChildNodeMethods(ITemplateWriter writer, NodeDesign node, string parentMethodSuffix)
        {
            if (node.Children?.Items == null || node.Children.Items.Length == 0)
            {
                return;
            }

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

                WriteChildNodeMethod(writer, child, parentMethodSuffix);
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

            if (node.NumericIdSpecified)
            {
                return CoreUtils.Format(
                    "global::Opc.Ua.NodeId.Create({0}u, {1}, context.NamespaceUris)",
                    node.NumericId, namespaceUri);
            }

            if (!string.IsNullOrEmpty(node.StringId))
            {
                return CoreUtils.Format(
                    "global::Opc.Ua.NodeId.Create(\"{0}\", {1}, context.NamespaceUris)",
                    EscapeString(node.StringId), namespaceUri);
            }

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

        private string GetBrowseNameValue(NodeDesign node)
        {
            string browseNameValue = !string.IsNullOrEmpty(node.BrowseName)
                ? node.BrowseName
                : node.SymbolicName.Name;
            return CoreUtils.Format("\"{0}\"", EscapeString(browseNameValue));
        }

        private string GetDisplayNameValue(NodeDesign node)
        {
            if (node.DisplayName != null)
            {
                return CoreUtils.Format(
                    "\"{0}\", string.Empty, \"{1}\"",
                    EscapeString(node.DisplayName.Key ?? string.Empty),
                    EscapeString(node.DisplayName.Value?.Trim() ?? node.SymbolicName.Name));
            }

            return CoreUtils.Format("\"{0}\"", node.SymbolicName.Name);
        }

        private static string GetDescriptionValue(NodeDesign node)
        {
            if (node.Description != null && !node.Description.IsAutogenerated)
            {
                return CoreUtils.Format(
                    "state.Description = new global::Opc.Ua.LocalizedText(\"{0}\", string.Empty, \"{1}\");",
                    EscapeString(node.Description.Key ?? string.Empty),
                    EscapeString(node.Description.Value?.Trim() ?? string.Empty));
            }

            return string.Empty;
        }

        private static string GetInverseNameValue(ReferenceTypeDesign node)
        {
            if (!node.Symmetric && node.InverseName != null)
            {
                return CoreUtils.Format(
                    "state.InverseName = new global::Opc.Ua.LocalizedText(\"{0}\", string.Empty, \"{1}\");",
                    EscapeString(node.InverseName.Key ?? string.Empty),
                    EscapeString(node.InverseName.Value ?? string.Empty));
            }

            if (node.Symmetric)
            {
                return "state.InverseName = global::Opc.Ua.LocalizedText.Null;";
            }

            return string.Empty;
        }

        private static string GetModellingRuleReplacement(ModellingRule modellingRule)
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

            return constant != null
                ? CoreUtils.Format("state.ModellingRuleId = {0};", constant)
                : string.Empty;
        }

        private static string GetValueCodeReplacement(object value)
        {
            if (value == null)
            {
                return string.Empty;
            }

            string valueCode = GetValueCode(value);
            return !string.IsNullOrEmpty(valueCode)
                ? CoreUtils.Format("state.Value = {0};", valueCode)
                : string.Empty;
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
                byte b => CoreUtils.Format("(byte){0}", b.ToString(CultureInfo.InvariantCulture)),
                sbyte sb => CoreUtils.Format("(sbyte){0}", sb.ToString(CultureInfo.InvariantCulture)),
                short s => CoreUtils.Format("(short){0}", s.ToString(CultureInfo.InvariantCulture)),
                ushort us => CoreUtils.Format("(ushort){0}", us.ToString(CultureInfo.InvariantCulture)),
                int i => i.ToString(CultureInfo.InvariantCulture),
                uint ui => CoreUtils.Format("{0}u", ui.ToString(CultureInfo.InvariantCulture)),
                long l => CoreUtils.Format("{0}L", l.ToString(CultureInfo.InvariantCulture)),
                ulong ul => CoreUtils.Format("{0}UL", ul.ToString(CultureInfo.InvariantCulture)),
                float f => CoreUtils.Format("{0}f", f.ToString(CultureInfo.InvariantCulture)),
                double d => d.ToString(CultureInfo.InvariantCulture),
                string s => CoreUtils.Format("\"{0}\"", EscapeString(s)),
                DateTime dt => CoreUtils.Format(
                    "new global::System.DateTime({0}L, global::System.DateTimeKind.Utc)",
                    dt.Ticks.ToString(CultureInfo.InvariantCulture)),
                Guid g => CoreUtils.Format("new global::System.Guid(\"{0}\")", g),
                byte[] bytes => CoreUtils.Format("new byte[] {{ {0} }}",
                    string.Join(", ", bytes.Select(b => b.ToString(CultureInfo.InvariantCulture)))),
                LocalizedText lt => CoreUtils.Format(
                    "new global::Opc.Ua.LocalizedText(\"{0}\")",
                    EscapeString(lt.Text ?? string.Empty)),
                QualifiedName qn => CoreUtils.Format(
                    "new global::Opc.Ua.QualifiedName(\"{0}\", {1})",
                    EscapeString(qn.Name),
                    qn.NamespaceIndex.ToString(CultureInfo.InvariantCulture)),
                _ => null
            };
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
