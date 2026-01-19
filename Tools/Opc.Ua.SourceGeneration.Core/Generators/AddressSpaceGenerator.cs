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
using System.Xml.Linq;
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

            // Write the methods to fill node state collection
            template.AddReplacement(
                Tokens.ListOfNodeStateInitializers,
                CodeTemplates.NodeState_Add_cs,
                nodesToGenerate,
                WriteTemplate_NodeStateAddCall);

            // Write the nodestate factory methods at class level
            template.AddReplacement(
                Tokens.ListOfTypes,
                nodesToGenerate,
                LoadTemplate_ListOfNodeStateFactories,
                WriteTemplate_ListOfNodeStateFactories);

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

        private bool WriteTemplate_NodeStateAddCall(IWriteContext context)
        {
            if (context.Target is not NodeDesign node)
            {
                return false;
            }

            context.Template.AddReplacement(Tokens.SymbolicId, node.SymbolicId.Name);
            return context.Template.Render();
        }

        private TemplateString LoadTemplate_ListOfNodeStateFactories(ILoadContext context)
        {
            if (context.Target is not NodeDesign node)
            {
                return null;
            }

            if (context.Token == Tokens.ListOfChildTypes)
            {
                return node switch
                {
                    ObjectDesign => CodeTemplates.NodeState_ChildObject_cs,
                    VariableDesign => CodeTemplates.NodeState_ChildVariable_cs,
                    MethodDesign => CodeTemplates.NodeState_ChildMethod_cs,
                    _ => null
                };
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

        private bool WriteTemplate_ListOfNodeStateFactories(IWriteContext context)
        {
            if (context.Target is not NodeDesign node)
            {
                return false;
            }

            // Common replacements for all node types
            context.Template.AddReplacement(Tokens.SymbolicId, node.SymbolicId.Name);
            context.Template.AddReplacement(Tokens.SymbolicName, node.SymbolicName.Name);
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
                    AddObjectTypeReplacements(context, objectType);
                    break;
                case VariableTypeDesign variableType:
                    AddVariableTypeReplacements(context, variableType);
                    break;
                case ReferenceTypeDesign referenceType:
                    AddReferenceTypeReplacements(context, referenceType);
                    break;
                case DataTypeDesign dataType:
                    AddDataTypeReplacements(context, dataType);
                    break;
                case ObjectDesign objectDesign:
                    AddObjectReplacements(context, objectDesign);
                    break;
                case VariableDesign variableDesign:
                    AddVariableReplacements(context, variableDesign);
                    break;
                case MethodDesign methodDesign:
                    AddMethodReplacements(context, methodDesign);
                    break;
                case ViewDesign viewDesign:
                    AddViewReplacements(context, viewDesign);
                    break;
            }

            // Common optional properties
            AddOptionalPropertyReplacements(context, node);

            // Role permissions
            List<RolePermission> rolePermissions = GetRolePermissions(node);
            context.Template.AddReplacement(
                Tokens.ListOfRolePermissions,
                CodeTemplates.NodeState_RolePermissions_cs,
                [rolePermissions],
                WriteTemplate_RolePermissions);

            // Child nodes
            List<InstanceDesign> childNodes = GetChildNodes(node);
            context.Template.AddReplacement(
                Tokens.ListOfChildNodeStates,
                CodeTemplates.NodeState_AddChild_cs,
                childNodes,
                WriteTemplate_AddChild);
            context.Template.AddReplacement(
                Tokens.ListOfChildTypes,
                childNodes,
                LoadTemplate_ListOfNodeStateFactories,
                WriteTemplate_ListOfNodeStateFactories);

            return context.Template.Render();
        }

        private bool WriteTemplate_AddChild(IWriteContext context)
        {
            if (context.Target is not InstanceDesign node || node.Parent == null)
            {
                return false;
            }

            context.Template.AddReplacement(Tokens.SymbolicId, node.SymbolicId.Name);
            return context.Template.Render();
        }

        private bool WriteTemplate_RolePermissions(IWriteContext context)
        {
            if (context.Target is not List<RolePermission> rolePermissions ||
                rolePermissions.Count == 0)
            {
                return false;
            }

            context.Template.AddReplacement(
                Tokens.ListOfRolePermissions,
                CodeTemplates.NodeState_RolePermission_cs,
                rolePermissions,
                LoadTemplate_RolePermissionEntry,
                WriteTemplate_RolePermissionEntry);
            return context.Template.Render();
        }

        private void AddObjectTypeReplacements(IWriteContext context, ObjectTypeDesign node)
        {
            context.Template.AddReplacement(
                Tokens.SuperTypeIdConstant,
                node.BaseTypeNode != null
                    ? GetNodeIdConstant(node.BaseTypeNode)
                    : "global::Opc.Ua.NodeId.Null");
            context.Template.AddReplacement(Tokens.IsAbstract, node.IsAbstract);
        }

        private void AddVariableTypeReplacements(IWriteContext context, VariableTypeDesign node)
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
                    : null);

            context.Template.AddReplacement(
                Tokens.ValueCode,
                GetValueCodeReplacement(node.DecodedValue));
        }

        private void AddReferenceTypeReplacements(IWriteContext context, ReferenceTypeDesign node)
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

        private void AddDataTypeReplacements(IWriteContext context, DataTypeDesign node)
        {
            context.Template.AddReplacement(
                Tokens.SuperTypeIdConstant,
                node.BaseTypeNode != null
                    ? GetNodeIdConstant(node.BaseTypeNode)
                    : "global::Opc.Ua.NodeId.Null");
            context.Template.AddReplacement(Tokens.IsAbstract, node.IsAbstract);
        }

        private void AddObjectReplacements(IWriteContext context, ObjectDesign node)
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

        private void AddVariableReplacements(IWriteContext context, VariableDesign node)
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
                    : null);

            context.Template.AddReplacement(
                Tokens.AccessLevelValue,
                node.AccessLevel.GetAccessLevelAsCode());
            context.Template.AddReplacement(
                Tokens.UserAccessLevelValue,
                //  node.AccessLevel.GetAccessLevelAsCode()); // TODO: Undo
                "state.AccessLevel");
            context.Template.AddReplacement(
                Tokens.MinimumSamplingIntervalValue,
                node.MinimumSamplingInterval.ToString(CultureInfo.InvariantCulture));
            context.Template.AddReplacement(Tokens.HistorizingValue, node.Historizing);

            context.Template.AddReplacement(
                Tokens.ValueCode,
                GetValueCodeReplacement(node.DecodedValue));
        }

        private void AddMethodReplacements(IWriteContext context, MethodDesign node)
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
                    : null);
        }

        private void AddViewReplacements(IWriteContext context, ViewDesign node)
        {
            context.Template.AddReplacement(
                Tokens.EventNotifier,
                node.SupportsEvents
                    ? "global::Opc.Ua.EventNotifiers.SubscribeToEvents"
                    : "global::Opc.Ua.EventNotifiers.None");
            context.Template.AddReplacement(Tokens.ContainsNoLoopsValue, node.ContainsNoLoops);
        }

        private void AddOptionalPropertyReplacements(IWriteContext context, NodeDesign node)
        {
            // Release status
            Export.ReleaseStatus releaseStatus = node.ReleaseStatus.ToNodeSetReleaseStatus();
            context.Template.AddReplacement(
                Tokens.ReleaseStatusValue,
                releaseStatus != Export.ReleaseStatus.Released
                    ? CoreUtils.Format(
                        "state.ReleaseStatus = global::Opc.Ua.Export.ReleaseStatus.{0};",
                        releaseStatus)
                    : null);

            // Categories
            context.Template.AddReplacement(
                Tokens.CategoriesValue,
                !string.IsNullOrEmpty(node.Category)
                    ? CoreUtils.Format(
                        "state.Categories = new string[] {{ {0} }};",
                        string.Join(
                            ", ",
                            node.Category
                                .Split([','])
                                .Select(c => CoreUtils.Format("\"{0}\"", c.Trim()))))
                    : null);

            // Specification
            context.Template.AddReplacement(
                Tokens.SpecificationValue,
                node.PartNo != 0
                    ? CoreUtils.Format("state.Specification = \"Part{0}\";", node.PartNo)
                    : null);

            // Access restrictions
            context.Template.AddReplacement(
                Tokens.AccessRestrictionsValue,
                node.AccessRestrictionsSpecified
                    ? CoreUtils.Format(
                        "state.AccessRestrictions = {0};",
                        node.AccessRestrictions.GetAccessRestrictionsAsCode())
                    : null);
        }

        private TemplateString LoadTemplate_RolePermissionEntry(ILoadContext context)
        {
            if (context.Target is not RolePermission)
            {
                return null;
            }

            return CodeTemplates.NodeState_RolePermission_cs;
        }

        private bool WriteTemplate_RolePermissionEntry(IWriteContext context)
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

        internal List<NodeDesign> GetNodesToGenerate()
        {
            var nodes = new List<NodeDesign>();

            foreach (NodeDesign node in m_context.Validator.Dictionary.Items)
            {
                if (!m_context.Validator.IsExcluded(node) && !node.IsMethodTypeNode())
                {
                    nodes.Add(node);
                }
            }

            return nodes;
        }

        private List<InstanceDesign> GetChildNodes(NodeDesign parent)
        {
            if (parent.Children?.Items == null || parent.Children.Items.Length == 0)
            {
                return [];
            }

            return [.. parent.Children.Items
                .Where(child => !m_context.Validator.IsExcluded(child) &&
                    child.ModellingRule is
                    not ModellingRule.ExposesItsArray and
                    not ModellingRule.MandatoryPlaceholder and
                    not ModellingRule.OptionalPlaceholder)];
        }

        private List<RolePermission> GetRolePermissions(NodeDesign node)
        {
            var rolePermissions = new List<RolePermission>();
            if (node.RolePermissions?.RolePermission != null)
            {
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
            }
            return rolePermissions;
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

        private static string GetBrowseNameValue(NodeDesign node)
        {
            string browseNameValue = !string.IsNullOrEmpty(node.BrowseName)
                ? node.BrowseName
                : node.SymbolicName.Name;
            return CoreUtils.Format("\"{0}\"", EscapeString(browseNameValue));
        }

        private static string GetDisplayNameValue(NodeDesign node)
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

            return null;
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

            return null;
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
                : null;
        }

        private static string GetValueCodeReplacement(object value)
        {
            if (value == null)
            {
                return null;
            }

            string valueCode = GetValueCode(value);
            return !string.IsNullOrEmpty(valueCode)
                ? CoreUtils.Format("state.Value = {0};", valueCode)
                : null;
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
