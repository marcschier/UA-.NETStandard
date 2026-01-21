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
using System.Linq;
using System.Xml;
using Microsoft.Extensions.Logging;
using Opc.Ua.Types;

namespace Opc.Ua.Schema.Model
{
    /// <summary>
    /// Generates Node state instances
    /// </summary>
    internal class ModelDesignToNodeState
    {
        /// <summary>
        /// Intializes the object with default values.
        /// </summary>
        public ModelDesignToNodeState(
            IModelDesign modelDesign,
            IServiceMessageContext context)
        {
            m_logger = context.Telemetry.CreateLogger<ModelDesignToNodeState>();
            m_modelDesign = modelDesign;
            m_context = new SystemContext(context.Telemetry)
            {
                NamespaceUris = context.NamespaceUris
            };
        }

        /// <summary>
        /// Create node states for the items in the model design
        /// </summary>
        public void AttachNodeStatesToNodeDesigns()
        {
            // update the references.
            foreach (NodeDesign node in m_modelDesign.Nodes)
            {
                CreateNodeState(node, m_modelDesign.NamespaceUris);
            }
        }

        private void CreateNodeState(
            NodeDesign root,
            NamespaceTable namespaceUris)
        {
            if (root is InstanceDesign)
            {
                root.State = CreateNodeState(
                    null,
                    string.Empty,
                    root.Hierarchy,
                    root.Hierarchy.NodeList[0].Instance,
                    false,
                    false,
                    namespaceUris);

                ClearModellingRules(root.State as BaseInstanceState);
            }
            else
            {
                root.State = CreateNodeState(
                    null,
                    string.Empty,
                    root.Hierarchy,
                    root,
                    true,
                    true,
                    namespaceUris);

                root.State.Categories = null;
                root.State.ReleaseStatus = root.ReleaseStatus.ToNodeSetReleaseStatus();

                if (!string.IsNullOrEmpty(root.Category))
                {
                    root.State.Categories = root.Category.Split([',']);
                }

                if (root.PartNo != 0)
                {
                    root.State.Specification = $"Part{root.PartNo}";
                }
            }

            root.State.Extensions = root.Extensions;

            if (root.Hierarchy != null &&
                root is TypeDesign &&
                root.Hierarchy.Nodes.TryGetValue(string.Empty, out HierarchyNode hierarchyNode))
            {
                if (hierarchyNode.Identifier != null)
                {
                    if (hierarchyNode.Identifier is uint numericId)
                    {
                        hierarchyNode.Instance.NumericId = numericId;
                        hierarchyNode.Instance.NumericIdSpecified = true;
                    }
                    else if (hierarchyNode.Identifier is string stringId)
                    {
                        hierarchyNode.Instance.StringId = stringId;
                    }
                    else
                    {
                        throw new InvalidOperationException(CoreUtils.Format(
                            "Invalid identifier {0}",
                            hierarchyNode.Identifier));
                    }
                }

                root.InstanceState = hierarchyNode.Instance.State = CreateNodeState(
                    null,
                    string.Empty,
                    root.Hierarchy,
                    hierarchyNode.Instance,
                    false,
                    false,
                    namespaceUris);

                if (root.InstanceState.ReleaseStatus == Export.ReleaseStatus.Released ||
                    root.InstanceState.Categories != null)
                {
                    root.InstanceState.Categories = null;
                    root.InstanceState.ReleaseStatus =
                        hierarchyNode.Instance.ReleaseStatus.ToNodeSetReleaseStatus();

                    if (!string.IsNullOrEmpty(root.Category))
                    {
                        root.InstanceState.Categories = root.Category.Split([',']);
                    }

                    if (root.PartNo != 0)
                    {
                        root.InstanceState.Specification = $"Part{root.PartNo}";
                    }
                }

                ClearModellingRules(hierarchyNode.Instance.State as BaseInstanceState);
            }
        }

        private BaseObjectTypeState CreateNodeState(
            ObjectTypeDesign root,
            NamespaceTable namespaceUris)
        {
            var state = new BaseObjectTypeState
            {
                Handle = root
            };

            if (root.BaseTypeNode != null)
            {
                state.SuperTypeId = ConstructNodeId(root.BaseTypeNode, namespaceUris);
            }
            else
            {
                state.SuperTypeId = default;
            }

            state.IsAbstract = root.IsAbstract;

            return state;
        }

        private BaseDataVariableTypeState CreateNodeState(
            VariableTypeDesign root,
            NamespaceTable namespaceUris)
        {
            var state = new BaseDataVariableTypeState
            {
                Handle = root
            };

            if (root.BaseTypeNode != null)
            {
                state.SuperTypeId = ConstructNodeId(
                    root.BaseTypeNode,
                    namespaceUris);
            }
            else
            {
                state.SuperTypeId = default;
            }

            VariableDesign mergedInstance = null;

            Hierarchy hierarchy = root.Hierarchy;

            if (hierarchy != null &&
                hierarchy.Nodes.TryGetValue(string.Empty, out HierarchyNode node))
            {
                mergedInstance = node.Instance as VariableDesign;
            }

            state.IsAbstract = root.IsAbstract;

            if (mergedInstance != null)
            {
                state.Value = mergedInstance.DecodedValue;
                state.DataType = ConstructNodeIdForDataType(
                    mergedInstance,
                    namespaceUris);
                state.ValueRank = ConstructValueRank(
                    mergedInstance.ValueRank,
                    mergedInstance.ArrayDimensions);
                state.ArrayDimensions = ConstructArrayDimensions(
                    mergedInstance.ValueRank,
                    mergedInstance.ArrayDimensions);
            }
            else
            {
                state.Value = root.DecodedValue;
                state.DataType = ConstructNodeIdForDataType(
                    root,
                    namespaceUris);
                state.ValueRank = ConstructValueRank(
                    root.ValueRank,
                    root.ArrayDimensions);
                state.ArrayDimensions = ConstructArrayDimensions(
                    root.ValueRank,
                    root.ArrayDimensions);
            }

            return state;
        }

        private ReferenceTypeState CreateNodeState(
            ReferenceTypeDesign root,
            NamespaceTable namespaceUris)
        {
            var state = new ReferenceTypeState
            {
                Handle = root
            };

            if (root.BaseTypeNode != null)
            {
                state.SuperTypeId = ConstructNodeId(
                    root.BaseTypeNode,
                    namespaceUris);
            }
            else
            {
                state.SuperTypeId = default;
            }

            state.IsAbstract = root.IsAbstract;
            state.Symmetric = root.Symmetric;

            if (state.Symmetric)
            {
                state.InverseName = Ua.LocalizedText.Null;
            }
            else
            {
                state.InverseName = new Ua.LocalizedText(
                    root.InverseName.Key,
                    string.Empty, root.
                    InverseName.Value);
            }

            return state;
        }

        private DataTypeState CreateNodeState(
            DataTypeDesign root,
            NamespaceTable namespaceUris)
        {
            var state = new DataTypeState
            {
                Handle = root
            };

            if (root.BaseTypeNode != null)
            {
                state.SuperTypeId = ConstructNodeId(root.BaseTypeNode, namespaceUris);
            }
            else
            {
                state.SuperTypeId = default;
            }

            state.IsAbstract = root.IsAbstract;
            state.Purpose =
                (Export.DataTypePurpose)(int)(root.Purpose == DataTypePurpose.Testing ?
                    DataTypePurpose.CodeGenerator :
                    root.Purpose);
            if (root.BasicDataType is BasicDataType.Enumeration or BasicDataType.UserDefined)
            {
                root.Fields ??= [];

                DataTypeDefinition definition = null;

                if (root.BasicDataType == BasicDataType.UserDefined && root.IsStructure)
                {
                    var sd = new StructureDefinition();

                    if (root.BaseTypeNode is DataTypeDesign baseType)
                    {
                        sd.BaseDataType = ConstructNodeId(baseType, namespaceUris);
                    }

                    sd.StructureType = StructureType.Structure;

                    if (root.IsUnion)
                    {
                        sd.StructureType = StructureType.Union;
                    }

                    foreach (Parameter field in root.Fields)
                    {
                        if (field.IsOptional)
                        {
                            sd.StructureType = StructureType.StructureWithOptionalFields;
                            break;
                        }

                        if (field.AllowSubTypes)
                        {
                            if (root.IsUnion)
                            {
                                sd.StructureType = StructureType.UnionWithSubtypedValues;
                                break;
                            }

                            sd.StructureType = StructureType.StructureWithSubtypedValues;
                            break;
                        }
                    }

                    sd.FirstExplicitFieldIndex = GetStructureDefinitionFields(
                        sd,
                        root,
                        namespaceUris);
                    definition = sd;
                }

                if (root.BasicDataType == BasicDataType.Enumeration && root.IsEnumeration)
                {
                    var ed = new EnumDefinition
                    {
                        IsOptionSet = root.IsOptionSet
                    };

                    var enumFields = new List<EnumField>();

                    if (root.Fields != null && root.Fields.Length > 0)
                    {
                        foreach (Parameter field in root.Fields)
                        {
                            EnumField enumField;

                            if (root.IsOptionSet)
                            {
                                long bit = 1;
                                int value = 0;

                                while (field.Identifier > 0 && bit <= long.MaxValue)
                                {
                                    if ((bit & (long)field.Identifier) != 0)
                                    {
                                        break;
                                    }

                                    bit <<= 1;
                                    value++;
                                }

                                enumField = new EnumField
                                {
                                    Name = field.Name,
                                    DisplayName = new Ua.LocalizedText(field.Name),
                                    Value = value
                                };
                            }
                            else
                            {
                                enumField = new EnumField
                                {
                                    Name = field.Name,
                                    DisplayName = new Ua.LocalizedText(field.Name),
                                    Value = (long)field.Identifier
                                };
                            }

                            if (field.Description != null &&
                                !field.Description.IsAutogenerated)
                            {
                                enumField.Description = new Ua.LocalizedText(
                                    field.Description.Value?.Trim());
                            }

                            enumFields.Add(enumField);
                        }

                        ed.Fields = enumFields.ToArray();
                    }

                    definition = ed;
                }

                state.DataTypeDefinition = new ExtensionObject(definition);
            }

            return state;
        }

        private int GetStructureDefinitionFields(
            StructureDefinition sd,
            DataTypeDesign dataType,
            NamespaceTable namespaceUris)
        {
            if (dataType == null || dataType.Fields == null)
            {
                return sd.Fields.Count;
            }

            if (dataType.BaseTypeNode is DataTypeDesign baseType)
            {
                GetStructureDefinitionFields(sd, baseType, namespaceUris);
            }

            int start = sd.Fields.Count;

            if (dataType.Fields != null && dataType.Fields.Length > 0)
            {
                // inherit optional fields flag if derived structure contains no
                // optional fields
                if (sd.StructureType == StructureType.Structure &&
                    dataType.Fields?.Any(f => f.IsOptional) == true)
                {
                    sd.StructureType = StructureType.StructureWithOptionalFields;
                }

                foreach (Parameter field in dataType.Fields)
                {
                    var structureField = new StructureField
                    {
                        Name = field.Name,
                        DataType = ConstructNodeIdForDataType(
                            field,
                            namespaceUris),
                        ValueRank = ConstructValueRank(
                            field.ValueRank,
                            field.ArrayDimensions),
                        ArrayDimensions = ConstructArrayDimensionsRW(
                            field.ValueRank,
                            field.ArrayDimensions)
                    };

                    if (sd.StructureType == StructureType.StructureWithOptionalFields)
                    {
                        structureField.IsOptional = field.IsOptional;
                    }
                    else if (sd.StructureType is
                        StructureType.StructureWithSubtypedValues or
                        StructureType.UnionWithSubtypedValues)
                    {
                        structureField.IsOptional = field.AllowSubTypes;
                    }

                    if (field.Description != null && !field.Description.IsAutogenerated)
                    {
                        structureField.Description =
                            new Ua.LocalizedText(field.Description.Value.Trim());
                    }

                    sd.Fields.Add(structureField);
                }
            }

            return start;
        }

        private BaseObjectState CreateNodeState(
            NodeState parent,
            ObjectDesign root,
            NamespaceTable namespaceUris)
        {
            var state = new BaseObjectState(parent)
            {
                Handle = root,

                TypeDefinitionId = ConstructNodeId(
                    root.TypeDefinitionNode,
                    namespaceUris),
                ReferenceTypeId = ConstructNodeId(
                    root.ReferenceType,
                    namespaceUris),
                ModellingRuleId = ConstructModellingRule(
                    root.ModellingRule),
                EventNotifier = ConstructEventNotifier(
                    root.SupportsEvents),
                Categories = null,
                ReleaseStatus = root.ReleaseStatus.ToNodeSetReleaseStatus(),
                DesignToolOnly = root.DesignToolOnly
            };

            if (!string.IsNullOrEmpty(root.Category))
            {
                state.Categories = root.Category.Split([',']);
            }

            if (root.PartNo != 0)
            {
                state.Specification = $"Part{root.PartNo}";
            }

            if (root.NumericIdSpecified)
            {
                state.NumericId = root.NumericId;
            }

            return state;
        }

        private static ViewState CreateNodeState(ViewDesign root)
        {
            var state = new ViewState
            {
                Handle = root,
                EventNotifier = ConstructEventNotifier(root.SupportsEvents),
                ContainsNoLoops = root.ContainsNoLoops,
                Categories = null,
                ReleaseStatus = root.ReleaseStatus.ToNodeSetReleaseStatus()
            };

            if (!string.IsNullOrEmpty(root.Category))
            {
                state.Categories = root.Category.Split([',']);
            }

            if (root.PartNo != 0)
            {
                state.Specification = $"Part{root.PartNo}";
            }

            return state;
        }

        private MethodState CreateNodeState(
            NodeState parent,
            MethodDesign root,
            NamespaceTable namespaceUris)
        {
            var state = new MethodState(parent)
            {
                Handle = root,

                ReferenceTypeId = ConstructNodeId(root.ReferenceType, namespaceUris),
                ModellingRuleId = ConstructModellingRule(root.ModellingRule)
            };
            state.Executable = state.UserExecutable = !root.NonExecutable;
            state.Categories = null;
            state.ReleaseStatus = root.ReleaseStatus.ToNodeSetReleaseStatus();
            state.MethodDeclarationId = ConstructNodeId(
                root.MethodDeclarationNode,
                namespaceUris);

            if (!string.IsNullOrEmpty(root.Category))
            {
                state.Categories = root.Category.Split([',']);
            }

            if (root.PartNo != 0)
            {
                state.Specification = $"Part{root.PartNo}";
            }

            if (root.NumericIdSpecified)
            {
                state.NumericId = root.NumericId;
            }

            return state;
        }

        private BaseVariableState CreateNodeState(
            NodeState parent,
            VariableDesign root,
            NamespaceTable namespaceUris)
        {
            BaseVariableState state;

            if (root is PropertyDesign)
            {
                state = new PropertyState(parent);
            }
            else
            {
                state = new BaseDataVariableState(parent);
            }

            state.Handle = root;
            state.TypeDefinitionId = ConstructNodeId(
                root.TypeDefinitionNode,
                namespaceUris);
            state.ReferenceTypeId = ConstructNodeId(
                root.ReferenceType,
                namespaceUris);
            state.ModellingRuleId = ConstructModellingRule(
                root.ModellingRule);
            state.Categories = null;
            state.ReleaseStatus = root.ReleaseStatus.ToNodeSetReleaseStatus();
            state.DesignToolOnly = root.DesignToolOnly;
            state.WriteMask = root.WriteAccess != 0 ?
                (AttributeWriteMask)root.WriteAccess :
                AttributeWriteMask.None;

            if (!string.IsNullOrEmpty(root.Category))
            {
                state.Categories = root.Category.Split([',']);
            }

            if (root.PartNo != 0)
            {
                state.Specification = $"Part{root.PartNo}";
            }

            if (root.NumericIdSpecified)
            {
                state.NumericId = root.NumericId;
            }

            state.Value = root.DecodedValue;
            state.DataType = ConstructNodeIdForDataType(root, namespaceUris);
            state.ValueRank = ConstructValueRank(
                root.ValueRank,
                root.ArrayDimensions);
            state.ArrayDimensions = ConstructArrayDimensions(
                root.ValueRank,
                root.ArrayDimensions);
            state.AccessLevel = ConstructAccessLevel(
                root.AccessLevel);
            state.UserAccessLevel = state.AccessLevel;
            state.MinimumSamplingInterval = root.MinimumSamplingInterval;
            state.Historizing = root.Historizing;

            if (root.DecodedValue is ExtensionObject extensionObject)
            {
                root.DecodedValue = SetTypeId(extensionObject, namespaceUris);
            }

            if (root.DecodedValue is ExtensionObject[] extensionObjects)
            {
                root.DecodedValue = extensionObjects
                    .Select(extensionObject => SetTypeId(
                        extensionObject,
                        namespaceUris))
                    .ToArray();
            }

            if (root.DecodedValue is IList<Argument> argument)
            {
                for (int ii = 0; ii < argument.Count; ii++)
                {
                    string namespaceUri = Namespaces.OpcUa;

                    if (!argument[ii].DataType.TryGetIdentifier(out string name))
                    {
                        continue;
                    }

                    int index = name.LastIndexOf(':');

                    if (index != -1)
                    {
                        namespaceUri = name[..index];
                        name = name[(index + 1)..];
                    }

                    argument[ii].DataType = ConstructNodeId(
                        new XmlQualifiedName(name, namespaceUri),
                        namespaceUris);
                }
            }

            return state;
        }

        private NodeState CreateNodeState(
            NodeState parent,
            string basePath,
            Hierarchy hierarchy,
            NodeDesign root,
            bool explicitOnly,
            bool isTypeDefinition,
            NamespaceTable namespaceUris)
        {
            m_logger.LogDebug("Creating NodeState: {Name}", root.SymbolicId.Name);

            NodeState state = null;

            switch (root)
            {
                case ObjectTypeDesign objectTypeDesign:
                    state = CreateNodeState(objectTypeDesign, namespaceUris);
                    break;
                case VariableTypeDesign variableTypeDesign:
                    state = CreateNodeState(variableTypeDesign, namespaceUris);
                    break;
                case ReferenceTypeDesign referenceTypeDesign:
                    state = CreateNodeState(referenceTypeDesign, namespaceUris);
                    break;
                case ObjectDesign objectDesign:
                    state = CreateNodeState(parent, objectDesign, namespaceUris);
                    break;
                case VariableDesign variableDesign:
                    state = CreateNodeState(parent, variableDesign, namespaceUris);
                    break;
                case DataTypeDesign dataTypeDesign:
                    state = CreateNodeState(dataTypeDesign, namespaceUris);
                    break;
                case MethodDesign methodDesign:
                    state = CreateNodeState(parent, methodDesign, namespaceUris);
                    break;
                case ViewDesign viewDesign:
                    state = CreateNodeState(viewDesign);
                    break;
            }

            state.SymbolicName = root.SymbolicName.Name;
            state.NodeId = ConstructNodeId(root, namespaceUris);
            state.BrowseName = new QualifiedName(
                root.BrowseName,
                (ushort)namespaceUris.GetIndex(root.SymbolicName.Namespace));
            state.DisplayName = new Ua.LocalizedText(
                root.DisplayName.Key,
                string.Empty,
                root.DisplayName.Value?.Trim());

            if (root.Description != null && !root.Description.IsAutogenerated)
            {
                state.Description = new Ua.LocalizedText(
                    root.Description.Key,
                    string.Empty,
                    root.Description.Value?.Trim());
            }

            state.WriteMask = AttributeWriteMask.None;
            state.UserWriteMask = AttributeWriteMask.None;
            state.AccessRestrictions = ConstructAccessRestrictions(
                root.AccessRestrictions,
                root.AccessRestrictionsSpecified);
            state.RolePermissions = ConstructRolePermissions(
                root.RolePermissions,
                namespaceUris);
            state.Extensions = root.Extensions;

            if (state is MethodState method)
            {
                var design = (MethodDesign)root;

                if (design.MethodDeclarationNode != null)
                {
                    method.MethodDeclarationId = ConstructNodeId(
                        design.MethodDeclarationNode,
                        namespaceUris);
                }
            }

            if (hierarchy == null)
            {
                return state;
            }

            for (int ii = 0; ii < hierarchy.References.Count; ii++)
            {
                HierarchyReference reference = hierarchy.References[ii];

                if (reference.SourcePath != basePath && reference.TargetPath != basePath)
                {
                    continue;
                }

                NodeId referenceTypeId = ConstructNodeId(reference.ReferenceType, namespaceUris);
                bool isInverse = reference.IsInverse;

                if (reference.TargetId != null)
                {
                    if (!isTypeDefinition &&
                        m_modelDesign.TryFindNode(
                            reference.TargetId,
                            root.SymbolicId.Name,
                            "TargetId",
                            out InstanceDesign instance) &&
                        (instance.ModellingRule == ModellingRule.MandatoryPlaceholder ||
                            instance.ModellingRule == ModellingRule.OptionalPlaceholder))
                    {
                        continue;
                    }

                    NodeId targetId = ConstructNodeId(reference.TargetId, namespaceUris);

                    if (!state.ReferenceExists(referenceTypeId, isInverse, targetId))
                    {
                        state.AddReference(referenceTypeId, isInverse, targetId);
                    }

                    continue;
                }

                if (reference.TargetPath != null && reference.TargetPath.Length == 0 && parent != null)
                {
                    if (!state.ReferenceExists(referenceTypeId, isInverse, parent.NodeId))
                    {
                        state.AddReference(referenceTypeId, isInverse, parent.NodeId);
                    }

                    continue;
                }

                if (reference.SourcePath == basePath)
                {
                    if (!hierarchy.Nodes.TryGetValue(reference.TargetPath, out HierarchyNode target))
                    {
                        continue;
                    }

                    if (!target.ExplicitlyDefined && isTypeDefinition)
                    {
                        continue;
                    }

                    NodeId targetId = ConstructNodeId(target.Instance, namespaceUris);

                    if (!target.Instance.NumericIdSpecified || target.Instance.NumericId == 0)
                    {
                        target.Instance.StringId = target.Instance.SymbolicId.Name;
                        targetId = ConstructNodeId(target.Instance, namespaceUris);
                    }

                    if (!state.ReferenceExists(referenceTypeId, isInverse, targetId))
                    {
                        state.AddReference(referenceTypeId, isInverse, targetId);
                    }

                    continue;
                }

                if (!hierarchy.Nodes.TryGetValue(reference.SourcePath, out HierarchyNode source))
                {
                    continue;
                }

                if (!source.ExplicitlyDefined && isTypeDefinition)
                {
                    continue;
                }

                NodeId sourceId = ConstructNodeId(source.Instance, namespaceUris);

                if (!source.Instance.NumericIdSpecified || source.Instance.NumericId == 0)
                {
                    source.Instance.StringId = source.Instance.SymbolicId.Name;
                    sourceId = ConstructNodeId(source.Instance, namespaceUris);
                }

                if (!state.ReferenceExists(referenceTypeId, !isInverse, sourceId))
                {
                    state.AddReference(referenceTypeId, !isInverse, sourceId);
                }
            }

            for (int ii = 0; ii < hierarchy.NodeList.Count; ii++)
            {
                HierarchyNode current = hierarchy.NodeList[ii];

                if (explicitOnly && !current.ExplicitlyDefined)
                {
                    continue;
                }

                string childPath = current.RelativePath;

                // only looking for nodes in the current tree.
                if (!childPath.StartsWith(basePath, StringComparison.Ordinal))
                {
                    continue;
                }

                // ignore reference to the current base node.
                if (childPath == basePath)
                {
                    continue;
                }

                // relative should always end in the name of the current instance.
                if (!childPath.EndsWith(current.Instance.SymbolicName.Name, StringComparison.Ordinal))
                {
                    continue;
                }

                // get the parent path.
                if (childPath.Length <= current.Instance.SymbolicName.Name.Length)
                {
                    if (!string.IsNullOrEmpty(basePath))
                    {
                        continue;
                    }
                }
                else
                {
                    int idx = childPath.Length - current.Instance.SymbolicName.Name.Length - 1;
                    string parentPath = current.RelativePath[..idx];

                    if (parentPath != basePath)
                    {
                        continue;
                    }
                }

                if (!string.IsNullOrEmpty(basePath))
                {
                    childPath = childPath[(basePath.Length + 1)..];
                    childPath = CoreUtils.Format(
                        "{0}{1}{2}",
                        basePath,
                        NodeDesign.PathChar,
                        childPath);
                }

                if (!explicitOnly && current.Instance is InstanceDesign instance)
                {
                    if (!isTypeDefinition &&
                        !current.ExplicitlyDefined &&
                        instance.ModellingRule != ModellingRule.Mandatory &&
                        instance.ModellingRule != ModellingRule.Optional)
                    {
                        continue;
                    }

                    if (!current.ExplicitlyDefined &&
                        instance.ModellingRule != ModellingRule.Mandatory &&
                        instance.ModellingRule != ModellingRule.None &&
                        instance.ModellingRule != ModellingRule.ExposesItsArray &&
                        instance.ModellingRule != ModellingRule.OptionalPlaceholder &&
                        instance.ModellingRule != ModellingRule.MandatoryPlaceholder)
                    {
                        continue;
                    }
                }

                if (isTypeDefinition &&
                    !current.ExplicitlyDefined &&
                    current.Inherited &&
                    current.AdHocInstance)
                {
                    // this assumes that ad-hoc instances are not more than one level deep.
                    // i.e. a type defines folder and adds a few instances but does not
                    // defined subfolders.
                    // need a better way to identify when to suppress inherited adhoc instances.
                    if (!basePath.Contains(NodeDesign.PathChar, StringComparison.Ordinal))
                    {
                        continue;
                    }
                }

                current.Instance.State = CreateNodeState(
                    state,
                    childPath,
                    hierarchy,
                    current.Instance,
                    false,
                    isTypeDefinition,
                    namespaceUris);

                if (current.Instance.State is BaseInstanceState child)
                {
                    if (root is DataTypeDesign or ViewDesign or ReferenceTypeDesign)
                    {
                        child.ModellingRuleId = default;
                        state.AddChild(child);
                    }
                    else if (explicitOnly)
                    {
                        if (current.ExplicitlyDefined)
                        {
                            state.AddChild(child);
                        }
                    }
                    else if (isTypeDefinition)
                    {
                        if (child.ModellingRuleId == ObjectIds.ModellingRule_Mandatory)
                        {
                            state.AddChild(child);
                        }
                        else if (current.ExplicitlyDefined &&
                            child.ModellingRuleId == ObjectIds.ModellingRule_Optional)
                        {
                            state.AddChild(child);
                        }
                        else if (current.ExplicitlyDefined &&
                            (child.ModellingRuleId == ObjectIds.ModellingRule_ExposesItsArray ||
                                child.ModellingRuleId == ObjectIds.ModellingRule_OptionalPlaceholder ||
                                child.ModellingRuleId == ObjectIds.ModellingRule_MandatoryPlaceholder))
                        {
                            state.AddChild(child);
                        }
                        else if (current.StaticValue && !current.Inherited)
                        {
                            state.AddChild(child);
                        }
                    }
                    else if (child.ModellingRuleId == ObjectIds.ModellingRule_Mandatory)
                    {
                        state.AddChild(child);
                    }
                    else if (current.ExplicitlyDefined)
                    {
                        state.AddChild(child);
                    }
                }
            }

            return state;
        }

        private ExtensionObject SetTypeId(ExtensionObject e, NamespaceTable namespaceUris)
        {
            XmlQualifiedName qname = null;

            if (e.Body is XmlElement element)
            {
                // determine the data type of the element.
                qname = new XmlQualifiedName(element.LocalName, element.NamespaceURI);

                string prefix = element.GetPrefixOfNamespace(Namespaces.XmlSchemaInstance);
                string xsitype = element.GetAttribute(prefix + ":type");

                if (!string.IsNullOrEmpty(xsitype))
                {
                    int index = xsitype.IndexOf(':', StringComparison.Ordinal);

                    if (index > 0)
                    {
                        qname = new XmlQualifiedName(
                            xsitype[(index + 1)..],
                            element.GetNamespaceOfPrefix(xsitype[..index]));
                    }
                    else
                    {
                        qname = new XmlQualifiedName(
                            xsitype[(index + 1)..],
                            element.NamespaceURI);
                    }
                }
            }
            else if (e.Body is IEncodeable encodeable)
            {
                qname = TypeInfo.GetXmlName(encodeable.GetType());
            }

            if (m_modelDesign.TryFindNode(
                qname,
                qname.Name,
                "DataType",
                out DataTypeDesign dataTypeNode))
            {
                uint numericId = dataTypeNode.NumericId;
                int namespaceIndex = namespaceUris.GetIndex(qname.Namespace);

                // look up XML encoding id.
                if (dataTypeNode.HasEncodings)
                {
                    foreach (EncodingDesign encoding in dataTypeNode.Encodings)
                    {
                        ObjectDesign encodingNode = m_modelDesign.FindNode<ObjectDesign>(
                            encoding.SymbolicId,
                            encoding.SymbolicId.Name,
                            "Encoding");

                        if (encodingNode != null &&
                            encodingNode.SymbolicName.Name == "DefaultXml")
                        {
                            numericId = encodingNode.NumericId;
                            namespaceIndex = namespaceUris.GetIndex(
                                encodingNode.SymbolicId.Namespace);
                            break;
                        }
                    }
                }

                if (namespaceIndex >= 0)
                {
                    return e.WithTypeId(new NodeId(numericId, (ushort)namespaceIndex));
                }
            }
            return e;
        }

        private static AccessRestrictionType? ConstructAccessRestrictions(
            AccessRestrictions restrictions,
            bool enabled)
        {
            AccessRestrictionType output = AccessRestrictionType.None;

            if (!enabled)
            {
                return null;
            }

            switch (restrictions)
            {
                case AccessRestrictions.SigningRequired:
                    output |= AccessRestrictionType.SigningRequired;
                    break;
                case AccessRestrictions.EncryptionRequired:
                    output |= AccessRestrictionType.EncryptionRequired;
                    break;
                case AccessRestrictions.SessionRequired:
                    output |= AccessRestrictionType.SessionRequired;
                    break;
                case AccessRestrictions.SessionWithSigningRequired:
                    output |=
                        AccessRestrictionType.SigningRequired |
                        AccessRestrictionType.SessionRequired;
                    break;
                case AccessRestrictions.SessionWithEncryptionRequired:
                    output |=
                        AccessRestrictionType.EncryptionRequired |
                        AccessRestrictionType.SessionRequired;
                    break;
                case AccessRestrictions.SessionAndApplyToBrowseRequired:
                    output |=
                        AccessRestrictionType.SessionRequired |
                        AccessRestrictionType.ApplyRestrictionsToBrowse;
                    break;
                case AccessRestrictions.SessionWithSigningAndApplyToBrowseRequired:
                    output |=
                        AccessRestrictionType.SigningRequired |
                        AccessRestrictionType.SessionRequired |
                        AccessRestrictionType.ApplyRestrictionsToBrowse;
                    break;
                case AccessRestrictions.SessionWithEncryptionAndApplyToBrowseRequired:
                    output |=
                        AccessRestrictionType.EncryptionRequired |
                        AccessRestrictionType.SessionRequired |
                        AccessRestrictionType.ApplyRestrictionsToBrowse;
                    break;
                case AccessRestrictions.SigningAndApplyToBrowseRequired:
                    output |=
                        AccessRestrictionType.SigningRequired |
                        AccessRestrictionType.ApplyRestrictionsToBrowse;
                    break;
                case AccessRestrictions.EncryptionAndApplyToBrowseRequired:
                    output |=
                        AccessRestrictionType.EncryptionRequired |
                        AccessRestrictionType.ApplyRestrictionsToBrowse;
                    break;
            }

            return output > AccessRestrictionType.None ? output : null;
        }

        private RolePermissionTypeCollection ConstructRolePermissions(
            RolePermissionSet input,
            NamespaceTable namespaceUris)
        {
            if (input == null)
            {
                return null;
            }

            if (input.RolePermission != null)
            {
                RolePermissionTypeCollection output = [];

                foreach (RolePermission ii in input.RolePermission)
                {
                    var role = new RolePermissionType();

                    ObjectDesign roleNode = m_modelDesign.FindNode<ObjectDesign>(
                        ii.Role,
                        ii.Role.Name,
                        "RoleType");
                    role.RoleId = ConstructNodeId(roleNode, namespaceUris);
                    role.Permissions = (uint)ImportRolePermission(ii.Permission);

                    output.Add(role);
                }

                return output;
            }

            return null;

            static PermissionType ImportRolePermission(Permissions[] input)
            {
                PermissionType output = PermissionType.None;

                if (input != null && input.Length > 0)
                {
                    foreach (Permissions jj in input)
                    {
                        switch (jj)
                        {
                            case Permissions.Browse:
                                output |= PermissionType.Browse;
                                break;
                            case Permissions.ReadRolePermissions:
                                output |= PermissionType.ReadRolePermissions;
                                break;
                            case Permissions.WriteAttribute:
                                output |= PermissionType.WriteAttribute;
                                break;
                            case Permissions.WriteRolePermissions:
                                output |= PermissionType.WriteRolePermissions;
                                break;
                            case Permissions.WriteHistorizing:
                                output |= PermissionType.WriteHistorizing;
                                break;
                            case Permissions.Read:
                                output |= PermissionType.Read;
                                break;
                            case Permissions.Write:
                                output |= PermissionType.Write;
                                break;
                            case Permissions.ReadHistory:
                                output |= PermissionType.ReadHistory;
                                break;
                            case Permissions.InsertHistory:
                                output |= PermissionType.InsertHistory;
                                break;
                            case Permissions.ModifyHistory:
                                output |= PermissionType.ModifyHistory;
                                break;
                            case Permissions.DeleteHistory:
                                output |= PermissionType.DeleteHistory;
                                break;
                            case Permissions.ReceiveEvents:
                                output |= PermissionType.ReceiveEvents;
                                break;
                            case Permissions.Call:
                                output |= PermissionType.Call;
                                break;
                            case Permissions.AddReference:
                                output |= PermissionType.AddReference;
                                break;
                            case Permissions.RemoveReference:
                                output |= PermissionType.RemoveReference;
                                break;
                            case Permissions.DeleteNode:
                                output |= PermissionType.DeleteNode;
                                break;
                            case Permissions.AddNode:
                                output |= PermissionType.AddNode;
                                break;
                            case Permissions.AllRead:
                                output |=
                                    PermissionType.Browse |
                                    PermissionType.Read |
                                    PermissionType.ReadHistory |
                                    PermissionType.ReceiveEvents |
                                    PermissionType.ReadRolePermissions;
                                break;
                            case Permissions.All:
                                output |=
                                    PermissionType.Browse |
                                    PermissionType.ReadRolePermissions |
                                    PermissionType.WriteAttribute |
                                    PermissionType.WriteRolePermissions |
                                    PermissionType.WriteHistorizing |
                                    PermissionType.Read |
                                    PermissionType.Write |
                                    PermissionType.ReadHistory |
                                    PermissionType.InsertHistory |
                                    PermissionType.ModifyHistory |
                                    PermissionType.DeleteHistory |
                                    PermissionType.ReceiveEvents |
                                    PermissionType.Call |
                                    PermissionType.AddReference |
                                    PermissionType.RemoveReference |
                                    PermissionType.DeleteNode |
                                    PermissionType.AddNode;
                                break;
                        }
                    }
                }

                return output;
            }
        }

        /// <summary>
        /// Maps the event notifier flag onto a byte.
        /// </summary>
        private static byte ConstructEventNotifier(bool supportsEvents)
        {
            if (supportsEvents)
            {
                return EventNotifiers.SubscribeToEvents;
            }

            return EventNotifiers.None;
        }

        /// <summary>
        /// Maps the access level enumeration onto a byte.
        /// </summary>
        private static byte ConstructAccessLevel(AccessLevel accessLevel)
        {
            switch (accessLevel)
            {
                case AccessLevel.Read:
                    return AccessLevels.CurrentRead;
                case AccessLevel.Write:
                    return AccessLevels.CurrentWrite;
                case AccessLevel.ReadWrite:
                    return AccessLevels.CurrentReadOrWrite;
                case AccessLevel.HistoryRead:
                    return AccessLevels.HistoryRead;
                case AccessLevel.HistoryWrite:
                    return AccessLevels.HistoryWrite;
                case AccessLevel.HistoryReadWrite:
                    return AccessLevels.HistoryReadOrWrite;
            }

            return AccessLevels.None;
        }

        /// <summary>
        /// Maps the modelling rule enumeration onto a string.
        /// </summary>
        private static NodeId ConstructModellingRule(ModellingRule modellingRule)
        {
            switch (modellingRule)
            {
                case ModellingRule.Mandatory:
                    return Objects.ModellingRule_Mandatory;
                case ModellingRule.Optional:
                    return Objects.ModellingRule_Optional;
                case ModellingRule.MandatoryPlaceholder:
                    return Objects.ModellingRule_MandatoryPlaceholder;
                case ModellingRule.OptionalPlaceholder:
                    return Objects.ModellingRule_OptionalPlaceholder;
                case ModellingRule.ExposesItsArray:
                    return Objects.ModellingRule_ExposesItsArray;
            }

            return default;
        }

        /// <summary>
        /// Maps the value rank enumeration onto a integer.
        /// </summary>
        private static int ConstructValueRank(ValueRank valueRank, string arrayDimensions)
        {
            switch (valueRank)
            {
                case ValueRank.Array:
                    return ValueRanks.OneDimension;
                case ValueRank.Scalar:
                    return ValueRanks.Scalar;
                case ValueRank.Any:
                case ValueRank.ScalarOrArray:
                    return ValueRanks.Any;
                case ValueRank.ScalarOrOneDimension:
                    return ValueRanks.ScalarOrOneDimension;
                case ValueRank.OneOrMoreDimensions:
                    if (string.IsNullOrEmpty(arrayDimensions))
                    {
                        return ValueRanks.OneOrMoreDimensions;
                    }

                    string[] dimensions = arrayDimensions.Split([','], StringSplitOptions.RemoveEmptyEntries);

                    return dimensions.Length;
            }

            return ValueRanks.Any;
        }

        /// <summary>
        /// Maps the array dimensions onto a constant declaration..
        /// </summary>
        private static UInt32Collection ConstructArrayDimensionsRW(ValueRank valueRank, string arrayDimensions)
        {
            if (valueRank is < 0 and not ValueRank.OneOrMoreDimensions)
            {
                return null;
            }

            if (string.IsNullOrEmpty(arrayDimensions))
            {
                if (valueRank == ValueRank.Array)
                {
                    return [.. new uint[1]];
                }

                return null;
            }

            string[] tokens = arrayDimensions.Split([','], StringSplitOptions.RemoveEmptyEntries);

            if (tokens == null || tokens.Length < 1)
            {
                return null;
            }

            var dimensions = new UInt32Collection();

            for (int ii = 0; ii < tokens.Length; ii++)
            {
                try
                {
                    dimensions.Add(Convert.ToUInt32(tokens[ii], CultureInfo.InvariantCulture));
                }
                catch
                {
                    dimensions.Add(0);
                }
            }

            return dimensions;
        }

        /// <summary>
        /// Maps the array dimensions onto a constant declaration..
        /// </summary>
        private static ReadOnlyList<uint> ConstructArrayDimensions(ValueRank valueRank, string arrayDimensions)
        {
            UInt32Collection dimensions = ConstructArrayDimensionsRW(valueRank, arrayDimensions);

            if (dimensions != null)
            {
                return new ReadOnlyList<uint>(dimensions);
            }

            return null;
        }

        private NodeId ConstructNodeId(NodeDesign node, NamespaceTable namespaceUris)
        {
            int index;

            if (node == null || node.StringId != null)
            {
                index = namespaceUris.GetIndex(node.SymbolicId.Namespace);
                return new NodeId(node.StringId, (ushort)index);
            }

            if (node.NumericId == 0)
            {
                for (NodeDesign parent = node.Parent; parent != null; parent = parent.Parent)
                {
                    if (parent.Hierarchy != null)
                    {
                        string browsePath = node.SymbolicId.Name;

                        if (browsePath.StartsWith(parent.SymbolicId.Name, StringComparison.Ordinal) &&
                            browsePath[parent.SymbolicId.Name.Length] == NodeDesign.PathChar)
                        {
                            browsePath = browsePath[(parent.SymbolicId.Name.Length + 1)..];
                        }

                        if (parent.Hierarchy.Nodes.TryGetValue(browsePath, out HierarchyNode instance))
                        {
                            node = instance.Instance;
                            break;
                        }
                    }
                }
            }

            index = namespaceUris.GetIndex(node.SymbolicId.Namespace);
            if (node.NumericId == 0)
            {
                // TODO: Handle this.
                m_logger.LogInformation("Node with SymbolicId {Name} has no NumericId or StringId.", node.SymbolicId.Name);
                return new NodeId(node.SymbolicId.Name, (ushort)index);
            }
            return new NodeId(node.NumericId, (ushort)index);
        }

        private NodeId ConstructNodeId(XmlQualifiedName nodeId, NamespaceTable namespaceUris)
        {
            if (nodeId == null)
            {
                return NodeId.Null;
            }

            NodeDesign node = m_modelDesign.FindNode(nodeId, nodeId.Name, "<NodeId>");
            if (node == null)
            {
                return NodeId.Null;
            }

            return ConstructNodeId(node, namespaceUris);
        }

        /// <summary>
        /// Removes the modelling rules for instances.
        /// </summary>
        private void ClearModellingRules(BaseInstanceState instanceState)
        {
            if (instanceState == null)
            {
                return;
            }

            instanceState.ModellingRuleId = default;

            var design = instanceState.Handle as NodeDesign;

            if (instanceState.RolePermissions == null ||
                instanceState.RolePermissions.Count == 0)
            {
                instanceState.RolePermissions = ConstructRolePermissions(
                    design.DefaultRolePermissions,
                    m_modelDesign.NamespaceUris);
            }

            instanceState.AccessRestrictions ??= ConstructAccessRestrictions(
                design.DefaultAccessRestrictions,
                design.DefaultAccessRestrictionsSpecified);

            var children = new List<BaseInstanceState>();
            instanceState.GetChildren(m_context, children);

            for (int ii = 0; ii < children.Count; ii++)
            {
                ClearModellingRules(children[ii]);
            }
        }

        private NodeId ConstructNodeIdForDataType(
            VariableTypeDesign type,
            NamespaceTable namespaceUris)
        {
            if (!m_modelDesign.UseAllowSubtypes)
            {
                DataTypeDesign dataType = m_modelDesign.FindNode<DataTypeDesign>(
                    type.DataType,
                    type.SymbolicId.Name,
                    "DataType");
                return ConstructNodeId(dataType, namespaceUris);
            }

            return ConstructNodeId(type.DataTypeNode, namespaceUris);
        }

        private NodeId ConstructNodeIdForDataType(
            Parameter field,
            NamespaceTable namespaceUris)
        {
            if (!m_modelDesign.UseAllowSubtypes)
            {
                DataTypeDesign dataType = m_modelDesign.FindNode<DataTypeDesign>(
                    field.DataType,
                    field.Name,
                    "DataType");
                return ConstructNodeId(dataType, namespaceUris);
            }

            return ConstructNodeId(field.DataTypeNode, namespaceUris);
        }

        private NodeId ConstructNodeIdForDataType(
            VariableDesign instance,
            NamespaceTable namespaceUris)
        {
            if (!m_modelDesign.UseAllowSubtypes)
            {
                DataTypeDesign dataType = m_modelDesign.FindNode<DataTypeDesign>(
                    instance.DataType,
                    instance.SymbolicId.Name,
                    "DataType");
                return ConstructNodeId(dataType, namespaceUris);
            }

            return ConstructNodeId(instance.DataTypeNode, namespaceUris);
        }

        private readonly ILogger m_logger;
        private readonly IModelDesign m_modelDesign;
        private readonly SystemContext m_context;
    }
}
