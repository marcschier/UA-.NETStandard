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
using System.IO;
using System.Linq;
using System.Xml;
using Microsoft.Extensions.Logging;
using Opc.Ua.Export;
using Opc.Ua.Schema.Model;
using Opc.Ua.Types;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Generates the script that instantiates the address space node states
    /// and optionally embeds the corresponding nodeset2.xml as resource.
    /// TODO: Right now we use serialization to instantiate, but change this
    /// to direct code generation.
    /// </summary>
    internal sealed class NodesetGenerator : IGenerator
    {
        /// <summary>
        /// Creates the nodeset generator
        /// </summary>
        public NodesetGenerator(
            GeneratorContext context,
            bool useXmlInitializers = false,
            bool embedNodeset = false)
        {
            m_context = context ?? throw new ArgumentNullException(nameof(context));
            m_useXmlInitializers = useXmlInitializers;
            m_embedNodeset = embedNodeset;
            m_logger = m_context.Telemetry.CreateLogger<NodesetGenerator>();
        }

        /// <inheritdoc/>
        public void Emit()
        {
            string nsPrefix = m_context.Validator.Dictionary.TargetNamespaceInfo.Prefix;
            var context = new SystemContext(m_context.Telemetry)
            {
                NamespaceUris = m_context.Validator.Dictionary.NamespaceUris,
                ServerUris = new StringTable()
            };

            // collect the nodes to write.
            NodeStateCollection nodeStateCollection = [];
            NodeStateCollection nodeStateCollectionWithServices = [];
            Dictionary<uint, NodeStateCollection> subsets = [];

            foreach (NodeDesign node in m_context.Validator.Dictionary.Items)
            {
                if (m_context.Validator.IsExcluded(node))
                {
                    continue;
                }

                bool isInAddressSpace =
                    !node.NotInAddressSpace;

                if (node is InstanceDesign instanceDesign &&
                    instanceDesign.TypeDefinition != null &&
                    instanceDesign.TypeDefinition.Name == "DataTypeEncodingType")
                {
                    isInAddressSpace =
                        instanceDesign.Parent == null ||
                        !instanceDesign.Parent.NotInAddressSpace;
                }

                if (node is MethodDesign methodDesign &&
                    methodDesign.SymbolicName.Name.EndsWith("MethodType", StringComparison.Ordinal))
                {
                    continue;
                }

                NodeState state = node.State;
                if (state != null)
                {
                    if (node.Purpose == Schema.Model.DataTypePurpose.Testing)
                    {
                        continue;
                    }

                    nodeStateCollectionWithServices.Add(state);

                    if (isInAddressSpace)
                    {
                        nodeStateCollection.Add(state);
                    }

                    List<BaseInstanceState> children = [];
                    state.GetChildren(context, children);

                    foreach (BaseInstanceState child in children)
                    {
                        if (IsExcluded(child))
                        {
                            state.RemoveChild(child);
                        }
                    }

                    RemoveChildrenWithNoNodeId(context, state);

                    if (node.PartNo != 0)
                    {
                        if (!subsets.TryGetValue(
                            node.PartNo,
                            out NodeStateCollection subset))
                        {
                            subset = [];
                            subsets[node.PartNo] = subset;
                        }

                        subset.Add(state);
                    }

                    if (state is BaseVariableState variable &&
                        variable.TypeDefinitionId == VariableTypeIds.DataTypeDictionaryType)
                    {
                        List<IReference> references = [];
                        variable.GetReferences(
                            context,
                            references,
                            ReferenceTypeIds.HasComponent,
                            true);

                        string file = null;

                        if (references.Count > 0 &&
                            references[0].TargetId == ObjectIds.XmlSchema_TypeSystem)
                        {
                            file = Path.Combine(
                                m_context.OutputFolder,
                                CoreUtils.Format("{0}.Types.xsd", nsPrefix));
                        }

                        if (references.Count > 0 &&
                            references[0].TargetId == ObjectIds.OPCBinarySchema_TypeSystem)
                        {
                            file = Path.Combine(
                                m_context.OutputFolder,
                                CoreUtils.Format("{0}.Types.bsd", nsPrefix));
                        }

                        if (file != null)
                        {
                            try
                            {
                                if (m_context.FileSystem.Exists(file))
                                {
                                    using Stream stream = m_context.FileSystem.OpenRead(file);
                                    using var ms = new MemoryStream();
                                    stream.CopyTo(ms);
                                    variable.Value = ms.ToArray();
                                }
                                else
                                {
                                    // TODO: Should throw as it should exist for type system to work
                                    m_logger.LogWarning(
                                        "Missing type system file: {File} for variable {Variable}",
                                        file,
                                        variable);
                                    variable.Value = null;
                                }
                            }
                            catch
                            {
                                variable.Value = null;
                            }
                        }
                    }
                }
            }

            string documentationFile = Path.Combine(
                m_context.OutputFolder,
                CoreUtils.Format("{0}.NodeSet2.documentation.csv", nsPrefix));
            if (!m_context.FileSystem.Exists(documentationFile))
            {
                documentationFile = Path.Combine(
                    m_context.OutputFolder,
                    CoreUtils.Format("{0}.NodeSet2.Services.documentation.csv", nsPrefix));
            }

            if (m_context.FileSystem.Exists(documentationFile))
            {
                Dictionary<NodeId, NodeState> index = [];

                ushort namespaceIndex = 0;

                foreach (NodeState ii in nodeStateCollectionWithServices)
                {
                    index[ii.NodeId] = ii;
                    namespaceIndex = CollectNodes(context, index, ii);
                }

                var reader = new NodeDocumentationReader(m_context.FileSystem);
                foreach (NodeDocumentationRow row in reader.Load(documentationFile))
                {
                    var nodeId = new NodeId(row.Id, namespaceIndex);

                    if (index.TryGetValue(nodeId, out NodeState target))
                    {
                        target.NodeSetDocumentation =
                            !string.IsNullOrEmpty(row.Link) ? row.Link : null;
                        target.Categories = [.. row.ConformanceUnits];
                    }
                }
            }

            // save as nodeset.
            string originalFile = Path.Combine(
                m_context.OutputFolder,
                CoreUtils.Format("{0}.NodeSet2.xml", nsPrefix));
            if (m_context.Validator.Dictionary.TargetNamespace == Namespaces.OpcUa)
            {
                originalFile = CoreUtils.Format("{0}{1}{2}.NodeSet2.Services.xml",
                    m_context.OutputFolder,
                    Path.DirectorySeparatorChar,
                    nsPrefix);
            }

            // load existing file from xml - this is used if we generates modeldesign from nodeset.
            if (m_context.FileSystem.Exists(originalFile))
            {
                try
                {
                    NodeStateCollection existingNodeStateCollection = null;

                    using (Stream istrm = m_context.FileSystem.OpenRead(originalFile))
                    {
                        var nodeSet = UANodeSet.Read(istrm);
                        existingNodeStateCollection = [];
                        nodeSet.Import(context, existingNodeStateCollection);
                    }

                    Dictionary<NodeId, NodeState> map = [];
                    IndexDocumentation(context, existingNodeStateCollection, map);

                    UpdateDocumentation(context, map, nodeStateCollection);
                    if (m_context.Validator.Dictionary.TargetNamespace == Namespaces.OpcUa)
                    {
                        UpdateDocumentation(context, map, nodeStateCollectionWithServices);
                    }
                }
                catch
                {
                    // ignore any unparseable file.
                }
            }

            if (m_embedNodeset)
            {
                // Generate nodeset2.xml files as source code (.g.cs)
                EmbedNodeSet2Xml(context, nodeStateCollection, nodeStateCollectionWithServices);
            }

            // Embed predefined nodes and add helpers as source code (.g.cs)
            EmbedPredefinedNodes(context, nodeStateCollection);
            GenerateHelpers();
        }

        private void EmbedNodeSet2Xml(
            SystemContext context,
            NodeStateCollection nodeStateCollection,
            NodeStateCollection nodeStateCollectionWithServices,
            bool validateOutput = true)
        {
            string nsPrefix = m_context.Validator.Dictionary.TargetNamespaceInfo.Prefix;
            var resources = new List<Resource>();
            string identifiersFilePath = Path.Combine(
                m_context.OutputFolder,
                CoreUtils.Format("{0}.NodeIds.csv", nsPrefix));
            WriteIdentifiers(context, identifiersFilePath, nodeStateCollection);
            // resources.Add(new TextFileResource("Csv", identifiersFilePath));

            identifiersFilePath = Path.Combine(m_context.OutputFolder, CoreUtils.Format(
                "{0}.NodeIds.permissions.csv",
                nsPrefix));
            WritePermissions(context, identifiersFilePath, nodeStateCollection);
            // resources.Add(new TextFileResource("Permission.Csv", identifiersFilePath));

            string outputFile = Path.Combine(m_context.OutputFolder, CoreUtils.Format(
                "{0}.NodeSet2.xml",
                nsPrefix));
            using (Stream ostrm = m_context.FileSystem.OpenWrite(outputFile))
            {
                var model = new ModelTableEntry
                {
                    ModelUri = m_context.Validator.Dictionary.TargetNamespace,
                    XmlSchemaUri = m_context.Validator.Dictionary.TargetXmlNamespace,
                    Version = m_context.Validator.Dictionary.TargetVersion,
                    ModelVersion = CoreUtils.FixupAsSemanticVersion(
                        m_context.Validator.Dictionary.TargetVersion),
                    PublicationDate = m_context.Validator.Dictionary.TargetPublicationDate,
                    PublicationDateSpecified =
                        m_context.Validator.Dictionary.TargetPublicationDateSpecified
                };

                if (m_context.Validator.Dictionary.Dependencies != null)
                {
                    model.RequiredModel = [.. m_context.Validator.Dictionary.Dependencies.Values];
                }

                nodeStateCollection.SaveAsNodeSet2(
                    context,
                    ostrm,
                    model,
                    m_context.Validator.Dictionary.TargetPublicationDate != DateTime.MinValue ?
                        m_context.Validator.Dictionary.TargetPublicationDate : DateTime.MinValue,
                    true);
                resources.Add(new TextFileResource("Xml", outputFile));

                if (m_context.Validator.Dictionary.TargetNamespace == Namespaces.OpcUa)
                {
                    string nodeSetFilePath = Path.Combine(m_context.OutputFolder, CoreUtils.Format(
                        "{0}.NodeSet2.Services.xml",
                        nsPrefix));
                    using (Stream ostrm2 = m_context.FileSystem.OpenWrite(nodeSetFilePath))
                    {
                        nodeStateCollectionWithServices.SaveAsNodeSet2(
                            context,
                            ostrm2,
                            model,
                            m_context.Validator.Dictionary.TargetPublicationDate != DateTime.MinValue ?
                                m_context.Validator.Dictionary.TargetPublicationDate : DateTime.MinValue,
                            true);
                    }
                    resources.Add(new TextFileResource("Services.Xml", nodeSetFilePath));

                    identifiersFilePath = Path.Combine(m_context.OutputFolder, CoreUtils.Format(
                        "{0}.NodeIds.Services.csv",
                        nsPrefix));
                    WriteIdentifiers(context, identifiersFilePath, nodeStateCollectionWithServices);
                    // resources.Add(new TextFileResource("Services.Csv", nodeSetFilePath));

                    identifiersFilePath = Path.Combine(m_context.OutputFolder, CoreUtils.Format(
                        "{0}.NodeIds.Services.permissions.csv",
                        nsPrefix));
                    WritePermissions(context, identifiersFilePath, nodeStateCollectionWithServices);
                    // resources.Add(new TextFileResource("Services.Permissions.Csv", nodeSetFilePath));
                }
            }

            if (validateOutput)
            {
                // Validate
                using (Stream istrm = m_context.FileSystem.OpenRead(outputFile))
                {
                    UANodeSet.Validate(istrm, out IReadOnlyList<string> errors);
                    foreach (string error in errors)
                    {
                        m_logger.LogError("Nodeset2 Validation Error: {Error}", error);
                    }
                }

                // load as node set.
                using (Stream istrm = m_context.FileSystem.OpenRead(outputFile))
                {
                    var nodeSet = UANodeSet.Read(istrm);
                    var collection2 = new NodeStateCollection();
                    nodeSet.Import(context, collection2);
                }
            }

            // Pack as resources
            var resourceGenerator = new ResourceGenerator(m_context);
            resourceGenerator.Embed(
                nsPrefix,
                "NodeSet2",
                false,
                [.. resources]);
        }

        /// <summary>
        /// Embed all initializers as source code
        /// </summary>
        private void EmbedPredefinedNodes(
            SystemContext context,
            NodeStateCollection collection)
        {
            var initializers = new ResourceGenerator(m_context);
            using var ostrm = new MemoryStream();
            if (!m_useXmlInitializers)
            {
                collection.SaveAsBinary(context, ostrm);
            }
            else
            {
                collection.SaveAsXml(context, ostrm, true);
            }
            var predefinedNodesInitializer =
                new StreamResource("Nodes", ostrm, m_useXmlInitializers);
            initializers.Embed(
                m_context.Validator.Dictionary.TargetNamespaceInfo.Prefix,
                "Predefined",
                internalAccess: true,
                predefinedNodesInitializer);
        }

        /// <summary>
        /// Generate helpers
        /// </summary>
        private void GenerateHelpers()
        {
            string nsPrefix = m_context.Validator.Dictionary.TargetNamespaceInfo.Prefix;
            // Add helpers
            using TextWriter writer = m_context.FileSystem.CreateTextWriter(Path.Combine(
                m_context.OutputFolder,
                nsPrefix + ".Helpers.g.cs"));
            using var templateWriter = new TemplateWriter(writer);
            var template = new Template(templateWriter, CodeTemplates.Helpers_File_cs);

            template.AddReplacement(
                Tokens.ListOfImports,
                m_context.Validator.Dictionary.Namespaces,
                LoadTemplate_NamespaceImports);

            template.AddReplacement(Tokens.NamespacePrefix, nsPrefix);
            template.AddReplacement(Tokens.Namespace,
                nsPrefix.Replace(".", string.Empty, StringComparison.Ordinal));
            template.AddReplacement(Tokens.Encoding, EncodingString);

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

            context.Out.WriteLine("using {0};",
                m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(ns.Value));
            return null;
        }

        private static void IndexDocumentation(
            SystemContext context,
            IEnumerable<NodeState> source,
            Dictionary<NodeId, NodeState> map)
        {
            foreach (NodeState node in source)
            {
                if (!node.NodeId.IsNullNodeId)
                {
                    if (!string.IsNullOrEmpty(node.NodeSetDocumentation) ||
                        node.Categories?.Count > 0)
                    {
                        map[node.NodeId] = node;
                    }
                }

                List<BaseInstanceState> children = [];
                node.GetChildren(context, children);
                IndexDocumentation(context, children, map);
            }
        }

        private static void UpdateDocumentation(
            SystemContext context,
            Dictionary<NodeId, NodeState> original,
            IEnumerable<NodeState> updated)
        {
            foreach (NodeState node in updated)
            {
                if (original.TryGetValue(node.NodeId, out NodeState existingNode))
                {
                    node.NodeSetDocumentation =
                        !string.IsNullOrWhiteSpace(existingNode.NodeSetDocumentation)
                        ? existingNode.NodeSetDocumentation
                        : null;
                    node.Categories = existingNode.Categories;
                }

                List<BaseInstanceState> children = [];
                node.GetChildren(context, children);
                UpdateDocumentation(context, original, children);
            }
        }

        private void WritePermissions(
            SystemContext context,
            string identifiersFilePath,
            NodeStateCollection nodeStateCollection)
        {
            var list = new Dictionary<string, NodeState>();
            NodeDesign[] nodes = [.. m_context.Validator.Nodes];

            foreach (NodeState nodeState in nodeStateCollection)
            {
                string name = nodeState.SymbolicName;
                if (name is "DefaultBinary" or "DefaultXml" or "DefaultJson")
                {
                    var design = nodeState.Handle as NodeDesign;
                    name = design.SymbolicId.Name;
                }
                GetPermissionListEntries(context, list, nodeState, name);
            }

            IOrderedEnumerable<KeyValuePair<string, NodeState>> entries = list.OrderBy(x => x.Key);
            using TextWriter writer = m_context.FileSystem.CreateTextWriter(identifiersFilePath);
            foreach (KeyValuePair<string, NodeState> nodeStates in entries)
            {
                AccessRestrictionType? restrictions = FindAccessRestrictions(nodeStates.Value);
                RolePermissionTypeCollection permissions = FindRolePermissions(nodeStates.Value);

                if (permissions == null && restrictions == null)
                {
                    continue;
                }

                NodeId nid = nodeStates.Value.NodeId;

                if (nid.IdType == IdType.Numeric)
                {
                    writer.Write($"{nodeStates.Key},{nid.IdentifierAsString},{nodeStates.Value.NodeClass}");
                }
                else if (nid.IdType == IdType.String)
                {
                    writer.Write($"{nodeStates.Key},\"{nid.IdentifierAsString}\",{nodeStates.Value.NodeClass}");
                }

                if (restrictions != null)
                {
                    writer.Write(",\"[");
                    writer.Write(FormatAccessRestrictions((AccessRestrictionType)restrictions));
                    writer.Write("]\"");
                }
                else
                {
                    writer.Write(",");
                }

                if (permissions != null)
                {
                    writer.Write(",\"{");
                    bool start = true;
                    foreach (RolePermissionType permission in permissions)
                    {
                        NodeDesign role = nodes
                            .FirstOrDefault(x =>
                                permission.RoleId.TryGetIdentifier(out uint numericId) &&
                                x.NumericId == numericId &&
                                x.SymbolicId.Namespace == Namespaces.OpcUa);

                        role ??= nodes
                            .FirstOrDefault(x =>
                                permission.RoleId.TryGetIdentifier(out uint numericId) &&
                                x.NumericId == numericId &&
                                x.SymbolicId.Namespace != Namespaces.OpcUa &&
                                x is InstanceDesign instance &&
                                instance.TypeDefinition ==
                                    new XmlQualifiedName("RoleType", Namespaces.OpcUa));
                        if (!start)
                        {
                            writer.Write(",");
                        }
                        start = false;
                        writer.Write("'");
                        writer.Write(role?.DisplayName.Value ?? "Unknown");
                        writer.Write("':'(");
                        writer.Write(permission.Permissions);
                        writer.Write(") ");
                        writer.Write(FormatPermissions(permission.Permissions));
                        writer.Write("'");
                    }
                    writer.Write("}\"");
                }
                else
                {
                    writer.Write(",");
                }
                writer.WriteLine();
            }
        }

        private void WriteIdentifiers(
            SystemContext context,
            string identifiersFilePath,
            NodeStateCollection nodes)
        {
            var list = new Dictionary<string, NodeState>();

            foreach (NodeState ii in nodes)
            {
                string name = ii.SymbolicName;

                if (name is "DefaultBinary" or "DefaultXml" or "DefaultJson")
                {
                    var design = ii.Handle as NodeDesign;
                    name = design.SymbolicId.Name;
                }

                GetIdentifierListEntries(context, list, ii, name);
            }

            using TextWriter writer = m_context.FileSystem.CreateTextWriter(identifiersFilePath);
            foreach (KeyValuePair<string, NodeState> ii in list
                .OrderBy(x => x.Value.NodeId))
            {
                NodeId nid = ii.Value.NodeId;

                if (nid.IdType == IdType.Numeric)
                {
                    writer.WriteLine($"{ii.Key},{nid.IdentifierAsString},{ii.Value.NodeClass}");
                }
                else if (nid.IdType == IdType.String)
                {
                    writer.WriteLine($"{ii.Key},\"{nid.IdentifierAsString}\",{ii.Value.NodeClass}");
                }
            }
        }

        private static void GetIdentifierListEntries(
            SystemContext context,
            Dictionary<string, NodeState> list,
            NodeState node,
            string parentPath)
        {
            if (node.NodeId.IsNullNodeId)
            {
                return;
            }

            list.Add(parentPath, node);

            var children = new List<BaseInstanceState>();
            node.GetChildren(context, children);

            foreach (BaseInstanceState child in children)
            {
                GetIdentifierListEntries(
                    context,
                    list,
                    child,
                    $"{parentPath}_{child.SymbolicName}");
            }
        }

        private static void GetPermissionListEntries(
            SystemContext context,
            Dictionary<string, NodeState> list,
            NodeState node,
            string parentPath)
        {
            if (node.NodeId.IsNullNodeId)
            {
                return;
            }

            list.Add(parentPath, node);

            var children = new List<BaseInstanceState>();
            node.GetChildren(context, children);

            foreach (BaseInstanceState child in children)
            {
                GetPermissionListEntries(
                    context,
                    list,
                    child,
                    $"{parentPath}_{child.SymbolicName}");
            }
        }

        private static void GetPermissionListEntries(
            SystemContext context,
            Dictionary<string, NodeState> list,
            BaseInstanceState node,
            string parentPath)
        {
            if (node.NodeId.IsNullNodeId)
            {
                return;
            }

            list.Add(parentPath, node);
            var children = new List<BaseInstanceState>();
            node.GetChildren(context, children);

            foreach (BaseInstanceState child in children)
            {
                GetPermissionListEntries(
                    context,
                    list,
                    child,
                    $"{parentPath}_{child.SymbolicName}");
            }
        }

        private static string FormatPermissions(uint flags)
        {
            var list = new List<PermissionType>();

            if (flags == 0x1FFFF || (flags & (uint)PermissionType.AddReference) != 0)
            {
                return "All";
            }

            if (flags != 0)
            {
#if NET8_0_OR_GREATER
                foreach (PermissionType value in Enum.GetValues<PermissionType>())
#else
                foreach (PermissionType value in Enum.GetValues(typeof(PermissionType)))
#endif
                {
                    if (value != 0 && (flags & (uint)value) == (uint)value)
                    {
                        list.Add(value);
                    }
                }
            }
            else
            {
                list.Add(PermissionType.None);
            }

            return string.Join("|", list);
        }

        private static string FormatAccessRestrictions(AccessRestrictionType flags)
        {
            var list = new List<AccessRestrictionType>();
            if (flags != 0)
            {
#if NET8_0_OR_GREATER
                foreach (AccessRestrictionType value in Enum.GetValues<AccessRestrictionType>())
#else
                foreach (AccessRestrictionType value in Enum.GetValues(typeof(AccessRestrictionType)))
#endif
                {
                    if (value != 0 && (flags & value) == value)
                    {
                        list.Add(value);
                    }
                }
            }
            else
            {
                list.Add(AccessRestrictionType.None);
            }
            return string.Join(",", list);
        }

        private static RolePermissionTypeCollection FindRolePermissions(NodeState node)
        {
            if (node.RolePermissions != null)
            {
                return node.RolePermissions;
            }
            //if (node is BaseInstanceState instance && instance.Parent != null)
            //{
            //    return FindRolePermissions(instance.Parent);
            //}
            return null;
        }

        private static AccessRestrictionType? FindAccessRestrictions(NodeState node)
        {
            if (node.AccessRestrictions != null)
            {
                return node.AccessRestrictions;
            }
            //if (node is BaseInstanceState instance && instance.Parent != null)
            //{
            //    return FindAccessRestrictions(instance.Parent);
            //}
            return null;
        }

        private static ushort CollectNodes(
            SystemContext context,
            Dictionary<NodeId, NodeState> index,
            NodeState node)
        {
            index[node.NodeId] = node;

            List<BaseInstanceState> children = [];
            node.GetChildren(context, children);

            foreach (BaseInstanceState child in children)
            {
                CollectNodes(context, index, child);
            }

            return node.NodeId.NamespaceIndex;
        }

        private static void RemoveChildrenWithNoNodeId(
            SystemContext context,
            NodeState parent)
        {
            List<BaseInstanceState> children = [];
            parent.GetChildren(context, children);

            foreach (BaseInstanceState child in children)
            {
                if (child.NodeId.TryGetIdentifier(out uint numericId) && numericId == 0)
                {
                    parent.RemoveChild(child);
                    continue;
                }

                RemoveChildrenWithNoNodeId(context, child);
            }
        }

        private bool IsExcluded(NodeState node)
        {
            if (m_context.Options.Exclusions != null)
            {
                foreach (string exclusion in m_context.Options.Exclusions)
                {
                    if (exclusion == node.ReleaseStatus.ToString())
                    {
                        return true;
                    }

                    if (node.Categories != null && node.Categories.Contains(exclusion))
                    {
                        return true;
                    }

                    if (!string.IsNullOrEmpty(node.Specification) &&
                        exclusion == node.Specification)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private string EncodingString => m_useXmlInitializers ? "Xml" : "Binary";
        private readonly bool m_useXmlInitializers;
        private readonly bool m_embedNodeset;
        private readonly ILogger m_logger;
        private readonly GeneratorContext m_context;
    }
}
