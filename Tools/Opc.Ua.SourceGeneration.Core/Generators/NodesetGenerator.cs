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
using Opc.Ua.Export;
using Opc.Ua.Schema.Model;
using Opc.Ua.Types;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Address space generator
    /// </summary>
    internal sealed class NodesetGenerator
    {
        /// <summary>
        /// Loads the model design from the specified file and validates it.
        /// </summary>
        public NodesetGenerator(GeneratorContext context, bool useXmlInitializers = false)
        {
            m_context = context;
            m_useXmlInitializers = useXmlInitializers;
        }

        /// <summary>
        /// Generates all files
        /// </summary>
        public void Emit(bool embedNodeset = false)
        {
            var context = new SystemContext(m_context.Telemetry)
            {
                NamespaceUris = m_context.Validator.Dictionary.NamespaceUris,
                ServerUris = new StringTable()
            };

            // collect the nodes to write.
            NodeStateCollection collection = [];
            NodeStateCollection collectionWithServices = [];
            Dictionary<uint, NodeStateCollection> subsets = [];

            for (int ii = 0; ii < m_context.Validator.Dictionary.Items.Length; ii++)
            {
                NodeDesign node = m_context.Validator.Dictionary.Items[ii];

                if (m_context.Validator.IsExcluded(node))
                {
                    continue;
                }

                bool isInAddressSpace = !m_context.Validator.Dictionary.Items[ii].NotInAddressSpace;

                if (m_context.Validator.Dictionary.Items[ii] is InstanceDesign design2 &&
                    design2.TypeDefinition != null &&
                    design2.TypeDefinition.Name == "DataTypeEncodingType")
                {
                    isInAddressSpace = design2.Parent == null || !design2.Parent.NotInAddressSpace;
                }

                if (m_context.Validator.Dictionary.Items[ii] is MethodDesign design3 &&
                    design3.SymbolicName.Name.EndsWith("MethodType", StringComparison.Ordinal))
                {
                    continue;
                }

                NodeState state = m_context.Validator.Dictionary.Items[ii].State;

                if (state != null)
                {
                    if (node.Purpose == Schema.Model.DataTypePurpose.Testing)
                    {
                        continue;
                    }

                    collectionWithServices.Add(state);

                    if (isInAddressSpace)
                    {
                        collection.Add(state);
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

                    if (m_context.Validator.Dictionary.Items[ii].PartNo != 0)
                    {
                        if (!subsets.TryGetValue(
                            m_context.Validator.Dictionary.Items[ii].PartNo,
                            out NodeStateCollection subset))
                        {
                            subsets[m_context.Validator.Dictionary.Items[ii].PartNo] = subset = [];
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
                                m_context.Validator.Dictionary.TargetNamespaceInfo.Prefix + ".Types.xsd");
                        }

                        if (references.Count > 0 &&
                            references[0].TargetId == ObjectIds.OPCBinarySchema_TypeSystem)
                        {
                            file = Path.Combine(
                                m_context.OutputFolder,
                                m_context.Validator.Dictionary.TargetNamespaceInfo.Prefix + ".Types.bsd");
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
                m_context.Validator.Dictionary.TargetNamespaceInfo.Prefix + ".NodeSet2.documentation.csv");
            if (!m_context.FileSystem.Exists(documentationFile))
            {
                documentationFile = Path.Combine(
                    m_context.OutputFolder,
                    m_context.Validator.Dictionary.TargetNamespaceInfo.Prefix + ".NodeSet2.Services.documentation.csv");
            }

            if (m_context.FileSystem.Exists(documentationFile))
            {
                Dictionary<NodeId, NodeState> index = [];

                ushort namespaceIndex = 0;

                foreach (NodeState ii in collectionWithServices)
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
                m_context.Validator.Dictionary.TargetNamespaceInfo.Prefix + ".NodeSet2.xml");
            if (m_context.Validator.Dictionary.TargetNamespace == Namespaces.OpcUa)
            {
                originalFile = CoreUtils.Format("{0}{1}{2}.NodeSet2.Services.xml",
                    m_context.OutputFolder,
                    Path.DirectorySeparatorChar,
                    m_context.Validator.Dictionary.TargetNamespaceInfo.Prefix);
            }

            // load existing file from xml.
            if (m_context.FileSystem.Exists(originalFile))
            {
                try
                {
                    NodeStateCollection existingCollection = null;

                    using (Stream istrm = m_context.FileSystem.OpenRead(originalFile))
                    {
                        var nodeSet = UANodeSet.Read(istrm);
                        existingCollection = [];
                        nodeSet.Import(context, existingCollection);
                    }

                    Dictionary<NodeId, NodeState> map = [];
                    IndexDocumentation(context, existingCollection, map);

                    UpdateDocumentation(context, map, collection);

                    if (m_context.Validator.Dictionary.TargetNamespace == Namespaces.OpcUa)
                    {
                        UpdateDocumentation(context, map, collectionWithServices);
                    }
                }
                catch
                {
                    // ignore any unparseable file.
                }
            }

            if (embedNodeset)
            {
                // Generate nodeset2.xml files as source code (.g.cs)
                var nodesetGenerator = new Nodeset2Generator(m_context);
                IReadOnlyList<Resource> resources = nodesetGenerator.Emit(
                    m_context.OutputFolder,
                    context,
                    collection,
                    collectionWithServices);

                // Pack as resources
                var resourceGenerator = new ResourceGenerator(m_context);
                resourceGenerator.Embed(
                    m_context.Validator.Dictionary.TargetNamespaceInfo.Prefix,
                    "NodeSet2",
                    false,
                    [.. resources]);
            }

            // Embed predefined nodes and add helpers as source code (.g.cs)
            EmbedPredefinedNodes(context, collection);
            GenerateHelpers();
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

            string externalPrefix = m_context.Validator.Dictionary.Namespaces.GetNamespacePrefix(ns.Value);

            context.Out.WriteLine("using {0};", externalPrefix);

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

                    if (!string.IsNullOrEmpty(node.Specification) && exclusion == node.Specification)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private string EncodingString => m_useXmlInitializers ? "Xml" : "Binary";
        private readonly bool m_useXmlInitializers;
        private readonly GeneratorContext m_context;
    }
}
