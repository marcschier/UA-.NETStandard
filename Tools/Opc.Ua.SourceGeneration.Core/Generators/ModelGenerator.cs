/* ========================================================================
 * Copyright (c) 2005-2024 The OPC Foundation, Inc. All rights reserved.
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
using Opc.Ua.Export;
using Opc.Ua.Schema.Model;
using Opc.Ua.Types;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Model generator
    /// </summary>
    internal sealed class ModelGenerator
    {
        /// <summary>
        /// Loads the model design from the specified file and validates it.
        /// </summary>
        public ModelGenerator(IFileSystem fileSystem, ITelemetryContext telemetry)
        {
            m_telemetry = telemetry;
            m_context = new ServiceMessageContext(telemetry);
            m_fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
        }

        /// <summary>
        /// Whether the XML version of the initialization strings.
        /// </summary>
        public bool UseXmlInitializers { get; private set; }

        /// <summary>
        /// Available nodesets
        /// </summary>
        public Dictionary<string, string> AvailableNodeSets { get; set; }

        /// <summary>
        /// Generates the source code files.
        /// </summary>
        public void ValidateAndUpdateIds(
            IReadOnlyList<string> designFilePaths,
            string identifierFilePath,
            IReadOnlyList<string> exclusions,
            DesignFileOptions options = null,
            bool useAllowSubtypes = true,
            bool useXmlInitializers = false)
        {
            UseXmlInitializers = useXmlInitializers;
            m_exclusions = exclusions;
            options ??= new DesignFileOptions();

            m_validator = new ModelDesignValidator(
                m_fileSystem,
                options.StartId,
                exclusions,
                m_telemetry,
                SpecificationVersion.V105)
            {
                UseAllowSubtypes = useAllowSubtypes,
                ReleaseCandidate = options.ReleaseCandidate,
                ModelVersion = options.ModelVersion,
                ModelPublicationDate = options.ModelPublicationDate
            };

            m_validator.Validate(designFilePaths, identifierFilePath, false);
            m_model = m_validator.Dictionary;
        }

        /// <summary>
        /// Generates all files
        /// </summary>
        public void Emit(string filePath)
        {
            // write type and object definitions.
            List<NodeDesign> nodes = GetNodeList();
            if (nodes.Count == 0)
            {
                return;
            }

            var context = new SystemContext(m_telemetry)
            {
                NamespaceUris = m_model.NamespaceUris,
                ServerUris = new StringTable()
            };

            GenerateConstants(filePath, nodes);
            GenerateDataTypes(filePath, nodes);
            GenerateNonDataTypes(filePath, nodes);
            GenerateXmlSchema(filePath, nodes);
            GenerateBinarySchema(filePath, nodes);

            NodeStateCollection nodeStates = GenerateNodeSet(filePath, context);

            // Embed initializers and add helpers as source code (.g.cs)
            EmbedInitializers(filePath, context, nodeStates);

            GenerateHelpers(filePath);
        }

        /// <summary>
        /// Writes the nodesets
        /// </summary>
        private NodeStateCollection GenerateNodeSet(
            string filePath,
            SystemContext context,
            bool embedNodeSet = false)
        {
            // collect the nodes to write.
            NodeStateCollection collection = [];
            NodeStateCollection collectionWithServices = [];
            Dictionary<uint, NodeStateCollection> subsets = [];

            for (int ii = 0; ii < m_model.Items.Length; ii++)
            {
                NodeDesign node = m_model.Items[ii];

                if (IsExcluded(node))
                {
                    continue;
                }

                bool isInAddressSpace = !m_model.Items[ii].NotInAddressSpace;

                if (m_model.Items[ii] is InstanceDesign design2 &&
                    design2.TypeDefinition != null &&
                    design2.TypeDefinition.Name == "DataTypeEncodingType")
                {
                    isInAddressSpace = design2.Parent == null || !design2.Parent.NotInAddressSpace;
                }

                if (m_model.Items[ii] is MethodDesign design3 &&
                    design3.SymbolicName.Name.EndsWith("MethodType", StringComparison.Ordinal))
                {
                    continue;
                }

                NodeState state = m_model.Items[ii].State;

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

                    if (m_model.Items[ii].PartNo != 0)
                    {
                        if (!subsets.TryGetValue(m_model.Items[ii].PartNo, out NodeStateCollection subset))
                        {
                            subsets[m_model.Items[ii].PartNo] = subset = [];
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
                                filePath,
                                m_model.TargetNamespaceInfo.Prefix + ".Types.xsd");
                        }

                        if (references.Count > 0 &&
                            references[0].TargetId == ObjectIds.OPCBinarySchema_TypeSystem)
                        {
                            file = Path.Combine(
                                filePath,
                                m_model.TargetNamespaceInfo.Prefix + ".Types.bsd");
                        }

                        if (file != null)
                        {
                            try
                            {
                                if (m_fileSystem.Exists(file))
                                {
                                    using Stream stream = m_fileSystem.OpenRead(file);
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
                filePath,
                m_model.TargetNamespaceInfo.Prefix + ".NodeSet2.documentation.csv");

            if (!m_fileSystem.Exists(documentationFile))
            {
                documentationFile = Path.Combine(
                    filePath,
                    m_model.TargetNamespaceInfo.Prefix + ".NodeSet2.Services.documentation.csv");
            }

            if (m_fileSystem.Exists(documentationFile))
            {
                Dictionary<NodeId, NodeState> index = [];

                ushort namespaceIndex = 0;

                foreach (NodeState ii in collectionWithServices)
                {
                    index[ii.NodeId] = ii;
                    namespaceIndex = CollectNodes(context, index, ii);
                }

                var reader = new NodeDocumentationReader(m_fileSystem);
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
                filePath,
                m_model.TargetNamespaceInfo.Prefix + ".NodeSet2.xml");
            if (m_model.TargetNamespace == Namespaces.OpcUa)
            {
                originalFile = CoreUtils.Format("{0}{1}{2}.NodeSet2.Services.xml",
                    filePath,
                    Path.DirectorySeparatorChar,
                    m_model.TargetNamespaceInfo.Prefix);
            }

            // load existing file from xml.
            if (m_fileSystem.Exists(originalFile))
            {
                try
                {
                    NodeStateCollection existingCollection = null;

                    using (Stream istrm = m_fileSystem.OpenRead(originalFile))
                    {
                        var nodeSet = UANodeSet.Read(istrm);
                        existingCollection = [];
                        nodeSet.Import(context, existingCollection);
                    }

                    Dictionary<NodeId, NodeState> map = [];
                    IndexDocumentation(context, existingCollection, map);

                    UpdateDocumentation(context, map, collection);

                    if (m_model.TargetNamespace == Namespaces.OpcUa)
                    {
                        UpdateDocumentation(context, map, collectionWithServices);
                    }
                }
                catch
                {
                    // ignore any unparseable file.
                }
            }

            if (embedNodeSet)
            {
                // Generate nodeset2.xml files as source code (.g.cs)
                var nodesetGenerator = new Nodeset2Generator(
                    m_model,
                    [.. m_validator.Nodes],
                    m_fileSystem,
                    m_telemetry);
                IReadOnlyList<Resource> resources = nodesetGenerator.Emit(
                    filePath,
                    context,
                    collection,
                    collectionWithServices);

                // Pack as resources
                var resourceGenerator = new ResourceGenerator(m_fileSystem, filePath);
                resourceGenerator.Embed(
                    m_model.TargetNamespaceInfo.Prefix,
                    "NodeSet2",
                    [.. resources]);
            }
            return collection;
        }

        private void GenerateConstants(string filePath, List<NodeDesign> nodes)
        {
            using TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(
                filePath,
                m_model.TargetNamespaceInfo.Prefix + ".Constants.g.cs"));
            var template = new Template(writer, CodeTemplateStrings.ConstantsFile_cs);

            template.AddReplacement(
                Tokens.Namespace,
                m_model.Namespaces.GetNamespacePrefix(m_model.TargetNamespace));
            template.AddReplacement(
                Tokens.NamespaceUri,
                m_model.Namespaces.GetConstantSymbolForNamespace(m_model.TargetNamespace));

            template.AddTemplate(
                Tokens.ListOfImports,
                null,
                m_model.Namespaces,
                LoadTemplate_NamespaceImports,
                null);

            List<string> namespaces = [];

            for (int ii = 0; ii < m_model.Namespaces.Length; ii++)
            {
                namespaces.Add(m_model.Namespaces[ii].Value);

                if (!string.IsNullOrEmpty(m_model.Namespaces[ii].XmlNamespace))
                {
                    namespaces.Add(m_model.Namespaces[ii].XmlNamespace);
                }
            }

            template.AddTemplate(
                Tokens.ListOfNamespaceUris,
                CodeTemplateStrings.NamespaceUri_cs,
                namespaces,
                null,
                WriteTemplate_CodeNamespaceUri);

            SortedDictionary<string, string> browseNames = GetBrowseNames(nodes);

            template.AddTemplate(
                Tokens.ListOfBrowseNames,
                CodeTemplateStrings.BrowseName_cs,
                browseNames,
                LoadTemplate_BrowseNames,
                WriteTemplate_BrowseNames);

            SortedDictionary<string, List<NodeDesign>> identifiers = GetIdentifiers();

            template.AddTemplate(
                Tokens.ListOfIdentifiers,
                CodeTemplateStrings.IdClass_cs,
                identifiers,
                LoadTemplate_IdClass,
                WriteTemplate_IdClass);

            template.AddTemplate(
                Tokens.ListOfNodeIds,
                CodeTemplateStrings.NodeIdClass_cs,
                identifiers,
                LoadTemplate_IdClass,
                WriteTemplate_NodeIdClass);

            var context = new Context
            {
                Target = nodes
            };
            template.WriteTemplate(context);
        }

        private void GenerateDataTypes(string filePath, List<NodeDesign> nodes)
        {
            using TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(
                filePath,
                m_model.TargetNamespaceInfo.Prefix + ".DataTypes.g.cs"));
            var template = new Template(writer, CodeTemplateStrings.TypesFile_cs);

            template.AddReplacement(
                Tokens.Namespace,
                m_model.Namespaces.GetNamespacePrefix(m_model.TargetNamespace));
            template.AddReplacement(
                Tokens.NamespaceUri,
                m_model.Namespaces.GetConstantSymbolForNamespace(m_model.TargetNamespace));

            template.AddTemplate(
                Tokens.ListOfImports,
                null,
                m_model.Namespaces,
                LoadTemplate_NamespaceImports,
                null);

            List<string> namespaces = [];

            for (int ii = 0; ii < m_model.Namespaces.Length; ii++)
            {
                namespaces.Add(m_model.Namespaces[ii].Value);

                if (!string.IsNullOrEmpty(m_model.Namespaces[ii].XmlNamespace))
                {
                    namespaces.Add(m_model.Namespaces[ii].XmlNamespace);
                }
            }

            List<DataTypeDesign> datatypes = [];

            for (int ii = 0; ii < nodes.Count; ii++)
            {
                if (nodes[ii] is DataTypeDesign dataTypeDesign &&
                    !dataTypeDesign.IsPartOfOpcUaTypesLibrary())
                {
                    datatypes.Add(dataTypeDesign);
                }
            }

            template.AddTemplate(
                Tokens.ListOfTypes,
                string.Empty,
                datatypes,
                LoadTemplate_ListOfTypes,
                WriteTemplate_ListOfTypes);

            var context = new Context
            {
                Target = nodes
            };
            template.WriteTemplate(context);
        }

        private void GenerateNonDataTypes(string filePath, List<NodeDesign> nodes)
        {
            using TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(
                filePath,
                m_model.TargetNamespaceInfo.Prefix + ".Classes.g.cs"));
            var template = new Template(writer, CodeTemplateStrings.TypesFile_cs);

            template.AddReplacement(
                Tokens.Namespace,
                m_model.Namespaces.GetNamespacePrefix(m_model.TargetNamespace));
            template.AddReplacement(
                Tokens.NamespaceUri,
                m_model.Namespaces.GetConstantSymbolForNamespace(m_model.TargetNamespace));

            template.AddTemplate(
                Tokens.ListOfImports,
                null,
                m_model.Namespaces,
                LoadTemplate_NamespaceImports,
                null);

            List<string> namespaces = [];

            for (int ii = 0; ii < m_model.Namespaces.Length; ii++)
            {
                namespaces.Add(m_model.Namespaces[ii].Value);

                if (!string.IsNullOrEmpty(m_model.Namespaces[ii].XmlNamespace))
                {
                    namespaces.Add(m_model.Namespaces[ii].XmlNamespace);
                }
            }

            List<NodeDesign> nonDataTypes = [];

            for (int ii = 0; ii < nodes.Count; ii++)
            {
                if (nodes[ii] is not DataTypeDesign)
                {
                    if (nodes[ii] is MethodDesign &&
                        !nodes[ii].SymbolicName.Name.EndsWith("MethodType", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    nonDataTypes.Add(nodes[ii]);
                }
            }

            template.AddTemplate(
                Tokens.ListOfTypes,
                string.Empty,
                nonDataTypes,
                LoadTemplate_ListOfTypes,
                WriteTemplate_ListOfTypes);

            var context = new Context
            {
                Target = nodes
            };
            template.WriteTemplate(context);
        }

        private void GenerateXmlSchema(string filePath, List<NodeDesign> nodes)
        {
            using TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(
                filePath,
                CoreUtils.Format("{0}.Types.xsd", m_model.TargetNamespaceInfo.Prefix)));
            WriteTemplate_XmlSchema(writer, nodes);
        }

        private void GenerateBinarySchema(string filePath, List<NodeDesign> nodes)
        {
            using TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(
                filePath,
                CoreUtils.Format("{0}.Types.bsd", m_model.TargetNamespaceInfo.Prefix)));
            WriteTemplate_BinarySchema(writer, nodes);
        }

        /// <summary>
        /// Generate helpers
        /// </summary>
        /// <param name="filePath"></param>
        private void GenerateHelpers(string filePath)
        {
            string nsPrefix = m_model.TargetNamespaceInfo.Prefix;
            // Add helpers
            using TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(
                filePath,
                nsPrefix + ".Helpers.g.cs"));
            var template = new Template(writer, CodeTemplateStrings.Helpers_File_cs);

            template.AddTemplate(
                Tokens.ListOfImports,
                null,
                m_model.Namespaces,
                LoadTemplate_NamespaceImports,
                null);

            template.AddReplacement(Tokens.NamespacePrefix, nsPrefix);
            template.AddReplacement(Tokens.Namespace,
                nsPrefix.Replace(".", string.Empty, StringComparison.Ordinal));
            template.AddReplacement(Tokens.Encoding, UseXmlInitializers ? "Xml" : "Binary");

            template.WriteTemplate(null);
        }

        /// <summary>
        /// Embed all initializers as source code
        /// </summary>
        private void EmbedInitializers(
            string filePath,
            SystemContext context,
            NodeStateCollection collection)
        {
            var initializers = new ResourceGenerator(m_fileSystem, filePath);
            using var ostrm = new MemoryStream();
            if (!UseXmlInitializers)
            {
                collection.SaveAsBinary(context, ostrm);
            }
            else
            {
                collection.SaveAsXml(context, ostrm, true);
            }
            var predefinedNodesInitializer =
                new StreamResource("PredefinedNodes", ostrm, UseXmlInitializers);
            initializers.Embed(
                m_model.TargetNamespaceInfo.Prefix,
                "Initializers",
                [.. m_initializers.Values, predefinedNodesInitializer]);
        }

        private void WriteTemplate_XmlSchema(TextWriter writer, List<NodeDesign> nodes)
        {
            var template = new Template(writer, SchemaTemplateStrings.XmlSchema_File_xml);

            if (!string.IsNullOrEmpty(m_model.TargetNamespaceInfo.XmlNamespace))
            {
                template.AddReplacement(Tokens.Namespace, m_model.TargetNamespaceInfo.XmlNamespace);
            }
            else
            {
                template.AddReplacement(Tokens.Namespace, m_model.TargetNamespaceInfo.Value);
            }

            template.AddReplacement(Tokens.TargetVersion, m_model.TargetVersion);
            template.AddReplacement(Tokens.ModelUri, m_model.TargetNamespaceInfo.Value);
            template.AddReplacement(Tokens.TargetPublicationDate, XmlConvert.ToString(
                m_model.TargetPublicationDate,
                XmlDateTimeSerializationMode.Utc));

            template.AddTemplate(
                Tokens.XmlnsS0ListOfNamespaces,
                null,
                m_model.Namespaces,
                LoadTemplate_XmlNamespaceImports,
                null);

            template.AddTemplate(
                Tokens.Imports,
                null,
                m_model.Namespaces,
                LoadTemplate_XmlNamespaceImports,
                null);

            template.AddTemplate(
                Tokens.BuiltInTypes,
                SchemaTemplateStrings.Stack_XmlSchema_BuiltInTypes_xsd,
                new ModelDesign[] { m_model },
                LoadTemplate_XmlType,
                WriteTemplate_XmlType);

            template.AddTemplate(
                Tokens.ListOfTypes,
                null,
                nodes,
                LoadTemplate_XmlType,
                WriteTemplate_XmlType);

            template.WriteTemplate(null);
        }

        private string LoadTemplate_XmlNamespaceImports(Template template, Context context)
        {
            if (context.Target is not Namespace ns)
            {
                return null;
            }

            if (ns.Value == m_model.TargetNamespace)
            {
                return null;
            }

            string uri = ns.Value;

            if (!string.IsNullOrEmpty(ns.XmlNamespace))
            {
                uri = ns.XmlNamespace;
            }

            if (context.Token.Contains("xmlns:s0", StringComparison.Ordinal))
            {
                if (ns.Value == Namespaces.OpcUa)
                {
                    return null;
                }

                template.WriteNextLine(context.Prefix);
                template.Write("xmlns:{0}=\"{1}\"", m_model.Namespaces.GetXmlNamespacePrefix(ns.Value), uri);

                return null;
            }

            template.WriteNextLine(context.Prefix);
            template.Write("""<xs:import namespace="{0}" />""", uri);

            return null;
        }

        private string LoadTemplate_XmlType(Template template, Context context)
        {
            if (context.Target is ModelDesign)
            {
                if (m_model.TargetNamespace == Namespaces.OpcUa)
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
                    case DataTypes.RolePermissionType:
                    case DataTypes.DataTypeDefinition:
                    case DataTypes.StructureDefinition:
                    case DataTypes.StructureField:
                    case DataTypes.StructureType:
                    case DataTypes.EnumDefinition:
                    case DataTypes.EnumField:
                        break;
                    default:
                        return null;
                }
            }

            BasicDataType basicType = dataType.BasicDataType;

            if (basicType == BasicDataType.Enumeration)
            {
                var baseType = dataType.BaseTypeNode as DataTypeDesign;

                if (baseType?.SymbolicId == new XmlQualifiedName("OptionSet", Namespaces.OpcUa))
                {
                    return SchemaTemplateStrings.XmlSchema_DerivedType_xml;
                }

                return SchemaTemplateStrings.XmlSchema_EnumeratedType_xml;
            }
            else if (basicType == BasicDataType.UserDefined)
            {
                if (dataType.BaseTypeNode.SymbolicName.Name == "Union")
                {
                    return SchemaTemplateStrings.XmlSchema_Union_xml;
                }
                else if (dataType.BaseTypeNode.SymbolicName.Name == "Structure")
                {
                    return SchemaTemplateStrings.XmlSchema_ComplexType_xml;
                }
                else
                {
                    return SchemaTemplateStrings.XmlSchema_DerivedType_xml;
                }
            }

            return SchemaTemplateStrings.XmlSchema_SimpleType_xml;
        }

        private bool WriteTemplate_XmlType(Template template, Context context)
        {
            if (context.Target is ModelDesign model)
            {
                if (m_model.TargetNamespace == Namespaces.OpcUa)
                {
                    return template.WriteTemplate(context);
                }

                return false;
            }

            if (context.Target is not DataTypeDesign dataType)
            {
                return false;
            }

            if (context.FirstInList)
            {
                template.WriteNextLine(string.Empty);
            }

            var baseType = dataType.BaseTypeNode as DataTypeDesign;

            if (baseType != null)
            {
                template.AddReplacement(Tokens.BaseType, baseType.GetXmlDataType(
                    ValueRank.Scalar,
                    m_model.TargetNamespace,
                    m_model.Namespaces));
            }

            template.AddReplacement(Tokens.TypeName, dataType.SymbolicName.Name);

            if (dataType.BasicDataType == BasicDataType.Enumeration && dataType.IsOptionSet)
            {
                template.AddReplacement(Tokens.XsRestrictionBaseType,
                    baseType.GetXmlDataType(
                        ValueRank.Scalar,
                        m_model.TargetNamespace,
                        m_model.Namespaces));
            }
            else
            {
                template.AddReplacement(Tokens.XsRestrictionBaseType, "xs:string");
            }

            template.AddTemplate(
                Tokens.Documentation,
                SchemaTemplateStrings.XmlSchema_Documentation_xml,
                new DataTypeDesign[] { dataType },
                LoadTemplate_XmlDocumentation,
                WriteTemplate_XmlDocumentation);

            template.AddTemplate(
                Tokens.CollectionType,
                SchemaTemplateStrings.XmlSchema_CollectionType_xml,
                new DataTypeDesign[] { dataType },
                LoadTemplate_XmlCollectionType,
                WriteTemplate_XmlCollectionType);

            template.AddTemplate(
                Tokens.ListOfFields,
                null,
                dataType.Fields,
                LoadTemplate_XmlTypeFields,
                null);

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_XmlTypeFields(Template template, Context context)
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

            if (basicType == BasicDataType.Enumeration)
            {
                if (dataType.IsOptionSet)
                {
                    return null;
                }

                template.WriteNextLine(context.Prefix);

                if (field.IdentifierInName)
                {
                    template.Write("""<xs:enumeration value="{0}" />""", field.Name);
                    return null;
                }

                template.Write("""<xs:enumeration value="{0}_{1}" />""", field.Name, field.Identifier);
                return null;
            }

            basicType = field.DataTypeNode.BasicDataType;

            if (basicType == BasicDataType.XmlElement && field.ValueRank == ValueRank.Scalar)
            {
                template.WriteNextLine(context.Prefix);
                template.Write("""<xs:element name="{0}" minOccurs="0" nillable="true">""", field.Name);
                template.WriteNextLine(context.Prefix);
                template.Write("  <xs:complexType>");
                template.WriteNextLine(context.Prefix);
                template.Write("    <xs:sequence>");
                template.WriteNextLine(context.Prefix);
                template.Write("""      <xs:any minOccurs="0" processContents="lax" />""");
                template.WriteNextLine(context.Prefix);
                template.Write("    </xs:sequence>");
                template.WriteNextLine(context.Prefix);
                template.Write("  </xs:complexType>");
                template.WriteNextLine(context.Prefix);
                template.Write("</xs:element>");
                return null;
            }

            template.WriteNextLine(context.Prefix);

            if (field.ValueRank != ValueRank.Scalar)
            {
                string fieldDataType = field.DataTypeNode.GetXmlDataType(
                    field.ValueRank,
                    m_model.TargetNamespace,
                    m_model.Namespaces);

                if (basicType == BasicDataType.UserDefined && field.AllowSubTypes)
                {
                    fieldDataType = "ua:ListOfExtensionObject";
                }

                template.Write(
                    """<xs:element name="{0}" type="{1}" minOccurs="0" nillable="true" />""",
                    field.Name,
                    fieldDataType);
            }
            else
            {
                switch (basicType)
                {
                    case BasicDataType.String:
                    case BasicDataType.ByteString:
                    case BasicDataType.DiagnosticInfo:
                    case BasicDataType.ExpandedNodeId:
                    case BasicDataType.LocalizedText:
                    case BasicDataType.NodeId:
                    case BasicDataType.QualifiedName:
                    case BasicDataType.Structure:
                    case BasicDataType.DataValue:
                        template.Write(
                                """<xs:element name="{0}" type="{1}" minOccurs="0" nillable="true" />""",
                                field.Name,
                                field.DataTypeNode.GetXmlDataType(
                                    field.ValueRank,
                                    m_model.TargetNamespace,
                                    m_model.Namespaces));
                        break;
                    case BasicDataType.Guid:
                    case BasicDataType.StatusCode:
                        template.Write(
                                """<xs:element name="{0}" type="{1}" minOccurs="0" />""",
                                field.Name,
                                field.DataTypeNode.GetXmlDataType(
                                    field.ValueRank,
                                    m_model.TargetNamespace,
                                    m_model.Namespaces));
                        break;
                    case BasicDataType.UserDefined:
                        string fieldDataType = field.DataTypeNode.GetXmlDataType(
                                field.ValueRank,
                                m_model.TargetNamespace,
                                m_model.Namespaces);

                        if (field.AllowSubTypes)
                        {
                            fieldDataType = "ua:ExtensionObject";
                        }

                        template.Write(
                            """<xs:element name="{0}" type="{1}" minOccurs="0" nillable="true" />""",
                            field.Name,
                            fieldDataType);
                        break;
                    default:
                        template.Write("""<xs:element name="{0}" type="{1}" minOccurs="0" />""",
                                field.Name,
                                field.DataTypeNode.GetXmlDataType(
    field.ValueRank,
                                    m_model.TargetNamespace,
                                    m_model.Namespaces));
                        break;
                }
            }

            return null;
        }

        private string LoadTemplate_XmlDocumentation(Template template, Context context)
        {
            if (context.Target is not DataTypeDesign dataType)
            {
                return null;
            }

            if (dataType.Description == null || dataType.Description.IsAutogenerated)
            {
                return null;
            }

            return context.TemplateString;
        }

        private bool WriteTemplate_XmlDocumentation(Template template, Context context)
        {
            if (context.Target is not DataTypeDesign dataType)
            {
                return false;
            }

            template.AddReplacement(Tokens.Description, dataType.Description.Value);

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_XmlCollectionType(Template template, Context context)
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

        private bool WriteTemplate_XmlCollectionType(Template template, Context context)
        {
            if (context.Target is not DataTypeDesign dataType)
            {
                return false;
            }

            template.WriteLine(string.Empty);
            template.AddReplacement(Tokens.TypeName, dataType.SymbolicName.Name);
            template.AddReplacement(
                Tokens.Nillable,
                !dataType.BasicDataType.IsXmlNillable() ?
                    string.Empty : """nillable="true" """);

            return template.WriteTemplate(context);
        }

        private void WriteTemplate_BinarySchema(TextWriter writer, List<NodeDesign> nodes)
        {
            var template = new Template(writer, SchemaTemplateStrings.BinarySchema_File_xml);

            template.AddReplacement(Tokens.DictionaryUri, m_model.TargetNamespace);

            template.AddTemplate(
                Tokens.XmlnsS0ListOfNamespaces,
                null,
                m_model.Namespaces,
                LoadTemplate_BinaryNamespaceImports,
                null);

            template.AddTemplate(
                Tokens.Imports,
                null,
                m_model.Namespaces,
                LoadTemplate_BinaryNamespaceImports,
                null);

            template.AddTemplate(
                Tokens.BuiltInTypes,
                SchemaTemplateStrings.BinarySchema_BuiltInTypes_bsd,
                new ModelDesign[] { m_model },
                LoadTemplate_BinaryType,
                WriteTemplate_BinaryType);

            template.AddTemplate(
                Tokens.ListOfTypes,
                null,
                nodes,
                LoadTemplate_BinaryType,
                WriteTemplate_BinaryType);

            template.WriteTemplate(null);
        }

        private string LoadTemplate_BinaryNamespaceImports(Template template, Context context)
        {
            if (context.Target is not Namespace ns)
            {
                return null;
            }

            if (ns.Value == m_model.TargetNamespace)
            {
                return null;
            }

            if (context.Token.Contains("xmlns:s0", StringComparison.Ordinal))
            {
                if (ns.Value == Namespaces.OpcUa)
                {
                    return null;
                }

                template.WriteNextLine(context.Prefix);
                template.Write(
                    """
                    xmlns:{0}="{1}"
                    """,
                    m_model.Namespaces.GetXmlNamespacePrefix(ns.Value),
                    ns.Value);
                return null;
            }

            template.WriteNextLine(context.Prefix);
            template.Write(
                """<opc:Import Namespace="{0}" Location="{1}.BinarySchema.bsd"/>""",
                ns.Value,
                m_model.Namespaces.GetNamespacePrefix(ns.Value));

            return null;
        }

        private string LoadTemplate_BinaryType(Template template, Context context)
        {
            if (context.Target is ModelDesign)
            {
                if (m_model.TargetNamespace == Namespaces.OpcUa)
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
                return SchemaTemplateStrings.BinarySchema_EnumeratedType_xml;
            }
            else if (basicType == BasicDataType.UserDefined)
            {
                return SchemaTemplateStrings.BinarySchema_ComplexType_xml;
            }

            return SchemaTemplateStrings.BinarySchema_OpaqueType_xml;
        }

        private bool WriteTemplate_BinaryType(Template template, Context context)
        {
            if (context.Target is ModelDesign model)
            {
                if (m_model.TargetNamespace == Namespaces.OpcUa)
                {
                    template.WriteNextLine(string.Empty);
                    return template.WriteTemplate(context);
                }

                return false;
            }

            if (context.Target is not DataTypeDesign dataType)
            {
                return false;
            }

            if (context.FirstInList)
            {
                template.WriteNextLine(string.Empty);
            }

            template.AddReplacement(Tokens.TypeName, dataType.SymbolicName.Name);

            if (dataType.BasicDataType == BasicDataType.UserDefined)
            {
                template.AddReplacement(Tokens.BaseType,
                    (dataType.BaseTypeNode as DataTypeDesign).GetBinaryDataType(
                        m_model.TargetNamespace,
                        m_model.Namespaces));
            }

            List<Parameter> fields = [];
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
                    if (IsExcluded(field))
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

                template.AddReplacement(Tokens.LengthInBits, lengthInBits);
                template.AddReplacement(
                    Tokens.IsOptionSet,
                    isOptionSet ? " IsOptionSet=\"true\"" : string.Empty);
            }

            template.AddTemplate(
                Tokens.Documentation,
                null,
                new DataTypeDesign[] { dataType },
                LoadTemplate_BinaryDocumentation,
                null);

            template.AddTemplate(
                Tokens.ListOfFields,
                null,
                fields,
                LoadTemplate_BinaryTypeFields,
                null);

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_BinaryTypeFields(Template template, Context context)
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
                m_model.TargetNamespace,
                m_model.Namespaces);

            if (field.AllowSubTypes)
            {
                fieldDataType = "ua:ExtensionObject";
            }

            if (basicType == BasicDataType.Enumeration)
            {
                template.WriteNextLine(context.Prefix);
                template.Write(
                    """<opc:EnumeratedValue Name="{0}" Value="{1}" />""",
                    field.Name,
                    field.Identifier);
                return null;
            }

            if (field.ValueRank != ValueRank.Scalar)
            {
                template.WriteNextLine(context.Prefix);
                template.Write(
                    """<opc:Field Name="NoOf{0}" TypeName="opc:Int32" />""",
                    field.Name);
                template.WriteNextLine(context.Prefix);
                template.Write(
                    """<opc:Field Name="{0}" TypeName="{1}" LengthField="NoOf{0}" />""",
                    field.Name,
                    fieldDataType);
                return null;
            }

            template.WriteNextLine(context.Prefix);

            if (field.IsInherited)
            {
                template.Write(
                    """<opc:Field Name="{0}" TypeName="{1}" SourceType="{2}" />""",
                    field.Name,
                    fieldDataType,
                    (field.Parent as DataTypeDesign).GetBinaryDataType(m_model.TargetNamespace, m_model.Namespaces));
            }
            else
            {
                template.Write("""<opc:Field Name="{0}" TypeName="{1}" />""", field.Name, fieldDataType);
            }

            return null;
        }

        private string LoadTemplate_BinaryDocumentation(Template template, Context context)
        {
            if (context.Target is not DataTypeDesign dataType)
            {
                return null;
            }

            if (dataType.Description == null || dataType.Description.IsAutogenerated)
            {
                return null;
            }

            template.WriteNextLine(context.Prefix);
            template.Write("<opc:Documentation>{0}</opc:Documentation>", dataType.Description.Value);

            return context.TemplateString;
        }

        private string LoadTemplate_IdClass(Template template, Context context)
        {
            if (context.Target is not KeyValuePair<string, List<NodeDesign>> nodes)
            {
                return null;
            }

            if (nodes.Value == null || nodes.Value.Count == 0)
            {
                return null;
            }

            return context.TemplateString;
        }

        private bool WriteTemplate_IdClass(Template template, Context context)
        {
            if (context.Target is not KeyValuePair<string, List<NodeDesign>> nodes ||
                nodes.Value == null)
            {
                return false;
            }

            template.AddReplacement(Tokens.NodeClass, nodes.Key);
            template.AddReplacement(
                Tokens.NamespacePrefix,
                m_model.Namespaces.GetNamespacePrefix(m_model.TargetNamespace));
            template.AddReplacement(Tokens.Namespace, m_model.TargetNamespace);

            template.AddTemplate(
                Tokens.ListOfIdentifiers,
                CodeTemplateStrings.IdDeclaration_cs,
                nodes.Value,
                null,
                WriteTemplate_IdDeclaration);

            return template.WriteTemplate(context);
        }

        private bool WriteTemplate_NodeIdClass(Template template, Context context)
        {
            if (context.Target is not KeyValuePair<string, List<NodeDesign>> nodes ||
                nodes.Value == null)
            {
                return false;
            }

            template.AddReplacement(Tokens.NodeClass, nodes.Key);
            template.AddReplacement(
                Tokens.NamespacePrefix,
                m_model.Namespaces.GetNamespacePrefix(m_model.TargetNamespace));
            template.AddReplacement(Tokens.Namespace, m_model.TargetNamespace);

            string templatePath = m_model.TargetNamespace != Namespaces.OpcUa ?
                CodeTemplateStrings.NodeIdDeclarationAbsolute_cs :
                CodeTemplateStrings.NodeIdDeclaration_cs;

            template.AddTemplate(
                Tokens.ListOfIdentifiers,
                templatePath,
                nodes.Value,
                null,
                WriteTemplate_IdDeclaration);

            return template.WriteTemplate(context);
        }

        private bool WriteTemplate_IdDeclaration(Template template, Context context)
        {
            if (context.Target is not NodeDesign node)
            {
                return false;
            }

            object id;
            string idType;
            if (node.NumericIdSpecified)
            {
                id = node.NumericId;
                idType = "uint";
            }
            else
            {
                id = $"\"{node.StringId}\"";
                idType = "string";
            }

            template.AddReplacement(Tokens.NodeClass, node.GetNodeClassString());
            template.AddReplacement(Tokens.SymbolicName, node.SymbolicId.Name);
            template.AddReplacement(Tokens.Identifier, id);
            template.AddReplacement(
                Tokens.NamespaceUri,
                m_model.Namespaces.GetConstantSymbolForNamespace(node.SymbolicId.Namespace));
            template.AddReplacement(
                Tokens.NamespacePrefix,
                m_model.Namespaces.GetNamespacePrefix(node.SymbolicId.Namespace));
            template.AddReplacement(Tokens.IdType, idType);

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_BrowseNames(Template template, Context context)
        {
            if (context.Target is not KeyValuePair<string, string> browseName ||
                browseName.Value == null)
            {
                return null;
            }

            return context.TemplateString;
        }

        private bool WriteTemplate_BrowseNames(Template template, Context context)
        {
            if (context.Target is not KeyValuePair<string, string> browseName ||
                browseName.Value == null)
            {
                return false;
            }

            template.AddReplacement(Tokens.SymbolicName, browseName.Key);
            template.AddReplacement(Tokens.BrowseName, browseName.Value);

            return template.WriteTemplate(context);
        }

        private bool WriteTemplate_CodeNamespaceUri(Template template, Context context)
        {
            if (context.Target is not string uri)
            {
                return false;
            }

            for (int ii = 0; ii < m_model.Namespaces.Length; ii++)
            {
                Namespace ns = m_model.Namespaces[ii];

                if (uri != ns.Value && uri != ns.XmlNamespace)
                {
                    continue;
                }

                template.AddReplacement(Tokens.NamespaceUri, uri);
                template.AddReplacement(Tokens.CodeName, ns.Prefix);

                if (uri != ns.XmlNamespace)
                {
                    template.AddReplacement(Tokens.Name, ns.Name);
                }
                else
                {
                    template.AddReplacement(Tokens.Name, ns.Name + "Xsd");
                }
            }

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_NamespaceImports(Template template, Context context)
        {
            if (context.Target is not Namespace ns)
            {
                return null;
            }

            if (ns.Value == m_model.TargetNamespace)
            {
                return null;
            }

            if (ns.FilePath == null && ns.Value != Namespaces.OpcUa)
            {
                return null;
            }

            string externalPrefix = m_model.Namespaces.GetNamespacePrefix(ns.Value);

            template.WriteNextLine(context.Prefix);
            template.Write("using {0};", externalPrefix);

            return null;
        }

        private string LoadTemplate_ListOfTypes(Template template, Context context)
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
                            return CodeTemplateStrings.DataTypes_Union_cs;
                        }

                        if (datatype.HasFields && datatype.Fields.Any(x => x.IsOptional))
                        {
                            if (datatype.GetBaseClassName(m_model.Namespaces) != "IEncodeable")
                            {
                                return CodeTemplateStrings.DataTypes_DerivedClassWithOptionalFields_cs;
                            }

                            return CodeTemplateStrings.DataTypes_ClassWithOptionalFields_cs;
                        }

                        if (datatype.GetBaseClassName(m_model.Namespaces) == "IEncodeable")
                        {
                            return CodeTemplateStrings.DataTypes_Class_cs;
                        }

                        return CodeTemplateStrings.DataTypes_DerivedClass_cs;
                    case BasicDataType.Enumeration:
                        var baseType = datatype.BaseTypeNode as DataTypeDesign;

                        if (baseType?.SymbolicId == new XmlQualifiedName("OptionSet", Namespaces.OpcUa))
                        {
                            return CodeTemplateStrings.DataTypes_DerivedClass_cs;
                        }

                        return CodeTemplateStrings.DataTypes_Enumeration_cs;
                    default:
                        if (datatype.IsOptionSet)
                        {
                            return CodeTemplateStrings.DataTypes_Enumeration_cs;
                        }

                        return null;
                }
            }

            // do not produce built in types.
            if (node.NumericId < 256 && node.SymbolicId.Namespace == Namespaces.OpcUa)
            {
                return null;
            }

            if (context.Target is ObjectTypeDesign objectType)
            {
                return CodeTemplateStrings.ObjectType_cs;
            }

            if (context.Target is VariableTypeDesign variableType)
            {
                return CodeTemplateStrings.VariableType_cs;
            }

            if (context.Target is MethodDesign method && method.HasArguments)
            {
                return CodeTemplateStrings.MethodType_cs;
            }

            return null;
        }

        private bool WriteTemplate_ListOfTypes(Template template, Context context)
        {
            // handle object or variable type.

            if (context.Target is not NodeDesign node)
            {
                return false;
            }

            Array children = GetFields(node);

            template.AddReplacement(Tokens.NodeClass, node.GetNodeClassString());
            template.AddReplacement(
                Tokens.Description,
                node.Description != null ? node.Description.Value : string.Empty);
            template.AddReplacement(Tokens.Encoding, UseXmlInitializers ? "Xml" : "Binary");
            template.AddReplacement(Tokens.TypeName, node.SymbolicName.Name);
            template.AddReplacement(
                Tokens.NamespaceUri,
                m_model.Namespaces.GetConstantSymbolForNamespace(node.SymbolicName.Namespace));
            template.AddReplacement(
                Tokens.NamespacePrefix,
                m_model.Namespaces.GetNamespacePrefix(node.SymbolicId.Namespace));
            template.AddReplacement(
                Tokens.XmlNamespaceUri,
                m_model.Namespaces.GetConstantForXmlNamespace(node.SymbolicId.Namespace));

            template.AddReplacement(
                Tokens.BrowseName,
                node.SymbolicName.Name);
            template.AddReplacement(
                Tokens.BrowseNameNamespacePrefix,
                m_model.Namespaces.GetNamespacePrefix(node.SymbolicName.Namespace));
            template.AddReplacement(
                Tokens.BrowseNameNamespaceUri,
                m_model.Namespaces.GetConstantSymbolForNamespace(node.SymbolicName.Namespace));

            var type = context.Target as TypeDesign;

            if (type != null)
            {
                template.AddReplacement(
                    Tokens.ClassName,
                    type.ClassName);
                template.AddReplacement(
                    Tokens.BaseType,
                    type.GetBaseClassName(m_model.Namespaces));
                template.AddReplacement(
                    Tokens.BaseTypeNamespacePrefix,
                    m_model.Namespaces.GetNamespacePrefix(type.BaseTypeNode.SymbolicId.Namespace));
                template.AddReplacement(
                    Tokens.BaseTypeNamespaceUri,
                    m_model.Namespaces.GetConstantSymbolForNamespace(type.BaseTypeNode.SymbolicId.Namespace));
                template.AddReplacement(
                    Tokens.BaseClassName,
                    type.BaseTypeNode.FixClassName());
            }

            if (context.Target is MethodDesign method)
            {
                template.AddReplacement(
                    Tokens.ClassName,
                    method.GetClassName(m_model.TargetNamespace, m_model.Namespaces));

                template.AddTemplate(
                    Tokens.ListOfInputArguments,
                    null,
                    method.InputArguments,
                    LoadTemplate_ListOfInputArguments,
                    null);

                template.AddTemplate(
                    Tokens.OnCallDeclaration,
                    null,
                    new MethodDesign[] { method },
                    LoadTemplate_OnCallDeclaration,
                    null);

                template.AddTemplate(
                    Tokens.OnCallAsyncDeclaration,
                    null,
                    new MethodDesign[] { method },
                    LoadTemplate_OnCallAsyncDeclaration,
                    null);

                template.AddTemplate(
                    Tokens.OnCallImplementation,
                    null,
                    new MethodDesign[] { method },
                    LoadTemplate_OnCallImplementation,
                    null);

                template.AddTemplate(
                    Tokens.OnCallAsyncImplementation,
                    null,
                    new MethodDesign[] { method },
                    LoadTemplate_OnCallAsyncImplementation,
                    null);

                template.AddTemplate(
                    Tokens.ListOfOutputDeclarations,
                    null,
                    method.OutputArguments,
                    LoadTemplate_ListOfOutputDeclarations,
                    null);

                template.AddTemplate(
                    Tokens.ListOfOutputArgumentsFromResult,
                    null,
                    method.OutputArguments,
                    LoadTemplate_ListOfOutputArgumentsFromResult,
                    null);

                template.AddTemplate(
                    Tokens.ListOfOutputArguments,
                    null,
                    method.OutputArguments,
                    LoadTemplate_ListOfOutputArguments,
                    null);

                template.AddTemplate(
                    Tokens.ListOfResultProperties,
                    null,
                    method.OutputArguments,
                    LoadTemplate_ListOfResultProperties,
                    null);
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

                // too much autogenerated code is broken.
                // template.AddReplacement(Tokens.IsAbstract, (dataType.IsAbstract) ? "abstract " : "");
                template.AddReplacement(Tokens.IsAbstract, dataType.IsAbstract ? string.Empty : string.Empty);

                if (!dataType.IsOptionSet)
                {
                    template.AddReplacement(Tokens.Flags, string.Empty);
                    template.AddReplacement(Tokens.BasicType, string.Empty);
                }
                else
                {
                    template.AddReplacement(Tokens.Flags, "[Flags]");
                    template.AddReplacement(Tokens.BasicType, CoreUtils.Format(" : {0}", dataType.BaseType.Name));

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

                        foreach (Parameter parameter in children)
                        {
                            clone.Add(parameter);
                        }
                    }

                    children = clone.ToArray();
                }

                Dictionary<string, string> encodings = new()
                {
                    { Tokens.BinaryEncodingId,
                        CoreUtils.Format("{0}_Encoding_DefaultBinary", node.SymbolicName.Name) },
                    { Tokens.XmlEncodingId,
                        CoreUtils.Format("{0}_Encoding_DefaultXml", node.SymbolicName.Name) },
                    { Tokens.JsonEncodingId,
                        CoreUtils.Format("{0}_Encoding_DefaultJson", node.SymbolicName.Name) }
                };
                foreach (KeyValuePair<string, string> kv in encodings)
                {
                    bool isEncodingPartOfModel = m_model.Items.Any(x =>
                        x.SymbolicId.Name == kv.Value &&
                        x.SymbolicId.Namespace == node.SymbolicName.Namespace);
                    if (!isEncodingPartOfModel)
                    {
                        template.AddReplacement(
                            kv.Key,
                            "NodeId.Null");
                    }
                    else
                    {
                        template.AddReplacement(
                            kv.Key,
                            CoreUtils.Format("ObjectIds.{0}", kv.Value));
                    }
                }

                template.AddTemplate(
                    Tokens.ListOfSwitchFields,
                    null,
                    children,
                    LoadTemplate_ListOfSwitchFields,
                    null);

                template.AddTemplate(
                    Tokens.ListOfEncodingMaskFields,
                    null,
                    completeListOfFields?.ToArray() ?? children,
                    LoadTemplate_ListOfEncodingMaskFields,
                    null);

                template.AddTemplate(
                    Tokens.ListOfEncodedFields,
                    null,
                    children,
                    LoadTemplate_ListOfEncodedFields,
                    null);

                template.AddTemplate(
                    Tokens.ListOfDecodedFields,
                    null,
                    children,
                    LoadTemplate_ListOfDecodedFields,
                    null);

                template.AddTemplate(
                    Tokens.ListOfComparedFields,
                    null,
                    children,
                    LoadTemplate_ListOfComparedFields,
                    null);

                template.AddTemplate(
                    Tokens.ListOfClonedFields,
                    null,
                    children,
                    LoadTemplate_ListOfClonedFields,
                    null);

                template.AddTemplate(
                    Tokens.CollectionClass,
                    CodeTemplateStrings.DataTypes_CollectionClass_cs,
                    new DataTypeDesign[] { dataType },
                    LoadTemplate_CollectionClass,
                    WriteTemplate_CollectionClass);
            }

            if (context.Target is ObjectTypeDesign objectType)
            {
                template.AddReplacement(Tokens.BaseT, string.Empty);
                template.AddReplacement(Tokens.IsAbstract,
                    CodeGeneration.GetBooleanString(objectType.IsAbstract));
                template.AddReplacement(Tokens.EventNotifier,
                    CodeGeneration.GetEventNotifierString(objectType.SupportsEvents));
            }

            if (context.Target is VariableTypeDesign variableType)
            {
                BasicDataType basicType = variableType.DataTypeNode.BasicDataType;

                // a hack to avoid breaking existing code when the ValueRank was set correctly to Any.
                if (variableType.SymbolicName.Name == "TwoStateDiscreteType")
                {
                    variableType.ValueRank = ValueRank.Scalar;
                }

                if (!variableType.DataTypeNode.IsRequiredParameterInTemplates(variableType.ValueRank))
                {
                    template.AddReplacement(Tokens.BaseT, string.Empty);
                }
                else
                {
                    string parameter = GetTemplateParameter(variableType);

                    if (parameter == "<T>" && variableType.ValueRank != ValueRank.Scalar)
                    {
                        parameter = "<Variant>";
                    }

                    template.AddReplacement(Tokens.BaseT, GetTemplateParameter(variableType));
                }

                // hack to keep the default value as Scalar after code was fixed to correctly set it to Any.

                string valueRank = variableType.ValueRank.GetValueRankString(variableType.ArrayDimensions);

                if (variableType.ValueRank == ValueRank.ScalarOrArray)
                {
                    for (TypeDesign baseType = variableType.BaseTypeNode;
                        baseType != null;
                        baseType = baseType.BaseTypeNode)
                    {
                        if (baseType.SymbolicId == new XmlQualifiedName("DataItemType", Namespaces.OpcUa))
                        {
                            valueRank = $"ValueRanks.{ValueRank.Scalar}";
                        }
                    }
                }

                template.AddReplacement(Tokens.DefaultValue,
                    variableType.DataTypeNode.GetDefaultDotNetValue(
                        variableType.ValueRank,
                        variableType.DefaultValue,
                        variableType.DecodedValue,
                        false,
                        m_model.TargetNamespace,
                        m_model.Namespaces,
                        m_context));
                template.AddReplacement(Tokens.ValueRank, valueRank);
                template.AddReplacement(
                    Tokens.ArrayDimensions,
                    variableType.ValueRank.GetArrayDimensionsString(variableType.ArrayDimensions));
                template.AddReplacement(
                    Tokens.IsAbstract,
                    CodeGeneration.GetBooleanString(variableType.IsAbstract));
                template.AddReplacement(
                    Tokens.AccessLevel,
                    variableType.AccessLevel.GetAccessLevelString());
                template.AddReplacement(
                    Tokens.MinimumSamplingInterval,
                    CodeGeneration.GetMinimumSamplingIntervalString(variableType.MinimumSamplingInterval));
                template.AddReplacement(
                    Tokens.Historizing,
                    CodeGeneration.GetBooleanString(variableType.Historizing));

                template.AddReplacement(
                    Tokens.DataType,
                    variableType.DataTypeNode.SymbolicName.Name);
                template.AddReplacement(
                    Tokens.DataTypeNamespacePrefix,
                    m_model.Namespaces.GetNamespacePrefix(variableType.DataTypeNode.SymbolicId.Namespace));
                template.AddReplacement(
                    Tokens.DataTypeNamespaceUri,
                    m_model.Namespaces.GetConstantSymbolForNamespace(variableType.DataTypeNode.SymbolicId.Namespace));

                template.AddTemplate(
                        Tokens.TypedVariableType,
                        CodeTemplateStrings.TypedVariableType_cs,
                        new VariableTypeDesign[] { variableType },
                        LoadTemplate_TypedVariableType,
                        WriteTemplate_TypedVariableType);

                template.AddTemplate(
                    Tokens.VariableTypeValue,
                    CodeTemplateStrings.VariableTypeValue_cs,
                    new VariableTypeDesign[] { variableType },
                    LoadTemplate_VariableTypeValue,
                    WriteTemplate_VariableTypeValue);
            }

            template.AddTemplate(
                Tokens.InitializationStringForType, // TODO: Do we need this - it is not referenced in any template?
                null,
                new NodeDesign[] { node },
                LoadTemplate_InitializationString,
                null);

            template.AddTemplate(
                Tokens.InitializeOptionalChildren,
                CodeTemplateStrings.InitializeOptionalChild_cs,
                children,
                LoadTemplate_InitializeOptionalChildren,
                WriteTemplate_InitializeOptionalChildren);

            template.AddTemplate(
                Tokens.InitializationString,
                null,
                new NodeDesign[] { node },
                LoadTemplate_InitializationString,
                null);

            template.AddTemplate(
                Tokens.ListOfFieldsForType, // TODO: Do we need this - it is not referenced in any template?
                null,
                children,
                LoadTemplate_ListOfFields,
                null);

            template.AddTemplate(
                Tokens.ListOfFieldInitializers,
                null,
                children,
                LoadTemplate_ListOfFieldInitializers,
                null);

            template.AddTemplate(
                Tokens.ListOfFields,
                null,
                children,
                LoadTemplate_ListOfFields,
                null);

            template.AddTemplate(
                Tokens.ListOfPropertiesForType, // TODO: Do we need this - it is not referenced in any template?
                CodeTemplateStrings.Property_cs,
                children,
                LoadTemplate_ListOfProperties,
                WriteTemplate_ListOfProperties);

            template.AddTemplate(
                Tokens.ListOfProperties,
                CodeTemplateStrings.Property_cs,
                children,
                LoadTemplate_ListOfProperties,
                WriteTemplate_ListOfProperties);

            template.AddTemplate(
                Tokens.FindChildMethodsForType, // TODO: Do we need this - it is not referenced in any template?
                CodeTemplateStrings.FindChildMethods_cs,
                new NodeDesign[] { type },
                LoadTemplate_FindChildMethods,
                WriteTemplate_FindChildMethods);

            template.AddTemplate(
                Tokens.FindChildMethods,
                CodeTemplateStrings.FindChildMethods_cs,
                new NodeDesign[] { type },
                LoadTemplate_FindChildMethods,
                WriteTemplate_FindChildMethods);

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_InitializationString(Template template, Context context)
        {
            string resourceName = null;
            if (context.Target is TypeDesign type)
            {
                bool forInstance = !context.Token.EndsWith("ForType", StringComparison.Ordinal);
                resourceName = AddInitializer(CoreUtils.Format(
                   "{0}",
                    type.SymbolicName.Name), type, forInstance);

                // output initializers for optional components.
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

                            string childResourceName = AddInitializer(CoreUtils.Format(
                                 "{0}{1}",
                                 type.SymbolicName.Name,
                                 current.Instance.SymbolicName.Name), current.Instance, false);

                            if (childResourceName == null)
                            {
                                // Should not happen
                                continue;
                            }

                            template.WriteNextLine(context.Prefix);
                            template.Write(
                                "private static ReadOnlySpan<byte> {0}_InitializationString => Initializers.{1};",
                                current.Instance.SymbolicName.Name,
                                childResourceName);
                            template.WriteNextLine(string.Empty);
                            break;
                        }
                    }
                }
            }

            else if (context.Target is MethodDesign method)
            {
                resourceName = AddInitializer(CoreUtils.Format(
                    "{0}",
                    method.SymbolicName.Name), method, false);
            }

            if (resourceName == null)
            {
                return null;
            }

            template.WriteNextLine(context.Prefix);
            template.Write("private static ReadOnlySpan<byte> InitializationString => Initializers.");
            template.Write(resourceName);
            template.Write(";");

            return context.TemplateString;
        }

        private string LoadTemplate_TypedVariableType(Template template, Context context)
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

        private bool WriteTemplate_TypedVariableType(Template template, Context context)
        {
            if (context.Target is not VariableTypeDesign type)
            {
                return false;
            }

            template.WriteLine(string.Empty);

            template.AddReplacement(Tokens.NodeClass, type.GetNodeClassString());
            template.AddReplacement(Tokens.ClassName, type.ClassName);
            template.AddReplacement(Tokens.TypeName, type.SymbolicName.Name);
            template.AddReplacement(Tokens.BrowseName, type.SymbolicName.Name);

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_VariableTypeValue(Template template, Context context)
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

        private bool WriteTemplate_VariableTypeValue(Template template, Context context)
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

            template.WriteLine(string.Empty);

            template.AddReplacement(Tokens.ClassName, type.ClassName);
            template.AddReplacement(Tokens.DataType, type.DataTypeNode.GetDotNetTypeName(
                ValueRank.Scalar,
                m_model.TargetNamespace,
                m_model.Namespaces,
                nullable: false));

            template.AddTemplate(
                Tokens.ListOfChildInitializers,
                null,
                fields,
                WriteTemplate_VariableTypeValueInitializers,
                null);

            template.AddTemplate(
                Tokens.ListOfUpdateChildrenChangeMasks,
                null,
                fields,
                WriteTemplate_VariableTypeValueUpdateChildrenChangeMasks,
                null);

            template.AddTemplate(
                Tokens.ListOfChildMethods,
                CodeTemplateStrings.VariableTypeValueField_cs,
                fields,
                null,
                WriteTemplate_VariableTypeValueField);

            return template.WriteTemplate(context);
        }

        private string WriteTemplate_VariableTypeValueInitializers(Template template, Context context)
        {
            if (context.Target is not KeyValuePair<string, Parameter> field ||
                field.Value == null)
            {
                return null;
            }

            if (!context.FirstInList)
            {
                template.WriteNextLine(context.Prefix);
            }

            string name = field.Key;
            // string path = field.Key.Replace('_', '.');
            string path = field.Key;

            template.WriteNextLine(context.Prefix);
            template.Write("instance = m_variable.{0};", path);

            template.WriteNextLine(context.Prefix);
            template.Write("if (instance != null)");

            template.WriteNextLine(context.Prefix);
            template.Write("{");

            template.WriteNextLine(context.Prefix);
            template.Write("    instance.OnReadValue = OnRead_{0};", name);

            template.WriteNextLine(context.Prefix);
            template.Write("    instance.OnWriteValue = OnWrite_{0};", name);

            template.WriteNextLine(context.Prefix);
            template.Write("    updateList.Add(instance);");

            template.WriteNextLine(context.Prefix);
            template.Write("}");

            return context.TemplateString;
        }

        private string WriteTemplate_VariableTypeValueUpdateChildrenChangeMasks(Template template, Context context)
        {
            if (context.Target is not KeyValuePair<string, Parameter> field ||
                field.Value == null)
            {
                return null;
            }

            if (!context.FirstInList)
            {
                template.WriteNextLine(context.Prefix);
            }

            // string path = field.Key.Replace('_', '.');
            string path = field.Key;

            template.WriteNextLine(context.Prefix);
            template.Write(
                "if (!CoreUtils.IsEqual(m_value.{0}, newValue.{0})) UpdateChildVariableStatus(m_variable.{0}, ref statusCode, ref timestamp);",
                path);

            return context.TemplateString;
        }

        private bool WriteTemplate_VariableTypeValueField(Template template, Context context)
        {
            if (context.Target is not KeyValuePair<string, Parameter> field ||
                field.Value == null)
            {
                return false;
            }

            template.AddReplacement(Tokens.ChildName, field.Key);
            // template.AddReplacement(Tokens.ChildPath, field.Value.Key.Replace('_', '.'));
            template.AddReplacement(Tokens.ChildPath, field.Key);
            template.AddReplacement(Tokens.ChildDataType,
                field.Value.DataTypeNode.GetDotNetTypeName(
                    field.Value.ValueRank,
                    m_model.TargetNamespace,
                    m_model.Namespaces,
                    nullable: false));

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_CollectionClass(Template template, Context context)
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

        private bool WriteTemplate_CollectionClass(Template template, Context context)
        {
            if (context.Target is not DataTypeDesign dataType)
            {
                return false;
            }

            template.WriteLine(string.Empty);
            template.AddReplacement(Tokens.XmlNamespaceUri, m_model.Namespaces.GetConstantForXmlNamespace(dataType.SymbolicId.Namespace));
            template.AddReplacement(Tokens.BrowseName, dataType.SymbolicName.Name);

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_ListOfFields(Template template, Context context)
        {
            if (context.Target is not InstanceDesign instance)
            {
                if (context.Target is not Parameter field)
                {
                    return null;
                }

                template.WriteNextLine(context.Prefix);
                template.Write("private {0} {1};", field.DataTypeNode.GetDotNetTypeName(
                    field.ValueRank,
                    m_model.TargetNamespace,
                    m_model.Namespaces,
                    nullable: true),
                    field.GetChildFieldName());

                return context.TemplateString;
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

            bool forInstance = !context.Token.EndsWith("ForType", StringComparison.Ordinal);
            if (forInstance)
            {
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
            }

            if (instance.IsBuiltInProperty())
            {
                return null;
            }

            template.WriteNextLine(context.Prefix);
            template.Write(
                "private {0} {1};",
                instance.GetClassName(m_model.TargetNamespace, m_model.Namespaces),
                instance.GetChildFieldName());

            return context.TemplateString;
        }

        private string LoadTemplate_ListOfSwitchFields(Template template, Context context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            var dataType = (DataTypeDesign)field.Parent;

            int index = context.Index + 1;

            template.WriteNextLine(context.Prefix);
            template.Write($"{field.Name} = {index}{(index == dataType.Fields.Length ? string.Empty : ",")}");

            return context.TemplateString;
        }

        private string LoadTemplate_ListOfEncodingMaskFields(Template template, Context context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            int index = context.Index;

            if (field.IsOptional)
            {
                //int mask = 0;
                //foreach (var indexField in dataType.Fields)
                //{
                //    if (indexField == field || mask >= sizeof(UInt32) * 8)
                //    {
                //        break;
                //    }
                //    if (indexField.IsOptional)
                //    {
                //        mask++;
                //    }
                //}

                template.WriteNextLine(context.Prefix);
                template.Write($"{field.Name} = 0x{1 << index:X},");
            }

            return context.TemplateString;
        }

        private string LoadTemplate_ListOfEncodedFields(Template template, Context context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            var dataType = (DataTypeDesign)field.Parent;
            bool isUnion = dataType.IsUnion;

            template.WriteNextLine(context.Prefix);

            if (isUnion)
            {
                template.Write($$"""case {{dataType.ClassName}}Fields.{{field.Name}}: { """);
            }

            if (field.IsOptional)
            {
                template.Write($"if ((EncodingMask & (uint){dataType.ClassName}Fields.{field.Name}) != 0) ");
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
                                m_model.TargetNamespace,
                                m_model.Namespaces,
                                nullable: false);
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
                            m_model.TargetNamespace,
                            m_model.Namespaces,
                            nullable: false);
                        template.Write(
                            "encoder.WriteEnumeratedArray({0}, {1}.ToArray(), typeof({2}));",
                            fieldName,
                            field.Name,
                            elementName);
                        if (isUnion)
                        {
                            template.Write(" break; }");
                        }

                        return context.TemplateString;
                    }

                    break;
                case BasicDataType.UserDefined:
                    if (field.AllowSubTypes)
                    {
                        if (field.ValueRank == ValueRank.Array)
                        {
                            template.Write(
                                "encoder.WriteExtensionObjectArray({0}, ExtensionObjectCollection.ToExtensionObjects({1}));",
                                fieldName,
                                field.Name);

                            if (isUnion)
                            {
                                template.Write(" break; }");
                            }

                            return context.TemplateString;
                        }

                        if (field.ValueRank == ValueRank.Scalar)
                        {
                            template.Write(
                                "encoder.WriteExtensionObject({0}, new ExtensionObject({1}));",
                                fieldName,
                                field.Name);

                            if (isUnion)
                            {
                                template.Write(" break; }");
                            }

                            return context.TemplateString;
                        }

                        template.Write("encoder.WriteVariant({0}, {1});", fieldName, field.Name);

                        if (isUnion)
                        {
                            template.Write(" break; }");
                        }

                        return context.TemplateString;
                    }

                    functionName = "Encodeable";
                    elementName = field.DataTypeNode.GetDotNetTypeName(
                        ValueRank.Scalar,
                        m_model.TargetNamespace,
                        m_model.Namespaces,
                        nullable: false);

                    if (field.ValueRank == ValueRank.Array)
                    {
                        template.Write("encoder.WriteEncodeableArray({0}, {1}.ToArray(), typeof({2}));",
                            fieldName,
                            field.Name,
                            elementName);

                        if (isUnion)
                        {
                            template.Write(" break; }");
                        }

                        return context.TemplateString;
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

            template.Write($"encoder.Write{functionName}({fieldName}, {field.Name}");

            if (elementName != null)
            {
                template.Write($", typeof({elementName})");
            }

            template.Write(");");

            if (isUnion)
            {
                template.Write(" break; }");
            }

            return context.TemplateString;
        }

        private string LoadTemplate_ListOfDecodedFields(Template template, Context context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            var dataType = (DataTypeDesign)field.Parent;
            bool isUnion = dataType.IsUnion;

            template.WriteNextLine(context.Prefix);

            if (isUnion)
            {
                template.Write($$"""case {{dataType.ClassName}}Fields.{{field.Name}}: { """);
            }

            if (field.IsOptional)
            {
                template.Write(
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
                                m_model.TargetNamespace,
                                m_model.Namespaces,
                                nullable: false);
                            break;
                        }

                        functionName = ((DataTypeDesign)field.DataTypeNode.BaseTypeNode).BasicDataType.ToString();
                        break;
                    }

                    functionName = "Enumerated";
                    elementName = field.DataTypeNode.GetDotNetTypeName(
                        ValueRank.Scalar,
                        m_model.TargetNamespace,
                        m_model.Namespaces,
                        nullable: false);
                    break;
                case BasicDataType.UserDefined:
                    if (field.AllowSubTypes)
                    {
                        template.Write($"{valueName} = ");
                        elementName = field.DataTypeNode.GetDotNetTypeName(
                            ValueRank.Scalar,
                            m_model.TargetNamespace,
                            m_model.Namespaces,
                            nullable: false);

                        if (field.ValueRank == ValueRank.Array)
                        {
                            template.Write($"({elementName}[])ExtensionObject.ToArray(decoder.ReadExtensionObjectArray({fieldName}), typeof({elementName}));");

                            if (isUnion)
                            {
                                template.Write(" break; }");
                            }

                            return context.TemplateString;
                        }

                        if (field.ValueRank == ValueRank.Scalar)
                        {
                            template.Write($"({elementName})ExtensionObject.ToEncodeable(decoder.ReadExtensionObject({fieldName}));");

                            if (isUnion)
                            {
                                template.Write(" break; }");
                            }

                            return context.TemplateString;
                        }

                        template.Write($"decoder.ReadVariant({fieldName});");

                        if (isUnion)
                        {
                            template.Write(" break; }");
                        }

                        return context.TemplateString;
                    }

                    functionName = "Encodeable";
                    elementName = field.DataTypeNode.GetDotNetTypeName(
                        ValueRank.Scalar,
                        m_model.TargetNamespace,
                        m_model.Namespaces,
                        nullable: false);
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

            template.Write("{0} = ", valueName);

            if (elementName != null)
            {
                if (field.ValueRank == ValueRank.Array)
                {
                    template.Write("({0}Collection)", elementName);
                }
                else
                {
                    template.Write("({0})", elementName);
                }

                template.Write($"decoder.Read{functionName}({fieldName}, typeof({elementName}));");
            }
            else
            {
                template.Write($"decoder.Read{functionName}({fieldName});");
            }

            if (isUnion)
            {
                template.Write(" break; }");
            }

            return context.TemplateString;
        }

        private string LoadTemplate_ListOfComparedFields(Template template, Context context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            var dataType = field.Parent as DataTypeDesign;

            template.WriteNextLine(context.Prefix);

            if (dataType.IsUnion)
            {
                template.Write($$"""case {{dataType.ClassName}}Fields.{{field.Name}}: { """);
            }

            if (field.IsOptional)
            {
                template.Write($"if ((EncodingMask & (uint){dataType.ClassName}Fields.{field.Name}) != 0) ");
            }

            template.Write("if (!CoreUtils.IsEqual({0}, value.{0})) return false;", field.GetChildFieldName());

            if (dataType.IsUnion)
            {
                template.Write(" break; }");
            }

            return context.TemplateString;
        }

        private string LoadTemplate_ListOfClonedFields(Template template, Context context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            var dataType = field.Parent as DataTypeDesign;

            template.WriteNextLine(context.Prefix);

            if (dataType.IsUnion)
            {
                template.Write($$"""case {{dataType.ClassName}}Fields.{{field.Name}}: { """);
            }

            if (field.IsOptional)
            {
                template.Write($"if ((EncodingMask & (uint){dataType.ClassName}Fields.{field.Name}) != 0) ");
            }

            template.Write("clone.{0} = ({1})CoreUtils.Clone(this.{0});",
                field.GetChildFieldName(),
                field.DataTypeNode.GetDotNetTypeName(
                    field.ValueRank,
                    m_model.TargetNamespace,
                    m_model.Namespaces,
                    nullable: true));

            if (dataType.IsUnion)
            {
                template.Write(" break; }");
            }

            return context.TemplateString;
        }

        private string LoadTemplate_ListOfInputArguments(Template template, Context context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            if (context.Index == 0)
            {
                template.WriteNextLine(string.Empty);
            }

            template.WriteNextLine(context.Prefix);

            string format = "{1} {0} = ({1})_inputArguments[{2}];";

            if (field.DataTypeNode.BasicDataType == BasicDataType.UserDefined)
            {
                if (field.ValueRank == ValueRank.Scalar)
                {
                    format = "{1} {0} = ({1})ExtensionObject.ToEncodeable((ExtensionObject)_inputArguments[{2}]);";
                }
                else
                {
                    format = "{1} {0} = ({1})ExtensionObject.ToArray(_inputArguments[{2}], typeof(" +
                        field.DataTypeNode.GetMethodArgumentDotNetType(
                            ValueRank.Scalar,
                            m_model.TargetNamespace,
                            m_model.Namespaces,
                            false) +
                        "));";
                }
            }

            template.Write(
                format,
                field.GetChildFieldName()[2..],
                field.DataTypeNode.GetMethodArgumentDotNetType(
                    field.ValueRank,
                    m_model.TargetNamespace,
                    m_model.Namespaces,
                    false),
                context.Index);

            return context.TemplateString;
        }

        private string LoadTemplate_ListOfOutputDeclarations(Template template, Context context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            if (context.Index == 0)
            {
                template.WriteNextLine(string.Empty);
            }

            template.WriteNextLine(context.Prefix);

            template.Write(
                "{1} {0} = ({1})_outputArguments[{2}];",
                field.GetChildFieldName()[2..],
                field.DataTypeNode.GetMethodArgumentDotNetType(
                    field.ValueRank,
                    m_model.TargetNamespace,
                    m_model.Namespaces,
                    field.IsOptional),
                context.Index);

            return context.TemplateString;
        }

        private string LoadTemplate_ListOfOutputArguments(Template template, Context context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            if (context.Index == 0)
            {
                template.WriteNextLine(string.Empty);
            }

            template.WriteNextLine(context.Prefix);

            template.Write(
                "_outputArguments[{1}] = {0};",
                field.GetChildFieldName()[2..],
                context.Index);

            return context.TemplateString;
        }

        private string LoadTemplate_OnCallDeclaration(Template template, Context context)
        {
            if (context.Target is not MethodDesign method)
            {
                return null;
            }

            template.WriteNextLine(context.Prefix);
            template.Write("ISystemContext _context,");

            template.WriteNextLine(context.Prefix);
            template.Write("MethodState _method,");

            template.WriteNextLine(context.Prefix);
            template.Write("NodeId _objectId");

            if (method.InputArguments != null)
            {
                for (int ii = 0; ii < method.InputArguments.Length; ii++)
                {
                    Parameter argument = method.InputArguments[ii];

                    template.Write(",");
                    template.WriteNextLine(context.Prefix);
                    template.Write("{1} {0}", argument.GetChildFieldName()[2..],
                        argument.DataTypeNode.GetMethodArgumentDotNetType(
                            argument.ValueRank,
                            m_model.TargetNamespace,
                            m_model.Namespaces,
                            argument.IsOptional));
                }
            }

            if (method.OutputArguments != null)
            {
                for (int ii = 0; ii < method.OutputArguments.Length; ii++)
                {
                    Parameter argument = method.OutputArguments[ii];

                    template.Write(",");
                    template.WriteNextLine(context.Prefix);
                    template.Write("ref {1} {0}", argument.GetChildFieldName()[2..],
                        argument.DataTypeNode.GetMethodArgumentDotNetType(
                            argument.ValueRank,
                            m_model.TargetNamespace,
                            m_model.Namespaces,
                            argument.IsOptional));
                }
            }

            template.Write(");");

            return context.TemplateString;
        }

        private string LoadTemplate_OnCallAsyncDeclaration(Template template, Context context)
        {
            if (context.Target is not MethodDesign method)
            {
                return null;
            }

            template.WriteNextLine(context.Prefix);
            template.Write("ISystemContext _context,");

            template.WriteNextLine(context.Prefix);
            template.Write("MethodState _method,");

            template.WriteNextLine(context.Prefix);
            template.Write("NodeId _objectId");

            if (method.InputArguments != null)
            {
                for (int ii = 0; ii < method.InputArguments.Length; ii++)
                {
                    Parameter argument = method.InputArguments[ii];

                    template.Write(",");
                    template.WriteNextLine(context.Prefix);
                    template.Write("{1} {0}", argument.GetChildFieldName()[2..],
                        argument.DataTypeNode.GetMethodArgumentDotNetType(
                            argument.ValueRank,
                            m_model.TargetNamespace,
                            m_model.Namespaces,
                            argument.IsOptional));
                }
            }

            //if (method.OutputArguments != null)
            //{
            //    for (int ii = 0; ii < method.OutputArguments.Length; ii++)
            //    {
            //        Parameter argument = method.OutputArguments[ii];
            //        template.Write(",");
            //        template.WriteNextLine(context.Prefix);
            //        template.Write("ref {1} {0}", GetChildFieldName(argument).Substring(2),
            //            GetMethodArgumentType(
            //                argument.DataTypeNode,
            //                argument.ValueRank,
            //                m_model.TargetNamespace,
            //                m_model.Namespaces));
            //    }
            //}

            template.Write(",");
            template.WriteNextLine(context.Prefix);
            template.Write("CancellationToken cancellationToken");

            template.Write(");");

            return context.TemplateString;
        }

        private string LoadTemplate_ListOfOutputArgumentsFromResult(Template template, Context context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            if (context.Index == 0)
            {
                template.WriteNextLine(string.Empty);
            }

            template.WriteNextLine(context.Prefix);

            string fieldName = field.GetChildFieldName();

            template.Write(
                "_outputArguments[{1}] = _result.{2}{0};",
                fieldName[3..],
                context.Index,
                fieldName.Substring(2, 1).ToUpperInvariant());

            return context.TemplateString;
        }

        private string LoadTemplate_ListOfResultProperties(Template template, Context context)
        {
            if (context.Target is not Parameter field)
            {
                return null;
            }

            template.WriteNextLine(context.Prefix);

            string fieldName = field.GetChildFieldName();

            template.Write(
               "public {1} {2}{0} {{ get; set; }}",
               fieldName[3..],
               field.DataTypeNode.GetMethodArgumentDotNetType(
                   field.ValueRank,
                   m_model.TargetNamespace,
                   m_model.Namespaces,
                   field.IsOptional),
               fieldName.Substring(2, 1).ToUpperInvariant());

            return context.TemplateString;
        }

        private string LoadTemplate_OnCallImplementation(Template template, Context context)
        {
            if (context.Target is not MethodDesign method)
            {
                return null;
            }

            template.WriteNextLine(context.Prefix);
            template.Write("_result = OnCall(");

            template.WriteNextLine(context.Prefix);
            template.Write("    _context,");

            template.WriteNextLine(context.Prefix);
            template.Write("    this,");

            template.WriteNextLine(context.Prefix);
            template.Write("    _objectId");

            if (method.InputArguments != null)
            {
                for (int ii = 0; ii < method.InputArguments.Length; ii++)
                {
                    template.Write(",");
                    template.WriteNextLine(context.Prefix);
                    template.Write("    {0}", method.InputArguments[ii].GetChildFieldName()[2..]);
                }
            }

            if (method.OutputArguments != null)
            {
                for (int ii = 0; ii < method.OutputArguments.Length; ii++)
                {
                    template.Write(",");
                    template.WriteNextLine(context.Prefix);
                    template.Write("    ref {0}", method.OutputArguments[ii].GetChildFieldName()[2..]);
                }
            }

            template.Write(");");

            return context.TemplateString;
        }

        private string LoadTemplate_OnCallAsyncImplementation(Template template, Context context)
        {
            if (context.Target is not MethodDesign method)
            {
                return null;
            }

            template.WriteNextLine(context.Prefix);
            template.Write("_result = await OnCallAsync(");

            template.WriteNextLine(context.Prefix);
            template.Write("    _context,");

            template.WriteNextLine(context.Prefix);
            template.Write("    this,");

            template.WriteNextLine(context.Prefix);
            template.Write("    _objectId");

            if (method.InputArguments != null)
            {
                for (int ii = 0; ii < method.InputArguments.Length; ii++)
                {
                    template.Write(",");
                    template.WriteNextLine(context.Prefix);
                    template.Write("    {0}", method.InputArguments[ii].GetChildFieldName()[2..]);
                }
            }

            template.Write(",");
            template.WriteNextLine(context.Prefix);
            template.Write("    cancellationToken");

            template.Write(").ConfigureAwait(false);");
            return context.TemplateString;
        }

        private string LoadTemplate_ListOfFieldInitializers(Template template, Context context)
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
                m_model.TargetNamespace,
                m_model.Namespaces,
                m_context);

            template.WriteNextLine(context.Prefix);
            template.Write("{0} = {1};", field.GetChildFieldName(), value);

            return context.TemplateString;
        }

        private string LoadTemplate_InitializeOptionalChildren(Template template, Context context)
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

        private bool WriteTemplate_InitializeOptionalChildren(Template template, Context context)
        {
            if (context.Target is not InstanceDesign instance)
            {
                return template.WriteTemplate(context);
            }

            if (context.FirstInList)
            {
                template.WriteNextLine(string.Empty);
            }

            template.AddReplacement(Tokens.Encoding, UseXmlInitializers ? "Xml" : "Binary");
            template.AddReplacement(Tokens.ChildName, instance.SymbolicName.Name);

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_ListOfProperties(Template template, Context context)
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
                                return CodeTemplateStrings.DataTypes_Property_cs;
                            }

                            return CodeTemplateStrings.DataTypes_ArrayProperty_cs;
                        }

                        return CodeTemplateStrings.DataTypes_Property_cs;
                    }

                    return CodeTemplateStrings.DataTypes_EnumerationValue_cs;
                }

                return null; // Do not emit
            }

            if (instance.ModellingRule
                is ModellingRule.ExposesItsArray
                or ModellingRule.MandatoryPlaceholder
                or ModellingRule.OptionalPlaceholder)
            {
                return null;
            }

            bool forInstance = !context.Token.EndsWith("ForType", StringComparison.Ordinal);
            if (forInstance)
            {
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
            }

            if (instance.IsOverridden())
            {
                if (instance.IsOverriddenWithSameClass(m_model.TargetNamespace, m_model.Namespaces))
                {
                    return null;
                }
                return CodeTemplateStrings.PropertyOverride_cs;
            }

            if (instance.IsBuiltInProperty())
            {
                return null;
            }

            return context.TemplateString;
        }

        private bool WriteTemplate_ListOfProperties(Template template, Context context)
        {
            if (context.Target is not InstanceDesign instance)
            {
                if (context.Target is not Parameter field)
                {
                    return false;
                }

                bool valueType = false;

                switch (field.DataTypeNode.BasicDataType)
                {
                    case BasicDataType.String:
                    case BasicDataType.ByteString:
                    case BasicDataType.DiagnosticInfo:
                    case BasicDataType.ExpandedNodeId:
                    case BasicDataType.LocalizedText:
                    case BasicDataType.NodeId:
                    case BasicDataType.QualifiedName:
                    case BasicDataType.Guid:
                    case BasicDataType.XmlElement:
                    case BasicDataType.StatusCode:
                    case BasicDataType.Structure:
                    case BasicDataType.UserDefined:
                    case BasicDataType.DataValue:
                        valueType = false;
                        break;
                    default:
                        if (field.ValueRank != ValueRank.Scalar)
                        {
                            valueType = false;
                        }

                        break;
                }

                const bool emitDefaultValue = true;

                template.AddReplacement(
                    Tokens.Description,
                    field.Description != null ? field.Description.Value : string.Empty);
                template.AddReplacement(Tokens.BrowseName, field.Name);
                template.AddReplacement(Tokens.EnumerationName, field.EnsureUniqueEnumName());
                template.AddReplacement(Tokens.TypeName, field.DataTypeNode.GetDotNetTypeName(
                    field.ValueRank,
                    m_model.TargetNamespace,
                    m_model.Namespaces,
                    nullable: false));
                template.AddReplacement(Tokens.FieldName, field.GetChildFieldName());
                template.AddReplacement(Tokens.IsRequired, valueType ? "true" : "false");
                template.AddReplacement(Tokens.EmitDefaultValue, emitDefaultValue ? "true" : "false");
                template.AddReplacement(Tokens.FieldIndex, CoreUtils.Format("{0}", context.Index + 1));
                template.AddReplacement(Tokens.DefaultValue, field.DataTypeNode.GetDefaultDotNetValue(
                    field.ValueRank,
                    null,
                    null,
                    true,
                    m_model.TargetNamespace,
                    m_model.Namespaces,
                    m_context));
                template.AddReplacement(Tokens.Identifier, field.Identifier.ToString(CultureInfo.InvariantCulture));

                if (field.IdentifierInName)
                {
                    template.AddReplacement(Tokens.XmlIdentifier, field.Name);
                }
                else
                {
                    template.AddReplacement(Tokens.XmlIdentifier,
                        CoreUtils.Format("{0}_{1}", field.Name, field.Identifier));
                }

                if (field.Name == "NodeId" &&
                    context.Container is DataTypeDesign dt &&
                    dt.BaseTypeNode.SymbolicName.Name == BrowseNames.HistoryUpdateDetails)
                {
                    template.AddReplacement(Tokens.PropertyAccessor, "public override");
                }
                else
                {
                    template.AddReplacement(Tokens.PropertyAccessor, "public");
                }

                return template.WriteTemplate(context);
            }

            template.AddReplacement(Tokens.PropertyAccessor, "public new");
            if (!instance.IsOverridden())
            {
                if (!s_builtInPropertyNames.Contains(instance.SymbolicName.Name) ||
                    (instance is VariableDesign && instance.SymbolicName.Name == "Value"))
                {
                    template.AddReplacement(Tokens.PropertyAccessor, "public");
                }
            }
            else
            {
                instance = instance.GetMergedInstance();
            }

            template.AddReplacement(Tokens.Description, instance.Description != null ? instance.Description.Value : string.Empty);
            template.AddReplacement(Tokens.ClassName, instance.GetClassName(m_model.TargetNamespace, m_model.Namespaces));
            template.AddReplacement(Tokens.ChildName, instance.SymbolicName.Name);
            template.AddReplacement(Tokens.FieldName, instance.GetChildFieldName());

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_FindChildMethods(Template template, Context context)
        {
            if (context.Target is not TypeDesign type)
            {
                return null;
            }

            if (type is DataTypeDesign)
            {
                return null;
            }

            Array children = GetChildren(type.Children);

            if (children.Length == 0)
            {
                return null;
            }

            int count = 0;

            bool forInstance = !context.Token.EndsWith("ForType", StringComparison.Ordinal);
            for (int ii = 0; ii < children.Length; ii++)
            {
                var instance = (InstanceDesign)children.GetValue(ii);

                if (instance.ModellingRule is ModellingRule.ExposesItsArray or
                    ModellingRule.MandatoryPlaceholder or
                    ModellingRule.OptionalPlaceholder)
                {
                    continue;
                }

                if (forInstance &&
                    instance.ModellingRule is ModellingRule.None or
                        ModellingRule.OptionalPlaceholder or
                        ModellingRule.MandatoryPlaceholder)
                {
                    continue;
                }

                if (instance.IsOverriddenWithSameClass(m_model.TargetNamespace, m_model.Namespaces))
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

        private bool WriteTemplate_FindChildMethods(Template template, Context context)
        {
            if (context.Target is not TypeDesign type)
            {
                return false;
            }

            Array children = GetChildren(type.Children);

            List<InstanceDesign> childrenToUse = [];

            bool forInstance = !context.Token.EndsWith("ForType", StringComparison.Ordinal);
            for (int ii = 0; ii < children.Length; ii++)
            {
                var instance = (InstanceDesign)children.GetValue(ii);

                if (!forInstance)
                {
                    childrenToUse.Add(instance);
                    continue;
                }

                if (instance.ModellingRule is not ModellingRule.Mandatory and not ModellingRule.Optional)
                {
                    continue;
                }

                if (instance.IsOverriddenWithSameClass(m_model.TargetNamespace, m_model.Namespaces))
                {
                    continue;
                }

                childrenToUse.Add(instance);
            }

            template.AddTemplate(
                Tokens.ListOfFindChildCase,
                CodeTemplateStrings.FindChildCase_cs,
                childrenToUse,
                LoadTemplate_ListOfFindChildCase,
                WriteTemplate_ListOfFindChildCase);

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

                if (!forInstance)
                {
                    childrenToUse.Add(instance);
                    continue;
                }

                childrenToUse.Add(instance);
            }

            template.AddTemplate(
                Tokens.ListOfFindChildren,
                CodeTemplateStrings.FindChildren_cs,
                childrenToUse,
                LoadTemplate_ListOfFindChildCase,
                WriteTemplate_ListOfFindChildCase);

            template.AddTemplate(
                Tokens.ListOfRemoveChild,
                CodeTemplateStrings.RemoveChild_cs,
                childrenToUse,
                (template, context) => context.Target is InstanceDesign ? context.TemplateString : null,
                WriteTemplate_ListOfRemoveChild);

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_ListOfFindChildCase(Template template, Context context)
        {
            if (context.Target is not InstanceDesign)
            {
                return null;
            }

            return context.TemplateString;
        }

        private bool WriteTemplate_ListOfFindChildCase(Template template, Context context)
        {
            if (context.Target is not InstanceDesign instance)
            {
                return false;
            }

            if (instance.Parent is TypeDesign type)
            {
                template.AddReplacement(Tokens.TypeName, type.SymbolicName.Name);
            }

            template.AddReplacement(Tokens.ClassName, instance.GetClassName(m_model.TargetNamespace, m_model.Namespaces));
            template.AddReplacement(Tokens.ChildName, instance.SymbolicName.Name);
            template.AddReplacement(Tokens.FieldName, instance.GetChildFieldName());
            template.AddReplacement(Tokens.NodeClass, instance.GetNodeClassString());

            template.AddReplacement(Tokens.BrowseName, instance.SymbolicName.Name);
            template.AddReplacement(Tokens.BrowseNameNamespacePrefix, m_model.Namespaces.GetNamespacePrefix(instance.SymbolicName.Namespace));
            template.AddReplacement(Tokens.BrowseNameNamespaceUri, m_model.Namespaces.GetConstantSymbolForNamespace(instance.SymbolicName.Namespace));

            return template.WriteTemplate(context);
        }

        private bool WriteTemplate_ListOfRemoveChild(Template template, Context context)
        {
            if (context.Target is not InstanceDesign instance)
            {
                return false;
            }

            if (instance.Parent is TypeDesign type)
            {
                template.AddReplacement(Tokens.TypeName, type.SymbolicName.Name);
            }

            template.AddReplacement(Tokens.ClassName, instance.GetClassName(m_model.TargetNamespace, m_model.Namespaces));
            template.AddReplacement(Tokens.ChildName, instance.SymbolicName.Name);
            template.AddReplacement(Tokens.FieldName, instance.GetChildFieldName());
            template.AddReplacement(Tokens.NodeClass, instance.GetNodeClassString());

            template.AddReplacement(Tokens.BrowseName, instance.SymbolicName.Name);
            template.AddReplacement(Tokens.BrowseNameNamespacePrefix, m_model.Namespaces.GetNamespacePrefix(instance.SymbolicName.Namespace));
            template.AddReplacement(Tokens.BrowseNameNamespaceUri, m_model.Namespaces.GetConstantSymbolForNamespace(instance.SymbolicName.Namespace));

            return template.WriteTemplate(context);
        }

        private static void IndexDocumentation(
            SystemContext context,
            IEnumerable<NodeState> source,
            Dictionary<NodeId, NodeState> map)
        {
            foreach (NodeState node in source)
            {
                if (!NodeId.IsNull(node.NodeId))
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
                if (child.NodeId.IdType == IdType.Numeric &&
                    (uint)child.NodeId.Identifier == 0)
                {
                    parent.RemoveChild(child);
                    continue;
                }

                RemoveChildrenWithNoNodeId(context, child);
            }
        }

        /// <summary>
        /// Returns the template parameter to use with the type.
        /// </summary>
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
                    string ns = m_model.Namespaces.GetNamespacePrefix(variableType.DataTypeNode.SymbolicId.Namespace);
                    scalarName = ns + "." + variableType.DataTypeNode.FixClassName();
                    break;
                case BasicDataType.Structure:
                    scalarName = "ExtensionObject";
                    break;
                default:
                    scalarName = variableType.DataTypeNode.GetDotNetTypeName(
                        m_model.TargetNamespace,
                        m_model.Namespaces,
                        nullable: false);
                    break;
            }

            if (variableType.ValueRank != ValueRank.Scalar)
            {
                return variableType.ValueRank == ValueRank.Array ? $"<{scalarName}[]>" : "<Variant>";
            }

            return $"<{scalarName}>";
        }

        /// <summary>
        /// Returns the children for the type.
        /// </summary>
        private Array GetFields(NodeDesign node)
        {
            if (node is DataTypeDesign dataType)
            {
                List<Parameter> fields = [];

                if (dataType.Fields == null)
                {
                    return fields.ToArray();
                }

                foreach (Parameter child in dataType.Fields)
                {
                    if (!IsExcluded(child))
                    {
                        fields.Add(child);
                    }
                }

                return fields.ToArray();
            }

            return GetChildren(node.Children);
        }

        /// <summary>
        /// Returns the children for the type.
        /// </summary>
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
                    if (!IsExcluded(child))
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
                        // CollectFields(parameter.DataTypeNode, parameter.ValueRank, fieldPath, fields);
                    }
                }
            }
        }

        private void GetBrowseNames(
            NodeDesign node,
            SortedDictionary<string, string> browseNames)
        {
            if (IsExcluded(node))
            {
                return;
            }

            if (node.IsMethodTypeNode())
            {
                return;
            }

            if (node.SymbolicName.Namespace == m_model.TargetNamespace)
            {
                browseNames[node.SymbolicName.Name] = node.BrowseName;
            }

            if (!node.HasChildren)
            {
                return;
            }

            foreach (NodeDesign child in node.Children.Items)
            {
                if (IsExcluded(child))
                {
                    continue;
                }

                if (child.SymbolicName == new XmlQualifiedName(BrowseNames.DefaultInstanceBrowseName, Namespaces.OpcUa))
                {
                    var variable = (VariableDesign)child;
                    var qname = variable.DecodedValue as QualifiedName;

                    if (qname != null)
                    {
                        browseNames[qname.Name] = qname.Name;
                    }

                    continue;
                }

                if (child.SymbolicName.Namespace == m_model.TargetNamespace)
                {
                    if (browseNames.TryGetValue(child.SymbolicName.Name, out string browseName))
                    {
                        if (browseName != child.BrowseName)
                        {
                            throw ServiceResultException.Create(
                                StatusCodes.BadTypeMismatch,
                                "Two nodes with the same symbolic name have different browse names: {0} != {1}.",
                                browseName,
                                child.BrowseName);
                        }

                        continue;
                    }

                    browseNames[child.SymbolicName.Name] = child.BrowseName;
                }

                if (child is InstanceDesign instance && instance.InstanceDeclarationNode == null)
                {
                    GetBrowseNames(child, browseNames);
                }
            }
        }

        private SortedDictionary<string, string> GetBrowseNames(IReadOnlyList<NodeDesign> nodes)
        {
            SortedDictionary<string, string> browseNames = [];

            foreach (NodeDesign node in nodes)
            {
                GetBrowseNames(node, browseNames);
            }

            return browseNames;
        }

        private bool IsParentExcluded(NodeDesign root, KeyValuePair<string, HierarchyNode> child)
        {
            string parentId = child.Key;
            _ = child.Value;

            while (parentId != null)
            {
                int index = parentId.LastIndexOf('_');

                if (index > 0)
                {
                    parentId = parentId[..index];
                }

                if (!root.Hierarchy.Nodes.TryGetValue(parentId, out HierarchyNode parent))
                {
                    return false;
                }

                if (IsExcluded(parent.Instance))
                {
                    return true;
                }

                if (index <= 0)
                {
                    break;
                }
            }

            return false;
        }

        private SortedDictionary<string, List<NodeDesign>> GetIdentifiers()
        {
            SortedDictionary<string, List<NodeDesign>> identifiers = [];

            for (int ii = 0; ii < m_model.Items.Length; ii++)
            {
                NodeDesign node = m_model.Items[ii];

                if (IsExcluded(node))
                {
                    continue;
                }

                if (node is InstanceDesign instance && instance.TypeDefinitionNode != null && IsExcluded(instance.TypeDefinitionNode))
                {
                    continue;
                }

                if (node.IsMethodTypeNode())
                {
                    continue;
                }

                string nodeClass = node.GetNodeClassString();

                if (nodeClass == "EventType")
                {
                    nodeClass = "ObjectType";
                }

                if (!identifiers.TryGetValue(nodeClass, out List<NodeDesign> nodesWithinClass))
                {
                    identifiers[nodeClass] = nodesWithinClass = [];
                }

                if (!nodesWithinClass.Contains(node))
                {
                    nodesWithinClass.Add(node);
                }

                if (node.Hierarchy == null)
                {
                    continue;
                }

                foreach (KeyValuePair<string, HierarchyNode> current in node.Hierarchy.Nodes)
                {
                    if (string.IsNullOrEmpty(current.Key))
                    {
                        continue;
                    }

                    if (IsExcluded(current.Value.Instance))
                    {
                        continue;
                    }

                    if (IsParentExcluded(node, current))
                    {
                        continue;
                    }

                    var method = current.Value.Instance as MethodDesign;

                    if (method?.MethodDeclarationNode != null && IsExcluded(method?.MethodDeclarationNode))
                    {
                        continue;
                    }

                    if (node is TypeDesign)
                    {
                        if (!current.Value.ExplicitlyDefined)
                        {
                            if (current.Value.Inherited && (current.Value.Instance == null || current.Value.Instance.BrowseName == current.Value.RelativePath))
                            {
                                continue;
                            }

                            if (current.Value.Instance is InstanceDesign child && child.ModellingRule != ModellingRule.Mandatory)
                            {
                                continue;
                            }
                        }
                    }

                    if (node is InstanceDesign)
                    {
                        if (current.Value.Instance is not InstanceDesign child)
                        {
                            continue;
                        }

                        if (child.ModellingRule != ModellingRule.Mandatory)
                        {
                            continue;
                        }

                        // this code includes children multiple layers deep - it can cause file to explode in size and break C# compiler.

                        //if (child.ModellingRule != ModellingRule.None && child.ModellingRule != ModellingRule.Mandatory)
                        //{
                        //    continue;
                        //}

                        //if (child.ModellingRule == ModellingRule.None && !current.Value.ExplicitlyDefined)
                        //{
                        //    continue;
                        //}
                    }

                    if (current.Value.Instance.NumericIdSpecified ? current.Value.Instance.NumericId == 0 : current.Value.Instance.StringId == null)
                    {
                        continue;
                    }

                    nodeClass = current.Value.Instance.GetNodeClassString();

                    if (!identifiers.TryGetValue(nodeClass, out nodesWithinClass))
                    {
                        identifiers[nodeClass] = nodesWithinClass = [];
                    }

                    nodesWithinClass.Add(current.Value.Instance);
                }
            }

            return identifiers;
        }

        private bool IsExcluded(NodeState node)
        {
            if (m_exclusions != null)
            {
                foreach (string jj in m_exclusions)
                {
                    if (jj == node.ReleaseStatus.ToString())
                    {
                        return true;
                    }

                    if (node.Categories != null && node.Categories.Contains(jj))
                    {
                        return true;
                    }

                    if (!string.IsNullOrEmpty(node.Specification) && jj == node.Specification)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private bool IsExcluded(NodeDesign node)
        {
            if (node == null)
            {
                return false;
            }

            if (node.NumericId > 1000000)
            {
                return true;
            }

            if (node.Purpose == Schema.Model.DataTypePurpose.Testing)
            {
                return true;
            }

            if (m_exclusions != null)
            {
                foreach (string jj in m_exclusions)
                {
                    if (jj == node.ReleaseStatus.ToString())
                    {
                        return true;
                    }

                    if (node.Category != null &&
                        node.Category.Contains(jj, StringComparison.Ordinal))
                    {
                        return true;
                    }

                    if (node.PartNo != 0 && jj == $"Part{node.PartNo}")
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private bool IsExcluded(Parameter parameter)
        {
            if (parameter == null)
            {
                return false;
            }

            if (m_exclusions != null)
            {
                foreach (string jj in m_exclusions)
                {
                    if (jj == parameter.ReleaseStatus.ToString())
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Returns a list of nodes to process.
        /// </summary>
        private List<NodeDesign> GetNodeList()
        {
            List<NodeDesign> nodes = [];

            foreach (NodeDesign node in m_model.Items)
            {
                if (!IsExcluded(node) && !node.IsDeclaration)
                {
                    nodes.Add(node);
                }
            }

            return nodes;
        }

        /// <summary>
        /// Adds the initializer for node
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        internal string AddInitializer(string name, NodeDesign node, bool forInstance)
        {
            var context = new SystemContext(m_telemetry)
            {
                NamespaceUris = m_model.NamespaceUris
            };

            NodeState state = node.State;

            if (forInstance)
            {
                state = node.InstanceState;
            }

            if (state == null)
            {
                return null;
            }

            List<BaseInstanceState> list = [];
            state.GetChildren(context, list);

            using var ostrm = new MemoryStream();
            if (UseXmlInitializers)
            {
                state.SaveAsXml(context, ostrm);
            }
            else
            {
                state.SaveAsBinary(context, ostrm);
            }

            if (!m_initializers.TryAdd(name, new BinaryResource(
                name,
                ostrm.ToArray(),
                UseXmlInitializers)))
            {
                // TODO: If generate a unique name?
                throw new InvalidOperationException($"Duplicate resource name {name}");
            }
            return name;
        }

        private static readonly string[] s_builtInPropertyNames =
        [
            "Description",
            "Save",
            "Handle",
            "Specification",
            "Update"
        ];

        private readonly Dictionary<string, Resource> m_initializers = [];
        private readonly IServiceMessageContext m_context;
        private readonly ITelemetryContext m_telemetry;
        private ModelDesignValidator m_validator;
        private ModelDesign m_model;
        private IReadOnlyList<string> m_exclusions;
        private readonly IFileSystem m_fileSystem;
    }
}
