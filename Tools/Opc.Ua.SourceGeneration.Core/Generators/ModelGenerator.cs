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

using Opc.Ua.Export;
using Opc.Ua.Schema.Model;
using Opc.Ua.Types;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Model generator
    /// </summary>
    public class ModelGenerator
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

        private readonly IServiceMessageContext m_context;
        private readonly ITelemetryContext m_telemetry;
        private ModelCompilerValidator m_validator;
        private ModelDesign m_model;
        private IReadOnlyList<string> m_exclusions;
        private readonly IFileSystem m_fileSystem;

        /// <summary>
        /// Whether the XML version of the initialization strings.
        /// </summary>
        public bool UseXmlInitializers { get; private set; }

        /// <summary>
        /// Whether to include the display names.
        /// </summary>
        public bool IncludeDisplayNames { get; private set; }

        /// <summary>
        /// Subscribe to log messages.
        /// </summary>
        public event Func<LogMessageEventArgs, Task> LogMessage;

        /// <summary>
        /// Available nodesets
        /// </summary>
        public Dictionary<string, string> AvailableNodeSets { get; set; }

        /// <summary>
        /// Generates the source code files.
        /// </summary>
        public virtual void ValidateAndUpdateIds(
            IReadOnlyList<string> designFilePaths,
            string identifierFilePath,
            uint startId,
            string specificationVersion,
            bool useAllowSubtypes,
            IReadOnlyList<string> exclusions,
            string modelVersion,
            string modelPublicationDate,
            bool releaseCandidate,
            bool extractIdentifiers)
        {
            m_validator = new ModelCompilerValidator(startId, exclusions, m_fileSystem, m_telemetry);
            m_validator.LogMessage += LogMessage;

            m_validator.EmbeddedCsvPath = "ModelCompiler.CSVs";
            m_validator.EmbeddedModelPath = "TemplateStrings.ModelCompiler.Design.v104";
            m_validator.EmbeddedResourceAssembly = Assembly.GetExecutingAssembly();

            if (!string.IsNullOrEmpty(specificationVersion))
            {
                m_validator.EmbeddedModelPath = $"ModelCompiler.Design.{specificationVersion}";

                if (specificationVersion == "v103")
                {
                    m_validator.EmbeddedCsvPath = "ModelCompiler.Design";
                }
            }

            m_validator.UseAllowSubtypes = useAllowSubtypes;
            m_validator.ReleaseCandidate = releaseCandidate;
            m_validator.ModelVersion = modelVersion;
            m_validator.ModelPublicationDate = modelPublicationDate;
            m_validator.Validate(designFilePaths, identifierFilePath, false);
            m_model = m_validator.Dictionary;
        }

        /// <summary>
        /// Generates a single file containing all of the classes.
        /// </summary>
        public virtual async Task GenerateMultipleFilesAsync(
            string filePath,
            bool useXmlInitializers,
            IReadOnlyList<string> excludedCategories,
            bool includeDisplayNames,
            bool minimal = false)
        {
            UseXmlInitializers = useXmlInitializers;
            m_exclusions = excludedCategories;
            IncludeDisplayNames = includeDisplayNames;

            // write type and object definitions.
            List<NodeDesign> nodes = GetNodeList();

            if (nodes.Count == 0)
            {
                return;
            }

            WriteTemplate_ConstantsSingleFile(filePath, nodes);
            WriteTemplate_DataTypesSingleFile(filePath, nodes);
            WriteTemplate_NonDataTypesSingleFile(filePath, nodes);
            WriteTemplate_XmlSchema(filePath, nodes);
            WriteTemplate_BinarySchema(filePath, nodes);

            await WriteTemplate_XmlExport(filePath, minimal).ConfigureAwait(false);
        }

        private static void IndexDocumentation(SystemContext context, IEnumerable<NodeState> source, Dictionary<NodeId, NodeState> map)
        {
            foreach (NodeState ii in source)
            {
                if (!NodeId.IsNull(ii.NodeId))
                {
                    if (!string.IsNullOrEmpty(ii.NodeSetDocumentation) || ii.Categories?.Count > 0)
                    {
                        map[ii.NodeId] = ii;
                    }
                }

                List<BaseInstanceState> children = [];
                ii.GetChildren(context, children);
                IndexDocumentation(context, children, map);
            }
        }

        private static void UpdateDocumentation(SystemContext context, Dictionary<NodeId, NodeState> original, IEnumerable<NodeState> updated)
        {
            foreach (NodeState ii in updated)
            {
                if (original.TryGetValue(ii.NodeId, out NodeState existingNode))
                {
                    ii.NodeSetDocumentation =
                            !string.IsNullOrWhiteSpace(existingNode.NodeSetDocumentation)
                            ? existingNode.NodeSetDocumentation
                            : null;

                    ii.Categories = existingNode.Categories;
                }

                List<BaseInstanceState> children = [];
                ii.GetChildren(context, children);
                UpdateDocumentation(context, original, children);
            }
        }

        private static ushort CollectNodes(SystemContext context, Dictionary<NodeId, NodeState> index, NodeState node)
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

        private static void RemoveChildrenWithNoNodeId(SystemContext context, NodeState parent)
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
        /// Generate initialization file in xml format
        /// </summary>
        private void GeneratePredefinedNodesXml(string filePath, SystemContext context, NodeStateCollection collection)
        {
            string outputFile = Path.Combine(filePath, m_model.TargetNamespaceInfo.Prefix + ".PredefinedNodes.xml");

            using (Stream ostrm = m_fileSystem.OpenWrite(outputFile))
            {
                collection.SaveAsXml(context, ostrm);
            }

            // load from xml.
            NodeStateCollection collection2 = [];

            using Stream istrm = m_fileSystem.OpenRead(outputFile);
            collection2.LoadFromXml(context, istrm, true);
        }

        /// <summary>
        /// Generate initialization file as source code
        /// </summary>
        private void GeneratePredefinedNodesSource(string filePath, SystemContext context, NodeStateCollection collection)
        {
            // save as base64 string.
            string initializationString;

            if (!UseXmlInitializers)
            {
                using var ostrm = new MemoryStream();
                collection.SaveAsBinary(context, ostrm);
                ostrm.Close();
                initializationString = Convert.ToBase64String(ostrm.ToArray());
            }
            else
            {
                using var ostrm = new MemoryStream();
                collection.SaveAsXml(context, ostrm);
                ostrm.Close();
                initializationString = Encoding.UTF8.GetString(ostrm.ToArray());
            }

            TextWriter writer = m_fileSystem.CreateTextWriter(
                Path.Combine(filePath, m_model.TargetNamespaceInfo.Prefix + ".PredefinedNodes.cs"));

            try
            {
                var template = new Template(
                    writer,
                    TemplateStrings.ModelCompiler_Templates_Version2_PredefinedNodesFile_cs);

                template.AddTemplate(
                    "// ListOfImports",
                    null,
                    m_model.Namespaces,
                    new LoadTemplateEventHandler(LoadTemplate_NamespaceImports),
                    null);

                template.AddReplacement("_Namespace_",
                    m_model.Namespaces.GetNamespacePrefix(m_model.TargetNamespace));
                template.AddReplacement("_Encoding_",
                    UseXmlInitializers ? "Xml" : "Binary");
                template.AddReplacement("_Decode_",
                    UseXmlInitializers ? "Encoding.UTF8.GetBytes" : "Convert.FromBase64String");

                template.AddTemplate(
                    "// InitializationString",
                    null,
                    new object[] { initializationString },
                    new LoadTemplateEventHandler(LoadTemplate_InitializationString),
                    null);
                string LoadTemplate_InitializationString(Template template, Context context)
                {
                    WriteInitializationString(template, context, context.Target as string);
                    return null;
                }

                var templateContext = new Context();
                template.WriteTemplate(templateContext);
            }
            finally
            {
                writer.Close();
            }
        }

        /// <summary>
        /// Generate nodeset xml file
        /// </summary>
        private void GenerateNodesetXml(string filePath, SystemContext context, NodeStateCollection collection)
        {
            // save as nodeset.
            string outputFile = Path.Combine(filePath, m_model.TargetNamespaceInfo.Prefix + ".NodeSet.xml");

            using (Stream ostrm = m_fileSystem.OpenWrite(outputFile))
            {
                collection.SaveAsNodeSet(context, ostrm);
            }

            // load as node set.
            using Stream istrm = m_fileSystem.OpenRead(outputFile);
            var nodeSet = NodeSet.Read(istrm);
        }

        /// <summary>
        /// Writes the schema information to a static XML export file.
        /// </summary>
        private Task WriteTemplate_XmlExport(string filePath, bool minimal)
        {
            var context = new SystemContext(m_telemetry)
            {
                NamespaceUris = m_model.NamespaceUris,
                ServerUris = new StringTable()
            };

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

                if (m_model.Items[ii] is InstanceDesign design2 && design2.TypeDefinition != null && design2.TypeDefinition.Name == "DataTypeEncodingType")
                {
                    isInAddressSpace = design2.Parent == null || !design2.Parent.NotInAddressSpace;
                }

                if (m_model.Items[ii] is MethodDesign design3 && design3.SymbolicName.Name.EndsWith("MethodType", StringComparison.Ordinal))
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
                                    variable.Value = File.ReadAllBytes(file);
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

                foreach (NodeDocumentationRow row in NodeDocumentationReader.Load(documentationFile))
                {
                    var nodeId = new NodeId(row.Id, namespaceIndex);

                    if (index.TryGetValue(nodeId, out NodeState target))
                    {
                        target.NodeSetDocumentation = !string.IsNullOrEmpty(row.Link) ? row.Link : null;
                        target.Categories = [.. row.ConformanceUnits];
                    }
                }
            }

            if (!minimal)
            {
                // save the xml.
                GeneratePredefinedNodesXml(filePath, context, collection);

                GenerateNodesetXml(filePath, context, collection);
            }

            // save as nodeset.
            string originalFile = Path.Combine(filePath, m_model.TargetNamespaceInfo.Prefix + ".NodeSet2.xml");
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

            // Generate predefined nodes as source code (.cs)
            GeneratePredefinedNodesSource(filePath, context, collection);

            return Task.CompletedTask;
        }

        private void WriteTemplate_XmlSchema(string filePath, List<NodeDesign> nodes)
        {
            TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(filePath, m_model.TargetNamespaceInfo.Prefix + ".Types.xsd"));
            WriteTemplate_XmlSchema(writer, nodes);
        }

        private void WriteTemplate_XmlSchema(TextWriter writer, List<NodeDesign> nodes)
        {
            try
            {
                var template = new Template(writer, TemplateStrings.ModelCompiler_Templates_XmlSchema_File_xml);

                if (!string.IsNullOrEmpty(m_model.TargetNamespaceInfo.XmlNamespace))
                {
                    template.AddReplacement("_Namespace_", m_model.TargetNamespaceInfo.XmlNamespace);
                }
                else
                {
                    template.AddReplacement("_Namespace_", m_model.TargetNamespaceInfo.Value);
                }

                template.AddReplacement(
                    "<tns:Model />",
                    $"<ua:Model ModelUri=\"{m_model.TargetNamespaceInfo.Value}\" Version=\"{m_model.TargetVersion}\" PublicationDate=\"{XmlConvert.ToString(m_model.TargetPublicationDate, XmlDateTimeSerializationMode.Utc)}\" />");

                template.AddTemplate(
                    "xmlns:s0=\"ListOfNamespaces\"",
                    null,
                    m_model.Namespaces,
                    new LoadTemplateEventHandler(LoadTemplate_XmlNamespaceImports),
                    null);

                template.AddTemplate(
                    "<!-- Imports -->",
                    null,
                    m_model.Namespaces,
                    new LoadTemplateEventHandler(LoadTemplate_XmlNamespaceImports),
                    null);

                template.AddTemplate(
                    "<!-- BuiltInTypes -->",
                    TemplateStrings.ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_BuiltInTypes_xsd,
                    new ModelDesign[] { m_model },
                    new LoadTemplateEventHandler(LoadTemplate_XmlType),
                    new WriteTemplateEventHandler(WriteTemplate_XmlType));

                template.AddTemplate(
                    "<!-- ListOfTypes -->",
                    null,
                    nodes,
                    new LoadTemplateEventHandler(LoadTemplate_XmlType),
                    new WriteTemplateEventHandler(WriteTemplate_XmlType));

                template.WriteTemplate(null);
            }
            finally
            {
                writer.Close();
            }
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
            template.Write("<xs:import namespace=\"{0}\" />", uri);

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
                    return TemplateStrings.ModelCompiler_Templates_XmlSchema_DerivedType_xml;
                }

                return TemplateStrings.ModelCompiler_Templates_XmlSchema_EnumeratedType_xml;
            }
            else if (basicType == BasicDataType.UserDefined)
            {
                if (dataType.BaseTypeNode.SymbolicName.Name == "Union")
                {
                    return TemplateStrings.ModelCompiler_Templates_XmlSchema_Union_xml;
                }
                else if (dataType.BaseTypeNode.SymbolicName.Name == "Structure")
                {
                    return TemplateStrings.ModelCompiler_Templates_XmlSchema_ComplexType_xml;
                }
                else
                {
                    return TemplateStrings.ModelCompiler_Templates_XmlSchema_DerivedType_xml;
                }
            }

            return TemplateStrings.ModelCompiler_Templates_XmlSchema_SimpleType_xml;
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
                template.AddReplacement("_BaseType_", baseType.GetXmlDataType(
                    ValueRank.Scalar,
                    m_model.TargetNamespace,
                    m_model.Namespaces));
            }

            template.AddReplacement("_TypeName_", dataType.SymbolicName.Name);

            if (dataType.BasicDataType == BasicDataType.Enumeration && dataType.IsOptionSet)
            {
                template.AddReplacement("<xs:restriction base=\"xs:string\">", CoreUtils.Format(
                    "<xs:restriction base=\"{0}\">",
                    baseType.GetXmlDataType(
                        ValueRank.Scalar,
                        m_model.TargetNamespace,
                        m_model.Namespaces)));
            }

            template.AddTemplate(
                "<!-- Documentation -->",
                TemplateStrings.ModelCompiler_Templates_XmlSchema_Documentation_xml,
                new DataTypeDesign[] { dataType },
                new LoadTemplateEventHandler(LoadTemplate_XmlDocumentation),
                new WriteTemplateEventHandler(WriteTemplate_XmlDocumentation));

            template.AddTemplate(
                "<!-- CollectionType -->",
                TemplateStrings.ModelCompiler_Templates_XmlSchema_CollectionType_xml,
                new DataTypeDesign[] { dataType },
                new LoadTemplateEventHandler(LoadTemplate_XmlCollectionType),
                new WriteTemplateEventHandler(WriteTemplate_XmlCollectionType));

            template.AddTemplate(
                "<!-- ListOfFields -->",
                null,
                dataType.Fields,
                new LoadTemplateEventHandler(LoadTemplate_XmlTypeFields),
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
                    template.Write("<xs:enumeration value=\"{0}\" />", field.Name);
                    return null;
                }

                template.Write("<xs:enumeration value=\"{0}_{1}\" />", field.Name, field.Identifier);
                return null;
            }

            basicType = field.DataTypeNode.BasicDataType;

            if (basicType == BasicDataType.XmlElement && field.ValueRank == ValueRank.Scalar)
            {
                template.WriteNextLine(context.Prefix);
                template.Write("<xs:element name=\"{0}\" minOccurs=\"0\" nillable=\"true\">", field.Name);
                template.WriteNextLine(context.Prefix);
                template.Write("  <xs:complexType>");
                template.WriteNextLine(context.Prefix);
                template.Write("    <xs:sequence>");
                template.WriteNextLine(context.Prefix);
                template.Write("      <xs:any minOccurs=\"0\" processContents=\"lax\" />");
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

                template.Write("<xs:element name=\"{0}\" type=\"{1}\" minOccurs=\"0\" nillable=\"true\" />", field.Name, fieldDataType);
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
                                "<xs:element name=\"{0}\" type=\"{1}\" minOccurs=\"0\" nillable=\"true\" />",
                                field.Name,
                                field.DataTypeNode.GetXmlDataType(
                                    field.ValueRank,
                                    m_model.TargetNamespace,
                                    m_model.Namespaces));
                        break;
                    case BasicDataType.Guid:
                    case BasicDataType.StatusCode:
                        template.Write(
                                "<xs:element name=\"{0}\" type=\"{1}\" minOccurs=\"0\" />",
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
                            "<xs:element name=\"{0}\" type=\"{1}\" minOccurs=\"0\" nillable=\"true\" />",
                            field.Name,
                            fieldDataType);
                        break;
                    default:
                        template.Write("<xs:element name=\"{0}\" type=\"{1}\" minOccurs=\"0\" />",
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

            template.AddReplacement("_Description_", dataType.Description.Value);

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
            template.AddReplacement("_TypeName_", dataType.SymbolicName.Name);
            template.AddReplacement("_Nillable_", !dataType.BasicDataType.IsNullable() ? string.Empty : "nillable=\"true\" ");

            return template.WriteTemplate(context);
        }

        private void WriteTemplate_BinarySchema(string filePath, List<NodeDesign> nodes)
        {
            TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(filePath, m_model.TargetNamespaceInfo.Prefix + ".Types.bsd"));
            WriteTemplate_BinarySchema(writer, nodes);
        }

        private void WriteTemplate_BinarySchema(TextWriter writer, List<NodeDesign> nodes)
        {
            try
            {
                var template = new Template(writer, TemplateStrings.ModelCompiler_Templates_BinarySchema_File_xml);

                template.AddReplacement("_DictionaryUri_", m_model.TargetNamespace);
                template.Replacements.Add("_BuildDate_", CoreUtils.Format("{0:yyyy-MM-dd}", DateTime.UtcNow));
                template.Replacements.Add("_Version_", CoreUtils.Format("{0}.{1}", CoreUtils.GetAssemblySoftwareVersion(), CoreUtils.GetAssemblyBuildNumber()));

                template.AddTemplate(
                    "xmlns:s0=\"ListOfNamespaces\"",
                    null,
                    m_model.Namespaces,
                    new LoadTemplateEventHandler(LoadTemplate_BinaryNamespaceImports),
                    null);

                template.AddTemplate(
                    "<!-- Imports -->",
                    null,
                    m_model.Namespaces,
                    new LoadTemplateEventHandler(LoadTemplate_BinaryNamespaceImports),
                    null);

                template.AddTemplate(
                    "<!-- BuiltInTypes -->",
                    TemplateStrings.ModelCompiler_Templates_BinarySchema_BuiltInTypes_bsd,
                    new ModelDesign[] { m_model },
                    new LoadTemplateEventHandler(LoadTemplate_BinaryType),
                    new WriteTemplateEventHandler(WriteTemplate_BinaryType));

                template.AddTemplate(
                    "<!-- ListOfTypes -->",
                    null,
                    nodes,
                    new LoadTemplateEventHandler(LoadTemplate_BinaryType),
                    new WriteTemplateEventHandler(WriteTemplate_BinaryType));

                template.WriteTemplate(null);
            }
            finally
            {
                writer.Close();
            }
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
                template.Write("xmlns:{0}=\"{1}\"", m_model.Namespaces.GetXmlNamespacePrefix(ns.Value), ns.Value);
                return null;
            }

            template.WriteNextLine(context.Prefix);
            template.Write(
                "<opc:Import Namespace=\"{0}\" Location=\"{1}.BinarySchema.bsd\"/>",
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
                return TemplateStrings.ModelCompiler_Templates_BinarySchema_EnumeratedType_xml;
            }
            else if (basicType == BasicDataType.UserDefined)
            {
                return TemplateStrings.ModelCompiler_Templates_BinarySchema_ComplexType_xml;
            }

            return TemplateStrings.ModelCompiler_Templates_BinarySchema_OpaqueType_xml;
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

            template.AddReplacement("_TypeName_", dataType.SymbolicName.Name);

            if (dataType.BasicDataType == BasicDataType.UserDefined)
            {
                template.AddReplacement("_BaseType_",
                    (dataType.BaseTypeNode as DataTypeDesign).GetBinaryDataType(
                        m_model.TargetNamespace,
                        m_model.Namespaces));
            }

            List<Parameter> fields = [];
            var parents = new Stack<DataTypeDesign>();

            for (DataTypeDesign parent = dataType; parent != null; parent = parent.BaseTypeNode as DataTypeDesign)
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

                template.AddReplacement("_LengthInBits_", lengthInBits);
                template.AddReplacement("_IsOptionSet_", isOptionSet ? " IsOptionSet=\"true\"" : string.Empty);
            }

            template.AddTemplate(
                "<!-- Documentation -->",
                null,
                new DataTypeDesign[] { dataType },
                new LoadTemplateEventHandler(LoadTemplate_BinaryDocumentation),
                null);

            template.AddTemplate(
                "<!-- ListOfFields -->",
                null,
                fields,
                new LoadTemplateEventHandler(LoadTemplate_BinaryTypeFields),
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

            string fieldDataType = field.DataTypeNode.GetBinaryDataType(m_model.TargetNamespace, m_model.Namespaces);

            if (field.AllowSubTypes)
            {
                fieldDataType = "ua:ExtensionObject";
            }

            if (basicType == BasicDataType.Enumeration)
            {
                template.WriteNextLine(context.Prefix);
                template.Write("<opc:EnumeratedValue Name=\"{0}\" Value=\"{1}\" />", field.Name, field.Identifier);
                return null;
            }

            if (field.ValueRank != ValueRank.Scalar)
            {
                template.WriteNextLine(context.Prefix);
                template.Write("<opc:Field Name=\"NoOf{0}\" TypeName=\"opc:Int32\" />", field.Name);
                template.WriteNextLine(context.Prefix);
                template.Write("<opc:Field Name=\"{0}\" TypeName=\"{1}\" LengthField=\"NoOf{0}\" />", field.Name, fieldDataType);
                return null;
            }

            template.WriteNextLine(context.Prefix);

            if (field.IsInherited)
            {
                template.Write(
                    "<opc:Field Name=\"{0}\" TypeName=\"{1}\" SourceType=\"{2}\" />",
                    field.Name,
                    fieldDataType,
                    (field.Parent as DataTypeDesign).GetBinaryDataType(m_model.TargetNamespace, m_model.Namespaces));
            }
            else
            {
                template.Write("<opc:Field Name=\"{0}\" TypeName=\"{1}\" />", field.Name, fieldDataType);
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

        private void WriteTemplate_ConstantsSingleFile(string filePath, List<NodeDesign> nodes)
        {
            TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(filePath, m_model.TargetNamespaceInfo.Prefix + ".Constants.cs"));

            try
            {
                var template = new Template(writer, TemplateStrings.ModelCompiler_Templates_Version2_ConstantsFile_cs);

                template.AddReplacement("_Namespace_", m_model.Namespaces.GetNamespacePrefix(m_model.TargetNamespace));
                template.AddReplacement("_NamespaceUri_", m_model.Namespaces.GetConstantSymbolForNamespace(m_model.TargetNamespace));

                template.AddTemplate(
                    "// ListOfImports",
                    null,
                    m_model.Namespaces,
                    new LoadTemplateEventHandler(LoadTemplate_NamespaceImports),
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
                    "// ListOfNamespaceUris",
                    TemplateStrings.ModelCompiler_Templates_Version2_NamespaceUri_cs,
                    namespaces,
                    null,
                    new WriteTemplateEventHandler(WriteTemplate_CodeNamespaceUri));

                SortedDictionary<string, string> browseNames = GetBrowseNames(nodes);

                template.AddTemplate(
                    "// ListOfBrowseNames",
                    TemplateStrings.ModelCompiler_Templates_Version2_BrowseName_cs,
                    browseNames,
                    new LoadTemplateEventHandler(LoadTemplate_BrowseNames),
                    new WriteTemplateEventHandler(WriteTemplate_BrowseNames));

                SortedDictionary<string, List<NodeDesign>> identifiers = GetIdentifiers();

                template.AddTemplate(
                    "// ListOfIdentifiers",
                    TemplateStrings.ModelCompiler_Templates_Version2_IdClass_cs,
                    identifiers,
                    new LoadTemplateEventHandler(LoadTemplate_IdClass),
                    new WriteTemplateEventHandler(WriteTemplate_IdClass));

                template.AddTemplate(
                    "// ListOfNodeIds",
                    TemplateStrings.ModelCompiler_Templates_Version2_NodeIdClass_cs,
                    identifiers,
                    new LoadTemplateEventHandler(LoadTemplate_IdClass),
                    new WriteTemplateEventHandler(WriteTemplate_IdClass));

                var context = new Context
                {
                    Target = nodes
                };
                template.WriteTemplate(context);
            }
            finally
            {
                writer.Close();
            }
        }

        private void WriteTemplate_DataTypesSingleFile(string filePath, List<NodeDesign> nodes)
        {
            TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(filePath, m_model.TargetNamespaceInfo.Prefix + ".DataTypes.cs"));

            try
            {
                var template = new Template(writer, TemplateStrings.ModelCompiler_Templates_Version2_TypesFile_cs);

                template.AddReplacement("_Namespace_", m_model.Namespaces.GetNamespacePrefix(m_model.TargetNamespace));
                template.AddReplacement("_NamespaceUri_", m_model.Namespaces.GetConstantSymbolForNamespace(m_model.TargetNamespace));

                template.AddTemplate(
                    "// ListOfImports",
                    null,
                    m_model.Namespaces,
                    new LoadTemplateEventHandler(LoadTemplate_NamespaceImports),
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
                    if (nodes[ii] is DataTypeDesign dataTypeDesign)
                    {
                        datatypes.Add(dataTypeDesign);
                    }
                }

                template.AddTemplate(
                    "// ListOfTypes",
                    TemplateStrings.ModelCompiler_Templates_Version2_Type_cs,
                    datatypes,
                    new LoadTemplateEventHandler(LoadTemplate_ListOfTypes),
                    new WriteTemplateEventHandler(WriteTemplate_ListOfTypes));

                var context = new Context
                {
                    Target = nodes
                };
                template.WriteTemplate(context);
            }
            finally
            {
                writer.Close();
            }
        }

        private void WriteTemplate_NonDataTypesSingleFile(string filePath, List<NodeDesign> nodes)
        {
            TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(filePath, m_model.TargetNamespaceInfo.Prefix + ".Classes.cs"));

            try
            {
                var template = new Template(writer, TemplateStrings.ModelCompiler_Templates_Version2_TypesFile_cs);

                template.AddReplacement("_Namespace_", m_model.Namespaces.GetNamespacePrefix(m_model.TargetNamespace));
                template.AddReplacement("_NamespaceUri_", m_model.Namespaces.GetConstantSymbolForNamespace(m_model.TargetNamespace));

                template.AddTemplate(
                    "// ListOfImports",
                    null,
                    m_model.Namespaces,
                    new LoadTemplateEventHandler(LoadTemplate_NamespaceImports),
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
                    "// ListOfTypes",
                    TemplateStrings.ModelCompiler_Templates_Version2_Type_cs,
                    nonDataTypes,
                    new LoadTemplateEventHandler(LoadTemplate_ListOfTypes),
                    new WriteTemplateEventHandler(WriteTemplate_ListOfTypes));

                var context = new Context
                {
                    Target = nodes
                };
                template.WriteTemplate(context);
            }
            finally
            {
                writer.Close();
            }
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

            template.AddReplacement("_NodeClass_", nodes.Key);
            template.AddReplacement("_NamespacePrefix_", m_model.Namespaces.GetNamespacePrefix(m_model.TargetNamespace));

            string templatePath = TemplateStrings.ModelCompiler_Templates_Version2_IdDeclaration_cs;

            if (context.TemplateString.EndsWith("NodeIdClass_cs", StringComparison.Ordinal))
            {
                if (m_model.TargetNamespace != Namespaces.OpcUa)
                {
                    templatePath = TemplateStrings.ModelCompiler_Templates_Version2_NodeIdDeclarationAbsolute_cs;
                }
                else
                {
                    templatePath = TemplateStrings.ModelCompiler_Templates_Version2_NodeIdDeclaration_cs;
                }
            }

            template.AddTemplate(
                "// ListOfIdentifiers",
                templatePath,
                nodes.Value,
                null,
                new WriteTemplateEventHandler(WriteTemplate_IdDeclaration));

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

            template.AddReplacement("_NodeClass_", node.GetNodeClassString());
            template.AddReplacement("_SymbolicName_", node.SymbolicId.Name);
            template.AddReplacement("_Identifier_", id);
            template.AddReplacement("_NamespaceUri_", m_model.Namespaces.GetConstantSymbolForNamespace(node.SymbolicId.Namespace));
            template.AddReplacement("_NamespacePrefix_", m_model.Namespaces.GetNamespacePrefix(node.SymbolicId.Namespace));
            template.AddReplacement("_IdType_", idType);

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

            template.AddReplacement("_SymbolicName_", browseName.Key);
            template.AddReplacement("_BrowseName_", browseName.Value);

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

                template.AddReplacement("_NamespaceUri_", uri);
                template.AddReplacement("_CodeName_", ns.Prefix);

                if (uri != ns.XmlNamespace)
                {
                    template.AddReplacement("_Name_", ns.Name);
                }
                else
                {
                    template.AddReplacement("_Name_", ns.Name + "Xsd");
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
                            return TemplateStrings.ModelCompiler_Templates_Version2_DataTypes_Union_cs;
                        }

                        if (datatype.HasFields && datatype.Fields.Any(x => x.IsOptional))
                        {
                            if (datatype.GetBaseClassName(m_model.Namespaces) != "IEncodeable")
                            {
                                return TemplateStrings.ModelCompiler_Templates_Version2_DataTypes_DerivedClassWithOptionalFields_cs;
                            }

                            return TemplateStrings.ModelCompiler_Templates_Version2_DataTypes_ClassWithOptionalFields_cs;
                        }

                        if (datatype.GetBaseClassName(m_model.Namespaces) == "IEncodeable")
                        {
                            return TemplateStrings.ModelCompiler_Templates_Version2_DataTypes_Class_cs;
                        }

                        return TemplateStrings.ModelCompiler_Templates_Version2_DataTypes_DerivedClass_cs;
                    case BasicDataType.Enumeration:
                        var baseType = datatype.BaseTypeNode as DataTypeDesign;

                        if (baseType?.SymbolicId == new XmlQualifiedName("OptionSet", Namespaces.OpcUa))
                        {
                            return TemplateStrings.ModelCompiler_Templates_Version2_DataTypes_DerivedClass_cs;
                        }

                        return TemplateStrings.ModelCompiler_Templates_Version2_DataTypes_Enumeration_cs;
                    default:
                        if (datatype.IsOptionSet)
                        {
                            return TemplateStrings.ModelCompiler_Templates_Version2_DataTypes_Enumeration_cs;
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
                return TemplateStrings.ModelCompiler_Templates_Version2_ObjectType_cs;
            }

            if (context.Target is VariableTypeDesign variableType)
            {
                return TemplateStrings.ModelCompiler_Templates_Version2_VariableType_cs;
            }

            if (context.Target is MethodDesign method && method.HasArguments)
            {
                return TemplateStrings.ModelCompiler_Templates_Version2_MethodType_cs;
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

            template.AddReplacement("_NodeClass_", node.GetNodeClassString());
            template.AddReplacement("_Description_", node.Description != null ? node.Description.Value : string.Empty);

            template.AddReplacement("_TypeName_", node.SymbolicName.Name);
            template.AddReplacement("_NamespaceUri_", m_model.Namespaces.GetConstantSymbolForNamespace(node.SymbolicName.Namespace));
            template.AddReplacement("_NamespacePrefix_", m_model.Namespaces.GetNamespacePrefix(node.SymbolicId.Namespace));
            template.AddReplacement("_XmlNamespaceUri_", m_model.Namespaces.GetConstantForXmlNamespace(node.SymbolicId.Namespace));

            template.AddReplacement("_BrowseName_", node.SymbolicName.Name);
            template.AddReplacement("_BrowseNameNamespacePrefix_", m_model.Namespaces.GetNamespacePrefix(node.SymbolicName.Namespace));
            template.AddReplacement("_BrowseNameNamespaceUri_", m_model.Namespaces.GetConstantSymbolForNamespace(node.SymbolicName.Namespace));

            var type = context.Target as TypeDesign;

            if (type != null)
            {
                template.AddReplacement("_ClassName_", type.ClassName);
                template.AddReplacement("_BaseType_", type.GetBaseClassName(m_model.Namespaces));
                template.AddReplacement("_BaseTypeNamespacePrefix_", m_model.Namespaces.GetNamespacePrefix(type.BaseTypeNode.SymbolicId.Namespace));
                template.AddReplacement("_BaseTypeNamespaceUri_", m_model.Namespaces.GetConstantSymbolForNamespace(type.BaseTypeNode.SymbolicId.Namespace));
                template.AddReplacement("_BaseClassName_", type.BaseTypeNode.FixClassName());
            }

            if (context.Target is MethodDesign method)
            {
                template.AddReplacement("_ClassName_", method.GetClassName(m_model.TargetNamespace, m_model.Namespaces));

                template.AddTemplate(
                    "// ListOfInputArguments",
                    null,
                    method.InputArguments,
                    new LoadTemplateEventHandler(LoadTemplate_ListOfInputArguments),
                    null);

                template.AddTemplate(
                    "_ISystemContext context_);",
                    null,
                    new MethodDesign[] { method },
                    new LoadTemplateEventHandler(LoadTemplate_OnCallDeclaration),
                    null);

                template.AddTemplate(
                    "_ISystemContext context_, CancellationToken cancellationToken);",
                    null,
                    new MethodDesign[] { method },
                    new LoadTemplateEventHandler(LoadTemplate_OnCallAsyncDeclaration),
                    null);

                template.AddTemplate(
                    "_result = OnCall(_context);",
                    null,
                    new MethodDesign[] { method },
                    new LoadTemplateEventHandler(LoadTemplate_OnCallImplementation),
                    null);

                template.AddTemplate(
                    "_result = await OnCallAsync(_context);",
                    null,
                    new MethodDesign[] { method },
                    new LoadTemplateEventHandler(LoadTemplate_OnCallAsyncImplementation),
                    null);

                template.AddTemplate(
                    "// ListOfOutputDeclarations",
                    null,
                    method.OutputArguments,
                    new LoadTemplateEventHandler(LoadTemplate_ListOfOutputDeclarations),
                    null);

                template.AddTemplate(
                    "// ListOfOutputArgumentsFromResult",
                    null,
                    method.OutputArguments,
                    new LoadTemplateEventHandler(LoadTemplate_ListOfOutputArgumentsFromResult),
                    null);

                template.AddTemplate(
                    "// ListOfOutputArguments",
                    null,
                    method.OutputArguments,
                    new LoadTemplateEventHandler(LoadTemplate_ListOfOutputArguments),
                    null);

                template.AddTemplate(
                    "// ListOfResultProperties",
                    null,
                    method.OutputArguments,
                    new LoadTemplateEventHandler(LoadTemplate_ListOfResultProperties),
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
                // template.AddReplacement("_IsAbstract_", (dataType.IsAbstract) ? "abstract " : "");
                template.AddReplacement("_IsAbstract_", dataType.IsAbstract ? string.Empty : string.Empty);

                if (!dataType.IsOptionSet)
                {
                    template.AddReplacement("[Flags]", string.Empty);
                    template.AddReplacement(" : _BasicType_", string.Empty);
                }
                else
                {
                    template.AddReplacement("_BasicType_", dataType.BaseType.Name);

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

                if (dataType.IsStructure)
                {
                    foreach (string ii in new string[] { "Binary", "Xml", "Json" })
                    {
                        bool encoding = m_model.Items.Any(x =>
                            x.SymbolicId.Name == $"{node.SymbolicName.Name}_Encoding_Default{ii}" &&
                            x.SymbolicId.Namespace == node.SymbolicName.Namespace);

                        if (!encoding)
                        {
                            template.AddReplacement($"ObjectIds._BrowseName__Encoding_Default{ii}", "NodeId.Null");
                        }
                    }
                }

                template.AddTemplate(
                    "// ListOfSwitchFields",
                    null,
                    children,
                    new LoadTemplateEventHandler(LoadTemplate_ListOfSwitchFields),
                    null);

                template.AddTemplate(
                    "// ListOfEncodingMaskFields",
                    null,
                    completeListOfFields?.ToArray() ?? children,
                    new LoadTemplateEventHandler(LoadTemplate_ListOfEncodingMaskFields),
                    null);

                template.AddTemplate(
                    "// ListOfEncodedFields",
                    null,
                    children,
                    new LoadTemplateEventHandler(LoadTemplate_ListOfEncodedFields),
                    null);

                template.AddTemplate(
                    "// ListOfDecodedFields",
                    null,
                    children,
                    new LoadTemplateEventHandler(LoadTemplate_ListOfDecodedFields),
                    null);

                template.AddTemplate(
                    "// ListOfComparedFields",
                    null,
                    children,
                    new LoadTemplateEventHandler(LoadTemplate_ListOfComparedFields),
                    null);

                template.AddTemplate(
                    "// ListOfClonedFields",
                    null,
                    children,
                    new LoadTemplateEventHandler(LoadTemplate_ListOfClonedFields),
                    null);

                template.AddTemplate(
                    "// CollectionClass",
                    TemplateStrings.ModelCompiler_Templates_Version2_DataTypes_CollectionClass_cs,
                    new DataTypeDesign[] { dataType },
                    new LoadTemplateEventHandler(LoadTemplate_CollectionClass),
                    new WriteTemplateEventHandler(WriteTemplate_CollectionClass));
            }

            if (context.Target is ObjectTypeDesign objectType)
            {
                template.AddReplacement("<BaseT>", string.Empty);
                template.AddReplacement("_IsAbstract_", CodeGeneration.GetBooleanString(objectType.IsAbstract));
                template.AddReplacement("_EventNotifier_", CodeGeneration.GetEventNotifierString(objectType.SupportsEvents));
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
                    template.AddReplacement("<BaseT>", string.Empty);
                }
                else
                {
                    string parameter = GetTemplateParameter(variableType);

                    if (parameter == "<T>" && variableType.ValueRank != ValueRank.Scalar)
                    {
                        parameter = "<Variant>";
                    }

                    template.AddReplacement("<BaseT>", GetTemplateParameter(variableType));
                }

                // hack to keep the default value as Scalar after code was fixed to correctly set it to Any.

                string valueRank = variableType.ValueRank.GetValueRankString(variableType.ArrayDimensions);

                if (variableType.ValueRank == ValueRank.ScalarOrArray)
                {
                    for (TypeDesign baseType = variableType.BaseTypeNode; baseType != null; baseType = baseType.BaseTypeNode)
                    {
                        if (baseType.SymbolicId == new XmlQualifiedName("DataItemType", Namespaces.OpcUa))
                        {
                            valueRank = $"ValueRanks.{ValueRank.Scalar}";
                        }
                    }
                }

                template.AddReplacement("_DefaultValue_", variableType.DataTypeNode.GetDefaultDotNetValue(
                    variableType.ValueRank,
                    variableType.DefaultValue,
                    variableType.DecodedValue,
                    false,
                    m_model.TargetNamespace,
                    m_model.Namespaces,
                    m_context));
                template.AddReplacement("_ValueRank_", valueRank);
                template.AddReplacement("_ArrayDimensions_",
                    variableType.ValueRank.GetArrayDimensionsString(variableType.ArrayDimensions));
                template.AddReplacement("_IsAbstract_", CodeGeneration.GetBooleanString(variableType.IsAbstract));
                template.AddReplacement("_AccessLevel_", variableType.AccessLevel.GetAccessLevelString());
                template.AddReplacement("_MinimumSamplingInterval_",
                    CodeGeneration.GetMinimumSamplingIntervalString(variableType.MinimumSamplingInterval));
                template.AddReplacement("_Historizing_", CodeGeneration.GetBooleanString(variableType.Historizing));

                template.AddReplacement("_DataType_", variableType.DataTypeNode.SymbolicName.Name);
                template.AddReplacement("_DataTypeNamespacePrefix_",
                    m_model.Namespaces.GetNamespacePrefix(variableType.DataTypeNode.SymbolicId.Namespace));
                template.AddReplacement("_DataTypeNamespaceUri_",
                    m_model.Namespaces.GetConstantSymbolForNamespace(variableType.DataTypeNode.SymbolicId.Namespace));

                template.AddTemplate(
                    "// TypedVariableType",
                    TemplateStrings.ModelCompiler_Templates_Version2_TypedVariableType_cs,
                    new VariableTypeDesign[] { variableType },
                    new LoadTemplateEventHandler(LoadTemplate_TypedVariableType),
                    new WriteTemplateEventHandler(WriteTemplate_TypedVariableType));

                template.AddTemplate(
                    "// VariableTypeValue",
                    TemplateStrings.ModelCompiler_Templates_Version2_VariableTypeValue_cs,
                    new VariableTypeDesign[] { variableType },
                    new LoadTemplateEventHandler(LoadTemplate_VariableTypeValue),
                    new WriteTemplateEventHandler(WriteTemplate_VariableTypeValue));
            }

            template.AddTemplate(
                "// InitializationStringForType",
                null,
                new NodeDesign[] { node },
                new LoadTemplateEventHandler(LoadTemplate_InitializationString),
                null);

            template.AddTemplate(
                "// InitializeOptionalChildren",
                TemplateStrings.ModelCompiler_Templates_Version2_InitializeOptionalChild_cs,
                children,
                new LoadTemplateEventHandler(LoadTemplate_InitializeOptionalChildren),
                new WriteTemplateEventHandler(WriteTemplate_InitializeOptionalChildren));

            template.AddTemplate(
                "// InitializationString",
                null,
                new NodeDesign[] { node },
                new LoadTemplateEventHandler(LoadTemplate_InitializationString),
                null);

            template.AddTemplate(
                "// ListOfFieldsForType",
                null,
                children,
                new LoadTemplateEventHandler(LoadTemplate_ListOfFieldsForType),
                null);

            template.AddTemplate(
                "// ListOfFieldInitializers",
                null,
                children,
                new LoadTemplateEventHandler(LoadTemplate_ListOfFieldInitializers),
                null);

            template.AddTemplate(
                "// ListOfFields",
                null,
                children,
                new LoadTemplateEventHandler(LoadTemplate_ListOfFieldsForType),
                null);

            template.AddTemplate(
                "// ListOfPropertiesForType",
                TemplateStrings.ModelCompiler_Templates_Version2_Property_cs,
                children,
                new LoadTemplateEventHandler(LoadTemplate_ListOfPropertiesForType),
                new WriteTemplateEventHandler(WriteTemplate_ListOfPropertiesForType));

            template.AddTemplate(
                "// ListOfProperties",
                TemplateStrings.ModelCompiler_Templates_Version2_Property_cs,
                children,
                new LoadTemplateEventHandler(LoadTemplate_ListOfPropertiesForType),
                new WriteTemplateEventHandler(WriteTemplate_ListOfPropertiesForType));

            template.AddTemplate(
                "// FindChildMethodsForType",
                TemplateStrings.ModelCompiler_Templates_Version2_FindChildMethods_cs,
                new NodeDesign[] { type },
                new LoadTemplateEventHandler(LoadTemplate_FindChildMethods),
                new WriteTemplateEventHandler(WriteTemplate_FindChildMethods));

            template.AddTemplate(
                "// FindChildMethods",
                TemplateStrings.ModelCompiler_Templates_Version2_FindChildMethods_cs,
                new NodeDesign[] { type },
                new LoadTemplateEventHandler(LoadTemplate_FindChildMethods),
                new WriteTemplateEventHandler(WriteTemplate_FindChildMethods));

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_InitializationString(Template template, Context context)
        {
            string xml = null;

            if (context.Target is TypeDesign type)
            {
                xml = ConstructInitializer(type, !context.Token.EndsWith("ForType", StringComparison.Ordinal));

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

                            template.WriteNextLine(context.Prefix);
                            template.Write("private const string {0}_InitializationString =", current.Instance.SymbolicName.Name);
                            string childXml = ConstructInitializer(current.Instance, false);
                            WriteInitializationString(template, context, childXml);
                            template.Write(";");
                            template.WriteNextLine(string.Empty);
                            break;
                        }
                    }
                }
            }

            if (context.Target is MethodDesign method)
            {
                xml = ConstructInitializer(method, false);
            }

            if (xml == null)
            {
                return null;
            }

            template.WriteNextLine(context.Prefix);
            template.Write("private const string InitializationString =");
            WriteInitializationString(template, context, xml);
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

            template.AddReplacement("_NodeClass_", type.GetNodeClassString());
            template.AddReplacement("_ClassName_", type.ClassName);
            template.AddReplacement("_TypeName_", type.SymbolicName.Name);
            template.AddReplacement("_BrowseName_", type.SymbolicName.Name);

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

            template.AddReplacement("_ClassName_", type.ClassName);
            template.AddReplacement("_DataType_", type.DataTypeNode.GetDotNetTypeName(
                ValueRank.Scalar,
                m_model.TargetNamespace,
                m_model.Namespaces));

            template.AddTemplate(
                "// ListOfChildInitializers",
                null,
                fields,
                new LoadTemplateEventHandler(WriteTemplate_VariableTypeValueInitializers),
                null);

            template.AddTemplate(
                "// ListOfUpdateChildrenChangeMasks",
                null,
                fields,
                new LoadTemplateEventHandler(WriteTemplate_VariableTypeValueUpdateChildrenChangeMasks),
                null);

            template.AddTemplate(
                "// ListOfChildMethods",
                TemplateStrings.ModelCompiler_Templates_Version2_VariableTypeValueField_cs,
                fields,
                null,
                new WriteTemplateEventHandler(WriteTemplate_VariableTypeValueField));

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

            template.AddReplacement("_ChildName_", field.Key);
            // template.AddReplacement("_ChildPath_", field.Value.Key.Replace('_', '.'));
            template.AddReplacement("_ChildPath_", field.Key);
            template.AddReplacement("_ChildDataType_", field.Value.DataTypeNode.GetDotNetTypeName(
                field.Value.ValueRank,
                m_model.TargetNamespace,
                m_model.Namespaces));

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
            template.AddReplacement("_XmlNamespaceUri_", m_model.Namespaces.GetConstantForXmlNamespace(dataType.SymbolicId.Namespace));
            template.AddReplacement("_BrowseName_", dataType.SymbolicName.Name);

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_ListOfFieldsForType(Template template, Context context)
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
                    m_model.Namespaces),
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

            if (!context.Token.EndsWith("ForType", StringComparison.Ordinal))
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
                template.Write($"case {dataType.ClassName}Fields.{field.Name}: {{ ");
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
                        if (field.DataTypeNode.BaseTypeNode.SymbolicId == new XmlQualifiedName("OptionSet", Namespaces.OpcUa))
                        {
                            functionName = "Encodeable";
                            elementName = field.DataTypeNode.GetDotNetTypeName(
                                ValueRank.Scalar,
                                m_model.TargetNamespace,
                                m_model.Namespaces);
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
                            m_model.Namespaces);
                        template.Write($"encoder.WriteEnumeratedArray({fieldName}, {field.Name}.ToArray(), typeof({elementName}));");

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
                            template.Write($"encoder.WriteExtensionObjectArray({fieldName}, ExtensionObjectCollection.ToExtensionObjects({field.Name}));");

                            if (isUnion)
                            {
                                template.Write(" break; }");
                            }

                            return context.TemplateString;
                        }

                        if (field.ValueRank == ValueRank.Scalar)
                        {
                            template.Write($"encoder.WriteExtensionObject({fieldName}, new ExtensionObject({field.Name}));");

                            if (isUnion)
                            {
                                template.Write(" break; }");
                            }

                            return context.TemplateString;
                        }

                        template.Write($"encoder.WriteVariant({fieldName}, {field.Name});");

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
                        m_model.Namespaces);

                    if (field.ValueRank == ValueRank.Array)
                    {
                        template.Write($"encoder.WriteEncodeableArray({fieldName}, {field.Name}.ToArray(), typeof({elementName}));");

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
                template.Write($"case {dataType.ClassName}Fields.{field.Name}: {{ ");
            }

            if (field.IsOptional)
            {
                template.Write($"if ((EncodingMask & (uint){dataType.ClassName}Fields.{field.Name}) != 0) ");
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
                    if (field.DataType == new XmlQualifiedName("Enumeration", Namespaces.OpcUa))
                    {
                        functionName = "Int32";
                        break;
                    }

                    if (field.DataTypeNode.IsOptionSet)
                    {
                        if (field.DataTypeNode.BaseTypeNode.SymbolicId == new XmlQualifiedName("OptionSet", Namespaces.OpcUa))
                        {
                            functionName = "Encodeable";
                            elementName = field.DataTypeNode.GetDotNetTypeName(
                                ValueRank.Scalar,
                                m_model.TargetNamespace,
                                m_model.Namespaces);
                            break;
                        }

                        functionName = ((DataTypeDesign)field.DataTypeNode.BaseTypeNode).BasicDataType.ToString();
                        break;
                    }

                    functionName = "Enumerated";
                    elementName = field.DataTypeNode.GetDotNetTypeName(
                        ValueRank.Scalar,
                        m_model.TargetNamespace,
                        m_model.Namespaces);
                    break;
                case BasicDataType.UserDefined:
                    if (field.AllowSubTypes)
                    {
                        template.Write($"{valueName} = ");
                        elementName = field.DataTypeNode.GetDotNetTypeName(
                            ValueRank.Scalar,
                            m_model.TargetNamespace,
                            m_model.Namespaces);

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
                        m_model.Namespaces);
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
                template.Write($"case {dataType.ClassName}Fields.{field.Name}: {{ ");
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
                template.Write($"case {dataType.ClassName}Fields.{field.Name}: {{ ");
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
                    m_model.Namespaces));

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
                            m_model.Namespaces) +
                        "));";
                }
            }

            template.Write(
                format,
                field.GetChildFieldName()[2..],
                field.DataTypeNode.GetMethodArgumentDotNetType(
                    field.ValueRank,
                    m_model.TargetNamespace,
                    m_model.Namespaces),
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
                    m_model.Namespaces),
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
                            m_model.Namespaces));
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
                            m_model.Namespaces));
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
                            m_model.Namespaces));
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
                   m_model.Namespaces),
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

            template.AddReplacement("_ChildName_", instance.SymbolicName.Name);

            return template.WriteTemplate(context);
        }

        private string LoadTemplate_ListOfPropertiesForType(Template template, Context context)
        {
            if (context.Target is not InstanceDesign instance)
            {
                if (context.Target is Parameter field)
                {
                    var dataType = field.Parent as DataTypeDesign;

                    if (dataType.BasicDataType != BasicDataType.Enumeration)
                    {
                        if (field.DataTypeNode.BasicDataType == BasicDataType.UserDefined || field.ValueRank == ValueRank.Array)
                        {
                            if (field.AllowSubTypes || (field.ValueRank != ValueRank.Array && field.ValueRank != ValueRank.Scalar))
                            {
                                return TemplateStrings.ModelCompiler_Templates_Version2_DataTypes_Property_cs;
                            }

                            return TemplateStrings.ModelCompiler_Templates_Version2_DataTypes_ArrayProperty_cs;
                        }

                        return TemplateStrings.ModelCompiler_Templates_Version2_DataTypes_Property_cs;
                    }

                    return TemplateStrings.ModelCompiler_Templates_Version2_DataTypes_EnumerationValue_cs;
                }

                return null;
            }

            if (instance.ModellingRule is ModellingRule.ExposesItsArray or ModellingRule.MandatoryPlaceholder or ModellingRule.OptionalPlaceholder)
            {
                return null;
            }

            if (!context.Token.EndsWith("ForType", StringComparison.Ordinal))
            {
                if (instance.ModellingRule == ModellingRule.None)
                {
                    return null;
                }

                if (instance is MethodDesign method && method.ModellingRule != ModellingRule.Mandatory && method.ModellingRule != ModellingRule.Optional)
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

                return TemplateStrings.ModelCompiler_Templates_Version2_PropertyOverride_cs;
            }

            if (instance.IsBuiltInProperty())
            {
                return null;
            }

            return context.TemplateString;
        }

        private bool WriteTemplate_ListOfPropertiesForType(Template template, Context context)
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

                template.AddReplacement("_Description_", field.Description != null ? field.Description.Value : string.Empty);
                template.AddReplacement("_BrowseName_", field.Name);
                template.AddReplacement("_EnumerationName_", field.EnsureUniqueEnumName());
                template.AddReplacement("_TypeName_", field.DataTypeNode.GetDotNetTypeName(
                    field.ValueRank,
                    m_model.TargetNamespace,
                    m_model.Namespaces));
                template.AddReplacement("_FieldName_", field.GetChildFieldName());
                template.AddReplacement("_IsRequired_", valueType ? "true" : "false");
                template.AddReplacement(", EmitDefaultValue = _EmitDefaultValue_", emitDefaultValue ? string.Empty : ", EmitDefaultValue = false");
                template.AddReplacement("_FieldIndex_", CoreUtils.Format("{0}", context.Index + 1));
                template.AddReplacement("_DefaultValue_", field.DataTypeNode.GetDefaultDotNetValue(
                    field.ValueRank,
                    null,
                    null,
                    true,
                    m_model.TargetNamespace,
                    m_model.Namespaces,
                    m_context));
                template.AddReplacement("_Identifier_", field.Identifier.ToString(CultureInfo.InvariantCulture));

                if (field.IdentifierInName)
                {
                    template.AddReplacement("_XmlIdentifier_", field.Name);
                }
                else
                {
                    template.AddReplacement("_XmlIdentifier_", CoreUtils.Format("{0}_{1}", field.Name, field.Identifier));
                }

                if (field.Name == "NodeId" && context.Container is DataTypeDesign dt && dt.BaseTypeNode.SymbolicName.Name == BrowseNames.HistoryUpdateDetails)
                {
                    template.AddReplacement("public", "public override");
                }

                return template.WriteTemplate(context);
            }

            if (!instance.IsOverridden())
            {
                if (!s_builtInPropertyNames.Contains(instance.SymbolicName.Name) || (instance is VariableDesign && instance.SymbolicName.Name == "Value"))
                {
                    template.AddReplacement("public new", "public");
                }
            }
            else
            {
                instance = instance.GetMergedInstance();
            }

            template.AddReplacement("_Description_", instance.Description != null ? instance.Description.Value : string.Empty);
            template.AddReplacement("_ClassName_", instance.GetClassName(m_model.TargetNamespace, m_model.Namespaces));
            template.AddReplacement("_ChildName_", instance.SymbolicName.Name);
            template.AddReplacement("_FieldName_", instance.GetChildFieldName());

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

            for (int ii = 0; ii < children.Length; ii++)
            {
                var instance = (InstanceDesign)children.GetValue(ii);

                if (instance.ModellingRule is ModellingRule.ExposesItsArray or
                    ModellingRule.MandatoryPlaceholder or
                    ModellingRule.OptionalPlaceholder)
                {
                    continue;
                }

                if (!context.Token.EndsWith("ForType", StringComparison.Ordinal) &&
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

            for (int ii = 0; ii < children.Length; ii++)
            {
                var instance = (InstanceDesign)children.GetValue(ii);

                if (context.Token.EndsWith("ForType", StringComparison.Ordinal))
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
                "// ListOfFindChildCase",
                TemplateStrings.ModelCompiler_Templates_Version2_FindChildCase_cs,
                childrenToUse,
                new LoadTemplateEventHandler(LoadTemplate_ListOfFindChildCase),
                new WriteTemplateEventHandler(WriteTemplate_ListOfFindChildCase));

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

                if (context.Token.EndsWith("ForType", StringComparison.Ordinal))
                {
                    childrenToUse.Add(instance);
                    continue;
                }

                childrenToUse.Add(instance);
            }

            template.AddTemplate(
                "// ListOfFindChildren",
                TemplateStrings.ModelCompiler_Templates_Version2_FindChildren_cs,
                childrenToUse,
                new LoadTemplateEventHandler(LoadTemplate_ListOfFindChildCase),
                new WriteTemplateEventHandler(WriteTemplate_ListOfFindChildCase));

            template.AddTemplate(
                "// ListOfRemoveChild",
                TemplateStrings.ModelCompiler_Templates_Version2_RemoveChild_cs,
                childrenToUse,
                (template, context) => context.Target is InstanceDesign ? context.TemplateString : null,
                new WriteTemplateEventHandler(WriteTemplate_ListOfRemoveChild));

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
                template.AddReplacement("_TypeName_", type.SymbolicName.Name);
            }

            template.AddReplacement("_ClassName_", instance.GetClassName(m_model.TargetNamespace, m_model.Namespaces));
            template.AddReplacement("_ChildName_", instance.SymbolicName.Name);
            template.AddReplacement("_FieldName_", instance.GetChildFieldName());
            template.AddReplacement("_NodeClass_", instance.GetNodeClassString());

            template.AddReplacement("_BrowseName_", instance.SymbolicName.Name);
            template.AddReplacement("_BrowseNameNamespacePrefix_", m_model.Namespaces.GetNamespacePrefix(instance.SymbolicName.Namespace));
            template.AddReplacement("_BrowseNameNamespaceUri_", m_model.Namespaces.GetConstantSymbolForNamespace(instance.SymbolicName.Namespace));

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
                template.AddReplacement("_TypeName_", type.SymbolicName.Name);
            }

            template.AddReplacement("_ClassName_", instance.GetClassName(m_model.TargetNamespace, m_model.Namespaces));
            template.AddReplacement("_ChildName_", instance.SymbolicName.Name);
            template.AddReplacement("_FieldName_", instance.GetChildFieldName());
            template.AddReplacement("_NodeClass_", instance.GetNodeClassString());

            template.AddReplacement("_BrowseName_", instance.SymbolicName.Name);
            template.AddReplacement("_BrowseNameNamespacePrefix_", m_model.Namespaces.GetNamespacePrefix(instance.SymbolicName.Namespace));
            template.AddReplacement("_BrowseNameNamespaceUri_", m_model.Namespaces.GetConstantSymbolForNamespace(instance.SymbolicName.Namespace));

            return template.WriteTemplate(context);
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

            switch (basicType)
            {
                case BasicDataType.UserDefined:
                    string ns = m_model.Namespaces.GetNamespacePrefix(variableType.DataTypeNode.SymbolicId.Namespace);
                    _ = ns + "." + variableType.DataTypeNode.FixClassName();
                    break;
                case BasicDataType.Structure:
                    break;
                default:
                    _ = variableType.DataTypeNode.GetDotNetTypeName(m_model.TargetNamespace, m_model.Namespaces);
                    break;
            }

            if (variableType.ValueRank != ValueRank.Scalar)
            {
                return variableType.ValueRank == ValueRank.Array ? $"<{(string)null}[]>" : "<Variant>";
            }

            return $"<{(string)null}>";
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

        private static void CollectMatchingFields(VariableTypeDesign variableType, Dictionary<string, Parameter> fields)
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

        private static void CollectFields(DataTypeDesign dataType, ValueRank valueRank, string basePath, Dictionary<string, Parameter> fields)
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

        private void GetBrowseNames(NodeDesign node, SortedDictionary<string, string> browseNames)
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
        /// Constructs the initializer for a object type.
        /// </summary>
        private string ConstructInitializer(NodeDesign node, bool forInstance)
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

            if (UseXmlInitializers)
            {
                using var ostrm = new MemoryStream();
                state.SaveAsXml(context, ostrm);
                return new UTF8Encoding().GetString(ostrm.ToArray());
            }
            else
            {
                using var ostrm = new MemoryStream();
                state.SaveAsBinary(context, ostrm);
                ostrm.Close();
                return Convert.ToBase64String(ostrm.ToArray());
            }
        }

        private void WriteInitializationString(Template template, Context context, string xml)
        {
            if (xml == null)
            {
                WriteInitializationStringLine(template, context, string.Empty);
                return;
            }

            if (!UseXmlInitializers)
            {
                for (int ii = 0; ii < xml.Length; ii += 80)
                {
                    if (ii > 0)
                    {
                        template.Write(" +");
                    }

                    if (ii + 80 >= xml.Length)
                    {
                        WriteInitializationStringLine(template, context, xml[ii..]);
                    }
                    else
                    {
                        WriteInitializationStringLine(template, context, xml.Substring(ii, 80));
                    }
                }

                return;
            }

            bool first = true;

            using var reader = new StringReader(xml);
            for (string line = reader.ReadLine(); line != null; line = reader.ReadLine())
            {
                line = line.Trim();

                if (string.IsNullOrEmpty(line))
                {
                    continue;
                }

                if (line.StartsWith("<?xml", StringComparison.Ordinal))
                {
                    continue;
                }

                if (!first)
                {
                    template.Write(" +");
                }

                WriteInitializationStringLine(template, context, line);
                first = false;
            }
        }

        private static void WriteInitializationStringLine(Template template, Context context, string line)
        {
            template.WriteNextLine(context.Prefix);
            template.Write(template.Indent);
            template.Write("   \"");

            for (int ii = 0; ii < line.Length; ii++)
            {
                if (line[ii] == '"')
                {
                    template.Write("\\\"");
                    continue;
                }

                if (line[ii] == '\\')
                {
                    template.Write("\\\\");
                    continue;
                }

                template.Write(line[ii]);
            }

            template.Write("\"");
        }

        private static readonly string[] s_builtInPropertyNames =
        [
            "Description",
            "Save",
            "Handle",
            "Specification",
            "Update"
        ];
    }
}
