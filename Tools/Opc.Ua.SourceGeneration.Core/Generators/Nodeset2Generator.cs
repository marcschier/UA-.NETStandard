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
    /// Generates a nodeset2 xml file and related files
    /// </summary>
    internal class Nodeset2Generator
    {
        /// <summary>
        /// Create generator
        /// </summary>
        public Nodeset2Generator(
            ModelDesign model,
            List<NodeDesign> nodes,
            IFileSystem fileSystem,
            ITelemetryContext telemetry)
        {
            m_model = model;
            m_nodes = nodes;
            m_fileSystem = fileSystem;
            m_logger = telemetry.CreateLogger<Nodeset2Generator>();
        }

        /// <summary>
        /// Generate nodeset 2 xml file. The file output will be validated by default.
        /// Disable validation if needed.
        /// </summary>
        public IReadOnlyList<Resource> Emit(
            string filePath,
            SystemContext context,
            NodeStateCollection collection,
            NodeStateCollection collectionWithServices,
            bool validateOutput = true)
        {
            var resources = new List<Resource>();
            string identifiersFilePath = Path.Combine(filePath, CoreUtils.Format(
                "{0}.NodeIds.csv",
                m_model.TargetNamespaceInfo.Prefix));
            WriteIdentifiers(context, identifiersFilePath, collection);
            resources.Add(identifiersFilePath.AsTextFileResource());

            identifiersFilePath = Path.Combine(filePath, CoreUtils.Format(
                "{0}.NodeIds.permissions.csv",
                m_model.TargetNamespaceInfo.Prefix));
            WritePermissions(context, identifiersFilePath, collection);
            resources.Add(identifiersFilePath.AsTextFileResource());

            string outputFile = Path.Combine(filePath, CoreUtils.Format(
                "{0}.NodeSet2.xml",
                m_model.TargetNamespaceInfo.Prefix));
            using (Stream ostrm = m_fileSystem.OpenWrite(outputFile))
            {
                var model = new ModelTableEntry
                {
                    ModelUri = m_model.TargetNamespace,
                    XmlSchemaUri = m_model.TargetXmlNamespace,
                    Version = m_model.TargetVersion,
                    ModelVersion = CoreUtils.FixupAsSemanticVersion(m_model.TargetVersion),
                    PublicationDate = m_model.TargetPublicationDate,
                    PublicationDateSpecified = m_model.TargetPublicationDateSpecified
                };

                if (m_model.Dependencies != null)
                {
                    model.RequiredModel = [.. m_model.Dependencies.Values];
                }

                collection.SaveAsNodeSet2(
                    context,
                    ostrm,
                    model,
                    m_model.TargetPublicationDate != DateTime.MinValue ?
                        m_model.TargetPublicationDate : DateTime.MinValue,
                    true);

                if (m_model.TargetNamespace == Namespaces.OpcUa)
                {
                    string nodeSetFilePath = Path.Combine(filePath, CoreUtils.Format(
                        "{0}.NodeSet2.Services.xml",
                        m_model.TargetNamespaceInfo.Prefix));
                    using (Stream ostrm2 = m_fileSystem.OpenWrite(nodeSetFilePath))
                    {
                        collectionWithServices.SaveAsNodeSet2(
                            context,
                            ostrm2,
                            model,
                            m_model.TargetPublicationDate != DateTime.MinValue ?
                                m_model.TargetPublicationDate : DateTime.MinValue,
                            true);
                    }
                    resources.Add(nodeSetFilePath.AsTextFileResource());

                    identifiersFilePath = Path.Combine(filePath, CoreUtils.Format(
                        "{0}.NodeIds.Services.csv",
                        m_model.TargetNamespaceInfo.Prefix));
                    WriteIdentifiers(context, identifiersFilePath, collectionWithServices);
                    resources.Add(identifiersFilePath.AsTextFileResource());

                    identifiersFilePath = Path.Combine(filePath, CoreUtils.Format(
                        "{0}.NodeIds.Services.permissions.csv",
                        m_model.TargetNamespaceInfo.Prefix));
                    WritePermissions(context, identifiersFilePath, collectionWithServices);
                    resources.Add(identifiersFilePath.AsTextFileResource());
                }
            }
            resources.Add(outputFile.AsTextFileResource());
            if (validateOutput)
            {
                // Validate
                using (Stream istrm = m_fileSystem.OpenRead(outputFile))
                {
                    UANodeSet.Validate(istrm, out IReadOnlyList<string> errors);
                    foreach (string error in errors)
                    {
                        m_logger.LogError("Nodeset2 Validation Error: {Error}", error);
                    }
                }

                // load as node set.
                using (Stream istrm = m_fileSystem.OpenRead(outputFile))
                {
                    var nodeSet = UANodeSet.Read(istrm);
                    var collection2 = new NodeStateCollection();
                    nodeSet.Import(context, collection2);
                }
            }
            return resources;
        }

        private void WritePermissions(
            SystemContext context,
            string identifiersFilePath,
            NodeStateCollection nodes)
        {
            var list = new Dictionary<string, NodeState>();

            foreach (NodeState node in nodes)
            {
                string name = node.SymbolicName;
                if (name is "DefaultBinary" or "DefaultXml" or "DefaultJson")
                {
                    var design = node.Handle as NodeDesign;
                    name = design.SymbolicId.Name;
                }
                GetPermissionListEntries(context, list, node, name);
            }

            IOrderedEnumerable<KeyValuePair<string, NodeState>> entries = list.OrderBy(x => x.Key);
            using TextWriter writer = m_fileSystem.CreateTextWriter(identifiersFilePath);
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
                        NodeDesign role = m_nodes
                            .FirstOrDefault(x =>
                                permission.RoleId.TryGetIdentifier(out uint numericId) &&
                                x.NumericId == numericId &&
                                x.SymbolicId.Namespace == Namespaces.OpcUa);

                        role ??= m_nodes
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

            IOrderedEnumerable<KeyValuePair<string, NodeState>> entries = list.OrderBy(x => x.Value.NodeId);

            using TextWriter writer = m_fileSystem.CreateTextWriter(identifiersFilePath);
            foreach (KeyValuePair<string, NodeState> ii in entries)
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
                GetIdentifierListEntries(context, list, child, $"{parentPath}_{child.SymbolicName}");
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
                GetPermissionListEntries(context, list, child, $"{parentPath}_{child.SymbolicName}");
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
                GetPermissionListEntries(context, list, child, $"{parentPath}_{child.SymbolicName}");
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

        private readonly ModelDesign m_model;
        private readonly List<NodeDesign> m_nodes;
        private readonly IFileSystem m_fileSystem;
        private readonly ILogger m_logger;
    }
}
