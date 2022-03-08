/* Copyright (c) 1996-2020 The OPC Foundation. All rights reserved.
   The source code in this file is covered under a dual-license scenario:
     - RCL: for OPC Foundation members in good-standing
     - GPL V2: everybody else
   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/
   GNU General Public License as published by the Free Software Foundation;
   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2
   This source code is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

using System;
using System.Collections.Generic;

namespace Opc.Ua
{
    /// <summary>
    /// Provides context information to used when evaluating filters.
    /// </summary>
    public interface INodeTable
    {
        /// <summary>
        /// The table of Namespace URIs used by the table.
        /// </summary>
        /// <value>The namespace URIs.</value>
        NamespaceTable NamespaceUris { get; }

        /// <summary>
        /// The table of Server URIs used by the table.
        /// </summary>
        /// <value>The server URIs.</value>
        StringTable ServerUris { get; }

        /// <summary>
        /// The type model that describes the nodes in the table.
        /// </summary>
        /// <value>The type tree.</value>
        ITypeTable TypeTree { get; }

        /// <summary>
        /// Returns true if the node is in the table.
        /// </summary>
        /// <param name="nodeId">The node identifier.</param>
        /// <returns>True if the node is in the table.</returns>
        bool Exists(ExpandedNodeId nodeId);

        /// <summary>
        /// Finds a node in the node set.
        /// </summary>
        /// <param name="nodeId">The node identifier.</param>
        /// <returns>Returns null if the node does not exist.</returns>
        INode Find(ExpandedNodeId nodeId);
    }

    /// <summary>
    /// A table of nodes.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1710:IdentifiersShouldHaveCorrectSuffix")]
    public class NodeTable : INodeTable, IEnumerable<INode>
    {

        /// <summary>
        /// Initializes the object.
        /// </summary>
        /// <param name="namespaceUris">The namespace URIs.</param>
        /// <param name="serverUris">The server URIs.</param>
        /// <param name="typeTree">The type tree.</param>
        public NodeTable(
            NamespaceTable namespaceUris,
            StringTable serverUris,
            TypeTable typeTree)
        {
            m_namespaceUris = namespaceUris;
            m_serverUris = serverUris;
            m_typeTree = typeTree;
            m_localNodes = new NodeIdDictionary<ILocalNode>();
            m_remoteNodes = new SortedDictionary<ExpandedNodeId, RemoteNode>();
        }



        /// <inheritdoc/>
        public NamespaceTable NamespaceUris => m_namespaceUris;

        /// <inheritdoc/>
        public StringTable ServerUris => m_serverUris;

        /// <inheritdoc/>
        public ITypeTable TypeTree => m_typeTree;

        /// <inheritdoc/>
        public bool Exists(ExpandedNodeId nodeId)
        {
            return InternalFind(nodeId) != null;
        }

        /// <inheritdoc/>
        public INode Find(ExpandedNodeId nodeId)
        {
            return InternalFind(nodeId);
        }



        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.Collections.Generic.IEnumerator`1"/> that can be used to iterate through the collection.
        /// </returns>
        public IEnumerator<INode> GetEnumerator()
        {
            var list = new List<INode>(Count);

            foreach (INode node in m_localNodes.Values)
            {
                list.Add(node);
            }

            foreach (INode node in m_remoteNodes.Values)
            {
                list.Add(node);
            }

            return list.GetEnumerator();
        }



        /// <summary>
        /// Returns an enumerator that iterates through a collection.
        /// </summary>
        /// <returns>
        /// An <see cref="T:System.Collections.IEnumerator"/> object that can be used to iterate through the collection.
        /// </returns>
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }



        /// <summary>
        /// The number of nodes in the table.
        /// </summary>
        /// <value>The count.</value>
        public int Count => m_localNodes.Count + m_remoteNodes.Count;

        /// <summary>
        /// Adds a node to the table (takes ownership of the object passed in).
        /// </summary>
        /// <param name="node">The node.</param>
        /// <remarks>
        /// Any existing node is removed.
        /// </remarks>
        public void Attach(ILocalNode node)
        {
            // remove duplicates.
            if (Exists(node.NodeId))
            {
                Remove(node.NodeId);
            }

            // check if importing a node from a XML source (must copy references from References array to ReferenceTable).

            if (node is Node serializedNode && serializedNode.References.Count > 0 && serializedNode.ReferenceTable.Count == 0)
            {
                // index references.
                foreach (ReferenceNode reference in node.References)
                {
                    // ignore invalid references.
                    if (NodeId.IsNull(reference.ReferenceTypeId) || NodeId.IsNull(reference.TargetId))
                    {
                        continue;
                    }

                    node.References.Add(reference.ReferenceTypeId, reference.IsInverse, reference.TargetId);

                    // see if a remote node needs to be created.
                    if (reference.TargetId.ServerIndex != 0)
                    {
                        if (!(Find(reference.TargetId) is RemoteNode remoteNode))
                        {
                            remoteNode = new RemoteNode(this, reference.TargetId);
                            InternalAdd(remoteNode);
                        }

                        remoteNode.AddRef();
                    }
                }

                // clear unindexed reference list.
                node.References.Clear();
            }

            // add the node to the table.
            InternalAdd(node);

            // add reverse references.
            foreach (IReference reference in node.References)
            {
                if (!(Find(reference.TargetId) is ILocalNode targetNode))
                {
                    continue;
                }

                // type definition and modelling rule references are one way.
                if (reference.ReferenceTypeId != ReferenceTypeIds.HasTypeDefinition && reference.ReferenceTypeId != ReferenceTypeIds.HasModellingRule)
                {
                    targetNode.References.Add(reference.ReferenceTypeId, !reference.IsInverse, node.NodeId);
                }
            }

            // see if it is a type.
            if (m_typeTree != null)
            {
                m_typeTree.Add(node);
            }
        }

        /// <summary>
        /// Removes node from the table.
        /// </summary>
        /// <param name="nodeId">The node identifier.</param>
        /// <returns>The result of removal.</returns>
        public bool Remove(ExpandedNodeId nodeId)
        {
            // find the target.
            INode source = Find(nodeId);

            if (source == null)
            {
                return false;
            }


            // can only directly remove local nodes.
            if (!(source is ILocalNode sourceNode))
            {
                return false;
            }

            // remove references.
            foreach (IReference reference in sourceNode.References)
            {
                INode target = InternalFind(reference.TargetId);

                if (target == null)
                {
                    continue;
                }

                // remove remote node if nothing else references it.

                if (target is RemoteNode remoteNode)
                {
                    if (remoteNode.Release() == 0)
                    {
                        InternalRemove(remoteNode);
                    }

                    continue;
                }

                // remote inverse references.                  

                if (target is ILocalNode targetNode)
                {
                    targetNode.References.Remove(reference.ReferenceTypeId, reference.IsInverse, sourceNode.NodeId);
                }
            }

            InternalRemove(sourceNode);

            return true;
        }

        /// <summary>
        /// Removes all references from the table.
        /// </summary>
        public void Clear()
        {
            m_localNodes.Clear();
            m_remoteNodes.Clear();
        }



        /// <summary>
        /// Adds the node to the table.
        /// </summary>
        /// <param name="node">The node.</param>
        private void InternalAdd(ILocalNode node)
        {
            if (node == null || node.NodeId == null)
            {
                return;
            }

            m_localNodes.Add(node.NodeId, node);
        }

        /// <summary>
        /// Removes the node from the table.
        /// </summary>
        /// <param name="node">The node.</param>
        private void InternalRemove(ILocalNode node)
        {
            if (node == null || node.NodeId == null)
            {
                return;
            }

            m_localNodes.Remove(node.NodeId);
        }

        /// <summary>
        /// Adds the remote node to the table.
        /// </summary>
        /// <param name="node">The node.</param>
        private void InternalAdd(RemoteNode node)
        {
            if (node == null || node.NodeId == null)
            {
                return;
            }

            m_remoteNodes[node.NodeId] = node;
        }

        /// <summary>
        /// Removes the remote node from the table.
        /// </summary>
        /// <param name="node">The node.</param>
        private void InternalRemove(RemoteNode node)
        {
            if (node == null || node.NodeId == null)
            {
                return;
            }

            m_remoteNodes.Remove(node.NodeId);
        }

        /// <summary>
        /// Finds the specified node. Returns null if the node does node exist.
        /// </summary>
        /// <param name="nodeId">The node identifier.</param>
        /// <returns></returns>
        private INode InternalFind(ExpandedNodeId nodeId)
        {
            if (nodeId == null)
            {
                return null;
            }

            // check for remote node.
            if (nodeId.ServerIndex != 0)
            {
                RemoteNode remoteNode = null;

                if (m_remoteNodes.TryGetValue(nodeId, out remoteNode))
                {
                    return remoteNode;
                }

                return null;
            }


            // convert to locale node id.
            var localId = ExpandedNodeId.ToNodeId(nodeId, m_namespaceUris);

            if (localId == null)
            {
                return null;
            }

            ILocalNode node = null;

            if (m_localNodes.TryGetValue(localId, out node))
            {
                return node;
            }

            // node not found.
            return null;
        }



        /// <summary>
        /// Stores information for a node on a remote server.
        /// </summary>
        private class RemoteNode : INode
        {

            /// <summary>
            /// Initializes the object.
            /// </summary>
            /// <param name="owner">The owner.</param>
            /// <param name="nodeId">The node identifier.</param>
            public RemoteNode(INodeTable owner, ExpandedNodeId nodeId)
            {
                m_nodeId = nodeId;
                m_refs = 0;
                m_nodeClass = NodeClass.Unspecified;
                m_browseName = new QualifiedName("(Unknown)");
                m_displayName = new LocalizedText(m_browseName.Name);
                m_typeDefinitionId = null;
            }

            /// <summary>
            /// Adds a reference to the node.
            /// </summary>
            /// <returns>The number of references.</returns>
            public int AddRef()
            {
                return ++m_refs;
            }

            /// <summary>
            /// Removes a reference to the node.
            /// </summary>
            /// <returns>The number of references.</returns>
            public int Release()
            {
                if (m_refs == 0)
                {
                    throw new InvalidOperationException("Cannot decrement reference count below zero.");
                }

                return --m_refs;
            }

            /// <summary>
            /// The cached type definition id for the remote node.
            /// </summary>
            /// <value>The type definition identifier.</value>
            public ExpandedNodeId TypeDefinitionId
            {
                get => m_typeDefinitionId;
                internal set => m_typeDefinitionId = value;
            }



            /// <summary>
            /// The node identifier.
            /// </summary>
            /// <value>The node identifier.</value>
            public ExpandedNodeId NodeId => m_nodeId;

            /// <summary>
            /// The node class.
            /// </summary>
            /// <value>The node class.</value>
            public NodeClass NodeClass
            {
                get => m_nodeClass;
                internal set => m_nodeClass = value;
            }

            /// <summary>
            /// The locale independent browse name.
            /// </summary>
            /// <value>The name of the browse.</value>
            public QualifiedName BrowseName
            {
                get => m_browseName;
                internal set => m_browseName = value;
            }

            /// <summary>
            /// The localized display name.
            /// </summary>
            /// <value>The display name.</value>
            public LocalizedText DisplayName
            {
                get => m_displayName;
                internal set => m_displayName = value;
            }



            private readonly ExpandedNodeId m_nodeId;
            private NodeClass m_nodeClass;
            private QualifiedName m_browseName;
            private LocalizedText m_displayName;
            private ExpandedNodeId m_typeDefinitionId;
            private int m_refs;

        }



        private readonly NodeIdDictionary<ILocalNode> m_localNodes;
        private readonly SortedDictionary<ExpandedNodeId, RemoteNode> m_remoteNodes;
        private readonly NamespaceTable m_namespaceUris;
        private readonly StringTable m_serverUris;
        private readonly TypeTable m_typeTree;

    }
}
