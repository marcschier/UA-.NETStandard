/* ========================================================================
 * Copyright (c) 2005-2020 The OPC Foundation, Inc. All rights reserved.
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

namespace Opc.Ua.Client
{
    /// <summary>
    /// An implementation of a client side nodecache.
    /// </summary>
    public class NodeCache : INodeCache
    {

        /// <summary>
        /// Initializes the object with default values.
        /// </summary>
        public NodeCache(Session session)
        {
            if (session == null)
            {
                throw new ArgumentNullException(nameof(session));
            }

            m_session = session;
            m_typeTree = new TypeTable(m_session.NamespaceUris);
            m_nodes = new NodeTable(m_session.NamespaceUris, m_session.ServerUris, m_typeTree);
        }



        /// <inheritdoc/>
        public NamespaceTable NamespaceUris => m_session.NamespaceUris;

        /// <inheritdoc/>
        public StringTable ServerUris => m_session.ServerUris;

        /// <inheritdoc/>
        public ITypeTable TypeTree => this;

        /// <inheritdoc/>
        public bool Exists(ExpandedNodeId nodeId)
        {
            return Find(nodeId) != null;
        }

        /// <inheritdoc/>
        public INode Find(ExpandedNodeId nodeId)
        {
            // check for null.
            if (NodeId.IsNull(nodeId))
            {
                return null;
            }

            // check if node alredy exists.
            INode node = m_nodes.Find(nodeId);

            if (node != null)
            {
                // do not return temporary nodes created after a Browse().
                if (node.GetType() != typeof(Node))
                {
                    return node;
                }
            }

            // fetch node from server.
            try
            {
                return FetchNode(nodeId);
            }
            catch (Exception e)
            {
                Utils.LogError("Could not fetch node from server: NodeId={0}, Reason='{1}'.", nodeId, e.Message);
                // m_nodes[nodeId] = null;
                return null;
            }
        }



        /// <inheritdoc/>
        public bool IsKnown(ExpandedNodeId typeId)
        {
            INode type = Find(typeId);

            if (type == null)
            {
                return false;
            }

            return m_typeTree.IsKnown(typeId);
        }

        /// <inheritdoc/>
        public bool IsKnown(NodeId typeId)
        {
            INode type = Find(typeId);

            if (type == null)
            {
                return false;
            }

            return m_typeTree.IsKnown(typeId);
        }

        /// <inheritdoc/>
        public NodeId FindSuperType(ExpandedNodeId typeId)
        {
            INode type = Find(typeId);

            if (type == null)
            {
                return null;
            }

            return m_typeTree.FindSuperType(typeId);
        }

        /// <inheritdoc/>
        public NodeId FindSuperType(NodeId typeId)
        {
            INode type = Find(typeId);

            if (type == null)
            {
                return null;
            }

            return m_typeTree.FindSuperType(typeId);
        }

        /// <inheritdoc/>
        public IList<NodeId> FindSubTypes(ExpandedNodeId typeId)
        {
            if (!(Find(typeId) is ILocalNode type))
            {
                return new List<NodeId>();
            }

            var subtypes = new List<NodeId>();

            foreach (IReference reference in type.References.Find(ReferenceTypeIds.HasSubtype, false, true, m_typeTree))
            {
                if (!reference.TargetId.IsAbsolute)
                {
                    subtypes.Add((NodeId)reference.TargetId);
                }
            }

            return subtypes;
        }

        /// <inheritdoc/>
        public bool IsTypeOf(ExpandedNodeId subTypeId, ExpandedNodeId superTypeId)
        {
            if (subTypeId == superTypeId)
            {
                return true;
            }


            if (!(Find(subTypeId) is ILocalNode subtype))
            {
                return false;
            }

            ILocalNode supertype = subtype;

            while (supertype != null)
            {
                ExpandedNodeId currentId = supertype.References.FindTarget(ReferenceTypeIds.HasSubtype, true, true, m_typeTree, 0);

                if (currentId == superTypeId)
                {
                    return true;
                }

                supertype = Find(currentId) as ILocalNode;
            }

            return false;
        }

        /// <inheritdoc/>
        public bool IsTypeOf(NodeId subTypeId, NodeId superTypeId)
        {
            if (subTypeId == superTypeId)
            {
                return true;
            }


            if (!(Find(subTypeId) is ILocalNode subtype))
            {
                return false;
            }

            ILocalNode supertype = subtype;

            while (supertype != null)
            {
                ExpandedNodeId currentId = supertype.References.FindTarget(ReferenceTypeIds.HasSubtype, true, true, m_typeTree, 0);

                if (currentId == superTypeId)
                {
                    return true;
                }

                supertype = Find(currentId) as ILocalNode;
            }

            return false;
        }

        /// <inheritdoc/>
        public QualifiedName FindReferenceTypeName(NodeId referenceTypeId)
        {
            return m_typeTree.FindReferenceTypeName(referenceTypeId);
        }

        /// <inheritdoc/>
        public NodeId FindReferenceType(QualifiedName browseName)
        {
            return m_typeTree.FindReferenceType(browseName);
        }

        /// <inheritdoc/>
        public NodeId FindDataTypeId(ExpandedNodeId encodingId)
        {
            if (!(Find(encodingId) is ILocalNode encoding))
            {
                return NodeId.Null;
            }

            IList<IReference> references = encoding.References.Find(ReferenceTypeIds.HasEncoding, true, true, m_typeTree);

            if (references.Count > 0)
            {
                return ExpandedNodeId.ToNodeId(references[0].TargetId, m_session.NamespaceUris);
            }

            return NodeId.Null;
        }

        /// <inheritdoc/>
        public Node FetchNode(ExpandedNodeId nodeId)
        {
            var localId = ExpandedNodeId.ToNodeId(nodeId, m_session.NamespaceUris);

            if (localId == null)
            {
                return null;
            }

            // fetch node from server.
            Node source = m_session.ReadNode(localId);

            try
            {
                // fetch references from server.
                ReferenceDescriptionCollection references = m_session.FetchReferences(localId);

                foreach (ReferenceDescription reference in references)
                {
                    // create a placeholder for the node if it does not already exist.
                    if (!m_nodes.Exists(reference.NodeId))
                    {
                        // transform absolute identifiers.
                        if (reference.NodeId != null && reference.NodeId.IsAbsolute)
                        {
                            reference.NodeId = ExpandedNodeId.ToNodeId(reference.NodeId, NamespaceUris);
                        }

                        var target = new Node(reference);
                        m_nodes.Attach(target);
                    }

                    // add the reference.
                    source.ReferenceTable.Add(reference.ReferenceTypeId, !reference.IsForward, reference.NodeId);
                }
            }
            catch (Exception e)
            {
                Utils.LogError("Could not fetch references for valid node with NodeId = {0}. Error = {1}", nodeId, e.Message);
            }

            // add to cache.
            m_nodes.Attach(source);

            return source;
        }

        /// <inheritdoc/>
        public IList<INode> FindReferences(
            ExpandedNodeId nodeId,
            NodeId referenceTypeId,
            bool isInverse,
            bool includeSubtypes)
        {
            IList<INode> targets = new List<INode>();


            if (!(Find(nodeId) is Node source))
            {
                return targets;
            }

            IList<IReference> references = source.ReferenceTable.Find(
                referenceTypeId,
                isInverse,
                includeSubtypes,
                m_typeTree);

            foreach (IReference reference in references)
            {
                INode target = Find(reference.TargetId);

                if (target != null)
                {
                    targets.Add(target);
                }
            }

            return targets;
        }

        /// <inheritdoc/>
        public string GetDisplayText(INode node)
        {
            // check for null.
            if (node == null)
            {
                return string.Empty;
            }

            // check for remote node.

            if (!(node is Node target))
            {
                return node.ToString();
            }

            string displayText = null;

            // use the modelling rule to determine which parent to follow.
            NodeId modellingRule = target.ModellingRule;

            foreach (IReference reference in target.ReferenceTable.Find(ReferenceTypeIds.Aggregates, true, true, m_typeTree))
            {
                var parent = Find(reference.TargetId) as Node;

                // use the first parent if modelling rule is new.
                if (modellingRule == Objects.ModellingRule_Mandatory)
                {
                    displayText = GetDisplayText(parent);
                    break;
                }

                // use the type node as the parent for other modelling rules.
                if (parent is VariableTypeNode || parent is ObjectTypeNode)
                {
                    displayText = GetDisplayText(parent);
                    break;
                }
            }

            // prepend the parent display name.
            if (displayText != null)
            {
                return Utils.Format("{0}.{1}", displayText, node);
            }

            // simply use the node name.
            return node.ToString();
        }



        private readonly Session m_session;
        private readonly TypeTable m_typeTree;
        private readonly NodeTable m_nodes;

    }
}
