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
using System.IO;
using System.Reflection;

namespace Opc.Ua
{
    /// <summary>
    /// Stores a collection of nodes.
    /// </summary>
    public partial class NodeStateCollection : List<NodeState>
    {

        /// <summary>
        /// Initializes a new instance of the <see cref="NodeStateCollection"/> class.
        /// </summary>
        public NodeStateCollection()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NodeStateCollection"/> class.
        /// </summary>
        /// <param name="capacity">The initial capacity.</param>
        public NodeStateCollection(int capacity) : base(capacity)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NodeStateCollection"/> class.
        /// </summary>
        /// <param name="collection">The collection whose elements are copied to the new list.</param>
        /// <exception cref="T:System.ArgumentNullException">
        /// 	<paramref name="collection"/> is null.
        /// </exception>
        public NodeStateCollection(IEnumerable<NodeState> collection) : base(collection)
        {
        }


        /// <summary>
        /// Stores a well known alias.
        /// </summary>
        private struct AliasToUse
        {
            public AliasToUse(string alias, NodeId nodeId)
            {
                Alias = alias;
                NodeId = nodeId;
            }

            public string Alias;
            public NodeId NodeId;
        }

        /// <summary>
        /// The list of aliases to use.
        /// </summary>
        private readonly AliasToUse[] s_AliasesToUse = new AliasToUse[]
        {
            new AliasToUse(BrowseNames.Boolean, DataTypeIds.Boolean),
            new AliasToUse(BrowseNames.SByte, DataTypeIds.SByte),
            new AliasToUse(BrowseNames.Byte, DataTypeIds.Byte),
            new AliasToUse(BrowseNames.Int16, DataTypeIds.Int16),
            new AliasToUse(BrowseNames.UInt16, DataTypeIds.UInt16),
            new AliasToUse(BrowseNames.Int32, DataTypeIds.Int32),
            new AliasToUse(BrowseNames.UInt32, DataTypeIds.UInt32),
            new AliasToUse(BrowseNames.Int64, DataTypeIds.Int64),
            new AliasToUse(BrowseNames.UInt64, DataTypeIds.UInt64),
            new AliasToUse(BrowseNames.Float, DataTypeIds.Float),
            new AliasToUse(BrowseNames.Double, DataTypeIds.Double),
            new AliasToUse(BrowseNames.DateTime, DataTypeIds.DateTime),
            new AliasToUse(BrowseNames.String, DataTypeIds.String),
            new AliasToUse(BrowseNames.ByteString, DataTypeIds.ByteString),
            new AliasToUse(BrowseNames.Guid, DataTypeIds.Guid),
            new AliasToUse(BrowseNames.XmlElement, DataTypeIds.XmlElement),
            new AliasToUse(BrowseNames.NodeId, DataTypeIds.NodeId),
            new AliasToUse(BrowseNames.ExpandedNodeId, DataTypeIds.ExpandedNodeId),
            new AliasToUse(BrowseNames.QualifiedName, DataTypeIds.QualifiedName),
            new AliasToUse(BrowseNames.LocalizedText, DataTypeIds.LocalizedText),
            new AliasToUse(BrowseNames.StatusCode, DataTypeIds.StatusCode),
            new AliasToUse(BrowseNames.Structure, DataTypeIds.Structure),
            new AliasToUse(BrowseNames.Number, DataTypeIds.Number),
            new AliasToUse(BrowseNames.Integer, DataTypeIds.Integer),
            new AliasToUse(BrowseNames.UInteger, DataTypeIds.UInteger),
            new AliasToUse(BrowseNames.HasComponent, ReferenceTypeIds.HasComponent),
            new AliasToUse(BrowseNames.HasProperty, ReferenceTypeIds.HasProperty),
            new AliasToUse(BrowseNames.Organizes, ReferenceTypeIds.Organizes),
            new AliasToUse(BrowseNames.HasEventSource, ReferenceTypeIds.HasEventSource),
            new AliasToUse(BrowseNames.HasNotifier, ReferenceTypeIds.HasNotifier),
            new AliasToUse(BrowseNames.HasSubtype, ReferenceTypeIds.HasSubtype),
            new AliasToUse(BrowseNames.HasTypeDefinition, ReferenceTypeIds.HasTypeDefinition),
            new AliasToUse(BrowseNames.HasModellingRule, ReferenceTypeIds.HasModellingRule),
            new AliasToUse(BrowseNames.HasEncoding, ReferenceTypeIds.HasEncoding),
            new AliasToUse(BrowseNames.HasDescription, ReferenceTypeIds.HasDescription),
            new AliasToUse(BrowseNames.HasCause, ReferenceTypeIds.HasCause),
            new AliasToUse(BrowseNames.ToState, ReferenceTypeIds.ToState),
            new AliasToUse(BrowseNames.FromState, ReferenceTypeIds.FromState),
            new AliasToUse(BrowseNames.HasEffect, ReferenceTypeIds.HasEffect),
            new AliasToUse(BrowseNames.HasTrueSubState, ReferenceTypeIds.HasTrueSubState),
            new AliasToUse(BrowseNames.HasFalseSubState, ReferenceTypeIds.HasFalseSubState),
            new AliasToUse(BrowseNames.HasDictionaryEntry, ReferenceTypeIds.HasDictionaryEntry),
            new AliasToUse(BrowseNames.HasCondition, ReferenceTypeIds.HasCondition),
            new AliasToUse(BrowseNames.HasGuard, ReferenceTypeIds.HasGuard),
            new AliasToUse(BrowseNames.HasAddIn, ReferenceTypeIds.HasAddIn),
            new AliasToUse(BrowseNames.HasInterface, ReferenceTypeIds.HasInterface)
        };

        /// <summary>
        /// Reads the schema information from a XML document.
        /// </summary>
        public void LoadFromBinary(ISystemContext context, Stream istrm, bool updateTables)
        {
            var messageContext = new ServiceMessageContext {
                NamespaceUris = context.NamespaceUris,
                ServerUris = context.ServerUris,
                Factory = context.EncodeableFactory
            };

            using (var decoder = new BinaryDecoder(istrm, messageContext))
            {
                // check if a namespace table was provided.
                var namespaceUris = new NamespaceTable();

                if (!decoder.LoadStringTable(namespaceUris))
                {
                    namespaceUris = null;
                }

                // update namespace table.
                if (updateTables)
                {
                    if (namespaceUris != null && context.NamespaceUris != null)
                    {
                        for (int ii = 0; ii < namespaceUris.Count; ii++)
                        {
                            context.NamespaceUris.GetIndexOrAppend(namespaceUris.GetString((uint)ii));
                        }
                    }
                }

                // check if a server uri table was provided.
                var serverUris = new StringTable();

                if (namespaceUris != null && namespaceUris.Count > 1)
                {
                    serverUris.Append(namespaceUris.GetString(1));
                }

                if (!decoder.LoadStringTable(serverUris))
                {
                    serverUris = null;
                }

                // update server table.
                if (updateTables)
                {
                    if (serverUris != null && context.ServerUris != null)
                    {
                        for (int ii = 0; ii < serverUris.Count; ii++)
                        {
                            context.ServerUris.GetIndexOrAppend(serverUris.GetString((uint)ii));
                        }
                    }
                }

                // setup the mappings to use during decoding.
                decoder.SetMappingTables(namespaceUris, serverUris);

                int count = decoder.ReadInt32(null);

                for (int ii = 0; ii < count; ii++)
                {
                    var state = NodeState.LoadNode(context, decoder);
                    Add(state);
                }
            }
        }

        /// <summary>
        /// Loads the nodes from an embedded resource.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="resourcePath">The resource path.</param>
        /// <param name="assembly">The assembly containing the resource.</param>
        /// <param name="updateTables">if set to <c>true</c> the namespace and server tables are updated with any new URIs.</param>
        public void LoadFromBinaryResource(ISystemContext context, string resourcePath, Assembly assembly, bool updateTables)
        {
            if (resourcePath == null)
            {
                throw new ArgumentNullException(nameof(resourcePath));
            }

            if (assembly == null)
            {
                throw new ArgumentNullException(nameof(assembly));
            }

            Stream istrm = assembly.GetManifestResourceStream(resourcePath);
            if (istrm == null)
            {
                // try to load from app directory
                var file = new FileInfo(resourcePath);
                istrm = file.OpenRead();
                if (istrm == null)
                {
                    throw ServiceResultException.Create(StatusCodes.BadDecodingError, "Could not load nodes from resource: {0}", resourcePath);
                }
            }

            LoadFromBinary(context, istrm, updateTables);
        }

    }

    /// <summary>
    /// A class that creates instances of nodes based on the paramters provided.
    /// </summary>
    public class NodeStateFactory
    {
        /// <summary>
        /// Creates a new instance.
        /// </summary>
        /// <param name="context">The current context.</param>
        /// <param name="parent">The parent.</param>
        /// <param name="nodeClass">The node class.</param>
        /// <param name="browseName">The browse name.</param>
        /// <param name="referenceTypeId">The reference type between the parent and the node.</param>
        /// <param name="typeDefinitionId">The type definition.</param>
        /// <returns>Returns null if the type is not known.</returns>
        public virtual NodeState CreateInstance(
            ISystemContext context,
            NodeState parent,
            NodeClass nodeClass,
            QualifiedName browseName,
            NodeId referenceTypeId,
            NodeId typeDefinitionId)
        {
            NodeState child = null;
            switch (nodeClass)
            {
                case NodeClass.Variable:
                {
                    if (context.TypeTable != null && context.TypeTable.IsTypeOf(referenceTypeId, ReferenceTypeIds.HasProperty))
                    {
                        child = new PropertyState(parent);
                        break;
                    }

                    child = new BaseDataVariableState(parent);
                    break;
                }

                case NodeClass.Object:
                {
                    child = new BaseObjectState(parent);
                    break;
                }

                case NodeClass.Method:
                {
                    child = new MethodState(parent);
                    break;
                }

                case NodeClass.ReferenceType:
                {
                    child = new ReferenceTypeState();
                    break;
                }

                case NodeClass.ObjectType:
                {
                    child = new BaseObjectTypeState();
                    break;
                }

                case NodeClass.VariableType:
                {
                    child = new BaseDataVariableTypeState();
                    break;
                }

                case NodeClass.DataType:
                {
                    child = new DataTypeState();
                    break;
                }

                case NodeClass.View:
                {
                    child = new ViewState();
                    break;
                }

                default:
                {
                    child = null;
                    break;
                }
            }

            return child;
        }
    }
}
