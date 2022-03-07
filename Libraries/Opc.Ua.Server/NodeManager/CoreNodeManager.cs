/* ========================================================================
 * Copyright (c) 2005-2022 The OPC Foundation, Inc. All rights reserved.
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

#pragma warning disable 0618

namespace Opc.Ua.Server
{
    /// <summary>
    /// The default node manager for the server.
    /// </summary>
    /// <remarks>
    /// Every Server has one instance of this NodeManager.
    /// It stores objects that implement ILocalNode and indexes them by NodeId.
    /// </remarks>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1506:AvoidExcessiveClassCoupling")]
    public partial class CoreNodeManager : INodeManager, IDisposable
    {

        /// <summary>
        /// Initializes the object with default values.
        /// </summary>
        public CoreNodeManager(
            IServerInternal server,
            ApplicationConfiguration configuration,
            ushort dynamicNamespaceIndex)
        {
            if (server == null)
            {
                throw new ArgumentNullException(nameof(server));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            m_server = server;
            m_nodes = new NodeTable(server.NamespaceUris, server.ServerUris, server.TypeTree);
            m_monitoredItems = new Dictionary<uint, MonitoredItem>();
            m_defaultMinimumSamplingInterval = 1000;
            m_namespaceUris = new List<string>();
            m_dynamicNamespaceIndex = dynamicNamespaceIndex;

            // use namespace 1 if out of range.
            if (m_dynamicNamespaceIndex == 0 || m_dynamicNamespaceIndex >= server.NamespaceUris.Count)
            {
                m_dynamicNamespaceIndex = 1;
            }

            m_samplingGroupManager = new SamplingGroupManager(
                server,
                this,
                (uint)configuration.ServerConfiguration.MaxNotificationQueueSize,
                configuration.ServerConfiguration.AvailableSamplingRates);
        }



        /// <summary>
        /// Frees any unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        /// <summary>
        /// An overrideable version of the Dispose.
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                List<INode> nodes = null;

                lock (m_lock)
                {
                    nodes = new List<INode>(m_nodes);
                    m_nodes.Clear();

                    m_monitoredItems.Clear();
                }

                foreach (INode node in nodes)
                {
                    Utils.SilentDispose(node);
                }

                Utils.SilentDispose(m_samplingGroupManager);
            }
        }



        /// <summary>
        /// Acquires the lock on the node manager.
        /// </summary>
        public object DataLock => m_lock;

        /// <summary>
        /// Imports the nodes from a dictionary of NodeState objects.
        /// </summary>
        internal void ImportNodes(ISystemContext context, IEnumerable<NodeState> predefinedNodes, bool isInternal)
        {
            var nodesToExport = new NodeTable(Server.NamespaceUris, Server.ServerUris, Server.TypeTree);

            foreach (NodeState node in predefinedNodes)
            {
                node.Export(context, nodesToExport);
            }

            lock (Server.CoreNodeManager.DataLock)
            {
                foreach (ILocalNode nodeToExport in nodesToExport)
                {
                    Server.CoreNodeManager.AttachNode(nodeToExport, isInternal);
                }
            }
        }


        /// <summary cref="INodeManager.NamespaceUris" />
        public IEnumerable<string> NamespaceUris => m_namespaceUris;

        /// <summary cref="INodeManager.CreateAddressSpace" />
        /// <remarks>
        /// Populates the NodeManager by loading the standard nodes from an XML file stored as an embedded resource.
        /// </remarks>
        public void CreateAddressSpace(IDictionary<NodeId, IList<IReference>> externalReferences)
        {
            // TBD
        }

        /// <summary cref="INodeManager.DeleteAddressSpace" />
        /// <remarks>
        /// Disposes all of the nodes.
        /// </remarks>
        public void DeleteAddressSpace()
        {
            var nodesToDispose = new List<IDisposable>();

            lock (m_lock)
            {
                // collect nodes to dispose.
                foreach (INode node in m_nodes)
                {
                    if (node is IDisposable disposable)
                    {
                        nodesToDispose.Add(disposable);
                    }
                }

                m_nodes.Clear();
            }

            // dispose of the nodes.
            foreach (IDisposable disposable in nodesToDispose)
            {
                try
                {
                    disposable.Dispose();
                }
                catch (Exception e)
                {
                    Utils.LogError(e, "Unexpected error disposing a Node object.");
                }
            }
        }

        /// <see cref="INodeManager.GetManagerHandle" />
        public object GetManagerHandle(NodeId nodeId)
        {
            lock (m_lock)
            {
                if (NodeId.IsNull(nodeId))
                {
                    return null;
                }

                return GetLocalNode(nodeId);
            }
        }

        /// <see cref="INodeManager.TranslateBrowsePath(OperationContext,object,RelativePathElement,IList{ExpandedNodeId},IList{NodeId})" />
        public void TranslateBrowsePath(
            OperationContext context,
            object sourceHandle,
            RelativePathElement relativePath,
            IList<ExpandedNodeId> targetIds,
            IList<NodeId> unresolvedTargetIds)
        {
            if (sourceHandle == null)
            {
                throw new ArgumentNullException(nameof(sourceHandle));
            }

            if (relativePath == null)
            {
                throw new ArgumentNullException(nameof(relativePath));
            }

            if (targetIds == null)
            {
                throw new ArgumentNullException(nameof(targetIds));
            }

            if (unresolvedTargetIds == null)
            {
                throw new ArgumentNullException(nameof(unresolvedTargetIds));
            }

            // check for valid handle.

            if (!(sourceHandle is ILocalNode source))
            {
                return;
            }

            lock (m_lock)
            {
                // find the references that meet the filter criteria.
                IList<IReference> references = source.References.Find(
                    relativePath.ReferenceTypeId,
                    relativePath.IsInverse,
                    relativePath.IncludeSubtypes,
                    m_server.TypeTree);

                // nothing more to do.
                if (references == null || references.Count == 0)
                {
                    return;
                }

                // find targets with matching browse names.
                foreach (IReference reference in references)
                {
                    INode target = GetLocalNode(reference.TargetId);

                    // target is not known to the node manager.
                    if (target == null)
                    {
                        // ignore unknown external references.
                        if (reference.TargetId.IsAbsolute)
                        {
                            continue;
                        }

                        // caller must check the browse name.
                        unresolvedTargetIds.Add((NodeId)reference.TargetId);
                        continue;
                    }

                    // check browse name.
                    if (target.BrowseName == relativePath.TargetName)
                    {
                        targetIds.Add(reference.TargetId);
                    }
                }
            }
        }


        /// <see cref="INodeManager.Browse" />
        public void Browse(
            OperationContext context,
            ref ContinuationPoint continuationPoint,
            IList<ReferenceDescription> references)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (continuationPoint == null)
            {
                throw new ArgumentNullException(nameof(continuationPoint));
            }

            if (references == null)
            {
                throw new ArgumentNullException(nameof(references));
            }

            // check for valid handle.

            if (!(continuationPoint.NodeToBrowse is ILocalNode source))
            {
                throw new ServiceResultException(StatusCodes.BadNodeIdUnknown);
            }

            // check for view.
            if (!ViewDescription.IsDefault(continuationPoint.View))
            {
                throw new ServiceResultException(StatusCodes.BadViewIdUnknown);
            }

            lock (m_lock)
            {
                // construct list of references.
                uint maxResultsToReturn = continuationPoint.MaxResultsToReturn;

                // get previous enumerator.

                // fetch a snapshot all references for node.
                if (!(continuationPoint.Data is IEnumerator<IReference> enumerator))
                {
                    var copy = new List<IReference>(source.References);
                    enumerator = copy.GetEnumerator();
                    enumerator.MoveNext();
                }

                do
                {
                    IReference reference = enumerator.Current;

                    // silently ignore bad values.
                    if (reference == null || NodeId.IsNull(reference.ReferenceTypeId) || NodeId.IsNull(reference.TargetId))
                    {
                        continue;
                    }

                    // apply browse filters.
                    bool include = ApplyBrowseFilters(
                        reference,
                        continuationPoint.BrowseDirection,
                        continuationPoint.ReferenceTypeId,
                        continuationPoint.IncludeSubtypes);

                    if (include)
                    {
                        var description = new ReferenceDescription {
                            NodeId = reference.TargetId
                        };
                        description.SetReferenceType(continuationPoint.ResultMask, reference.ReferenceTypeId, !reference.IsInverse);

                        // only fetch the metadata if it is requested.
                        if (continuationPoint.TargetAttributesRequired)
                        {
                            // get the metadata for the node.
                            NodeMetadata metadata = GetNodeMetadata(context, GetManagerHandle(reference.TargetId), continuationPoint.ResultMask);

                            // update description with local node metadata.
                            if (metadata != null)
                            {
                                description.SetTargetAttributes(
                                    continuationPoint.ResultMask,
                                    metadata.NodeClass,
                                    metadata.BrowseName,
                                    metadata.DisplayName,
                                    metadata.TypeDefinition);

                                // check node class mask.
                                if (!CheckNodeClassMask(continuationPoint.NodeClassMask, description.NodeClass))
                                {
                                    continue;
                                }
                            }

                            // any target that is not remote must be owned by another node manager.
                            else if (!reference.TargetId.IsAbsolute)
                            {
                                description.Unfiltered = true;
                            }
                        }

                        // add reference to list.
                        references.Add(description);

                        // construct continuation point if max results reached.
                        if (maxResultsToReturn > 0 && references.Count >= maxResultsToReturn)
                        {
                            continuationPoint.Index = 0;
                            continuationPoint.Data = enumerator;
                            enumerator.MoveNext();
                            return;
                        }
                    }
                }
                while (enumerator.MoveNext());

                // nothing more to browse if it exits from the loop normally.
                continuationPoint.Dispose();
                continuationPoint = null;
            }
        }

        /// <summary>
        /// Returns true is the target meets the filter criteria.
        /// </summary>
        private bool ApplyBrowseFilters(
            IReference reference,
            BrowseDirection browseDirection,
            NodeId referenceTypeId,
            bool includeSubtypes)
        {
            // check browse direction.
            if (reference.IsInverse)
            {
                if (browseDirection == BrowseDirection.Forward)
                {
                    return false;
                }
            }
            else
            {
                if (browseDirection == BrowseDirection.Inverse)
                {
                    return false;
                }
            }

            // check reference type filter.
            if (!NodeId.IsNull(referenceTypeId))
            {
                if (reference.ReferenceTypeId != referenceTypeId)
                {
                    if (includeSubtypes)
                    {
                        if (m_server.TypeTree.IsTypeOf(reference.ReferenceTypeId, referenceTypeId))
                        {
                            return true;
                        }
                    }

                    return false;
                }
            }

            // include reference for now.
            return true;
        }


        /// <see cref="INodeManager.GetNodeMetadata" />
        public NodeMetadata GetNodeMetadata(
            OperationContext context,
            object targetHandle,
            BrowseResultMask resultMask)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // find target.

            if (!(targetHandle is ILocalNode target))
            {
                return null;
            }

            lock (m_lock)
            {
                // copy the default metadata.
                var metadata = new NodeMetadata(target, target.NodeId);

                // copy target attributes.
                if ((resultMask & BrowseResultMask.NodeClass) != 0)
                {
                    metadata.NodeClass = target.NodeClass;
                }

                if ((resultMask & BrowseResultMask.BrowseName) != 0)
                {
                    metadata.BrowseName = target.BrowseName;
                }

                if ((resultMask & BrowseResultMask.DisplayName) != 0)
                {
                    metadata.DisplayName = target.DisplayName;

                    // check if the display name can be localized.
                    if (!string.IsNullOrEmpty(metadata.DisplayName.Key))
                    {
                        metadata.DisplayName = Server.ResourceManager.Translate(context.PreferredLocales, metadata.DisplayName);
                    }
                }

                metadata.WriteMask = target.WriteMask;

                if (metadata.WriteMask != AttributeWriteMask.None)
                {
                    var value = new DataValue((uint)(int)target.UserWriteMask);
                    ServiceResult result = target.Read(context, Attributes.UserWriteMask, value);

                    if (ServiceResult.IsBad(result))
                    {
                        metadata.WriteMask = AttributeWriteMask.None;
                    }
                    else
                    {
                        metadata.WriteMask = (AttributeWriteMask)(int)((uint)(int)metadata.WriteMask & (uint)value.Value);
                    }
                }

                metadata.EventNotifier = EventNotifiers.None;
                metadata.AccessLevel = AccessLevels.None;
                metadata.Executable = false;

                switch (target.NodeClass)
                {
                    case NodeClass.Object:
                    {
                        metadata.EventNotifier = ((IObject)target).EventNotifier;
                        break;
                    }

                    case NodeClass.View:
                    {
                        metadata.EventNotifier = ((IView)target).EventNotifier;
                        break;
                    }

                    case NodeClass.Variable:
                    {
                        var variable = (IVariable)target;
                        metadata.DataType = variable.DataType;
                        metadata.ValueRank = variable.ValueRank;
                        metadata.ArrayDimensions = variable.ArrayDimensions;
                        metadata.AccessLevel = variable.AccessLevel;

                        var value = new DataValue(variable.UserAccessLevel);
                        ServiceResult result = variable.Read(context, Attributes.UserAccessLevel, value);

                        if (ServiceResult.IsBad(result))
                        {
                            metadata.AccessLevel = 0;
                            break;
                        }

                        metadata.AccessLevel = (byte)(metadata.AccessLevel & (byte)value.Value);
                        break;
                    }

                    case NodeClass.Method:
                    {
                        var method = (IMethod)target;
                        metadata.Executable = method.Executable;

                        if (metadata.Executable)
                        {
                            var value = new DataValue(method.UserExecutable);
                            ServiceResult result = method.Read(context, Attributes.UserExecutable, value);

                            if (ServiceResult.IsBad(result))
                            {
                                metadata.Executable = false;
                                break;
                            }

                            metadata.Executable = (bool)value.Value;
                        }

                        break;
                    }
                }

                // look up type definition.
                if ((resultMask & BrowseResultMask.TypeDefinition) != 0)
                {
                    if (target.NodeClass == NodeClass.Variable || target.NodeClass == NodeClass.Object)
                    {
                        metadata.TypeDefinition = target.TypeDefinitionId;
                    }
                }

                // Set AccessRestrictions and RolePermissions
                var node = (Node)target;
                metadata.AccessRestrictions = (AccessRestrictionType)Enum.Parse(typeof(AccessRestrictionType), node.AccessRestrictions.ToString());
                metadata.RolePermissions = node.RolePermissions;
                metadata.UserRolePermissions = node.UserRolePermissions;

                // check if NamespaceMetadata is defined for NamespaceUri
                string namespaceUri = Server.NamespaceUris.GetString(target.NodeId.NamespaceIndex);
                NamespaceMetadataState namespaceMetadataState = Server.NodeManager.ConfigurationNodeManager.GetNamespaceMetadataState(namespaceUri);
                if (namespaceMetadataState != null)
                {
                    metadata.DefaultAccessRestrictions = (AccessRestrictionType)Enum.ToObject(typeof(AccessRestrictionType),
                        namespaceMetadataState.DefaultAccessRestrictions.Value);

                    metadata.DefaultRolePermissions = namespaceMetadataState.DefaultRolePermissions.Value;
                    metadata.DefaultUserRolePermissions = namespaceMetadataState.DefaultUserRolePermissions.Value;
                }

                // return metadata.
                return metadata;
            }
        }

        /// <summary cref="INodeManager.AddReferences" />
        /// <remarks>
        /// This method must not be called without first acquiring
        /// </remarks>
        public void AddReferences(IDictionary<NodeId, IList<IReference>> references)
        {
            if (references == null)
            {
                throw new ArgumentNullException(nameof(references));
            }

            lock (m_lock)
            {
                IEnumerator<KeyValuePair<NodeId, IList<IReference>>> enumerator = references.GetEnumerator();

                while (enumerator.MoveNext())
                {
                    var actualNode = GetLocalNode(enumerator.Current.Key);

                    if (actualNode != null)
                    {
                        foreach (IReference reference in enumerator.Current.Value)
                        {
                            AddReference(actualNode, reference.ReferenceTypeId, reference.IsInverse, reference.TargetId);
                        }
                    }
                }
            }
        }

        /// <see cref="INodeManager.Read" />
        public void Read(
            OperationContext context,
            double maxAge,
            IList<ReadValueId> nodesToRead,
            IList<DataValue> values,
            IList<ServiceResult> errors)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (nodesToRead == null)
            {
                throw new ArgumentNullException(nameof(nodesToRead));
            }

            if (values == null)
            {
                throw new ArgumentNullException(nameof(values));
            }

            if (errors == null)
            {
                throw new ArgumentNullException(nameof(errors));
            }

            lock (m_lock)
            {
                for (int ii = 0; ii < nodesToRead.Count; ii++)
                {
                    ReadValueId nodeToRead = nodesToRead[ii];

                    // skip items that have already been processed.
                    if (nodeToRead.Processed)
                    {
                        continue;
                    }

                    // look up the node.
                    var node = GetLocalNode(nodeToRead.NodeId);

                    if (node == null)
                    {
                        continue;
                    }

                    DataValue value = values[ii] = new DataValue();

                    value.Value = null;
                    value.ServerTimestamp = DateTime.UtcNow;
                    value.SourceTimestamp = DateTime.MinValue;
                    value.StatusCode = StatusCodes.BadAttributeIdInvalid;

                    // owned by this node manager.
                    nodeToRead.Processed = true;

                    // read the default value (also verifies that the attribute id is valid for the node).
                    ServiceResult error = node.Read(context, nodeToRead.AttributeId, value);

                    if (ServiceResult.IsBad(error))
                    {
                        errors[ii] = error;
                        continue;
                    }

                    // always use default value for base attributes.
                    bool useDefault = false;

                    switch (nodeToRead.AttributeId)
                    {
                        case Attributes.NodeId:
                        case Attributes.NodeClass:
                        case Attributes.BrowseName:
                        {
                            useDefault = true;
                            break;
                        }
                    }

                    if (useDefault)
                    {
                        errors[ii] = error;
                        continue;
                    }

                    // apply index range to value attributes.
                    if (nodeToRead.AttributeId == Attributes.Value)
                    {
                        object defaultValue = value.Value;

                        error = nodeToRead.ParsedIndexRange.ApplyRange(ref defaultValue);

                        if (ServiceResult.IsBad(error))
                        {
                            value.Value = null;
                            errors[ii] = error;
                            continue;
                        }

                        // apply data encoding.
                        if (!QualifiedName.IsNull(nodeToRead.DataEncoding))
                        {
                            error = EncodeableObject.ApplyDataEncoding(Server.MessageContext, nodeToRead.DataEncoding, ref defaultValue);

                            if (ServiceResult.IsBad(error))
                            {
                                value.Value = null;
                                errors[ii] = error;
                                continue;
                            }
                        }

                        value.Value = defaultValue;

                        // don't replace timestamp if it was set in the NodeSource
                        if (value.SourceTimestamp == DateTime.MinValue)
                        {
                            value.SourceTimestamp = DateTime.UtcNow;
                        }
                    }
                }
            }

        }

        /// <see cref="INodeManager.HistoryRead" />
        public void HistoryRead(
            OperationContext context,
            HistoryReadDetails details,
            TimestampsToReturn timestampsToReturn,
            bool releaseContinuationPoints,
            IList<HistoryReadValueId> nodesToRead,
            IList<HistoryReadResult> results,
            IList<ServiceResult> errors)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (details == null)
            {
                throw new ArgumentNullException(nameof(details));
            }

            if (nodesToRead == null)
            {
                throw new ArgumentNullException(nameof(nodesToRead));
            }

            if (results == null)
            {
                throw new ArgumentNullException(nameof(results));
            }

            if (errors == null)
            {
                throw new ArgumentNullException(nameof(errors));
            }

            var readRawModifiedDetails = details as ReadRawModifiedDetails;
            var readAtTimeDetails = details as ReadAtTimeDetails;
            var readProcessedDetails = details as ReadProcessedDetails;
            var readEventDetails = details as ReadEventDetails;

            lock (m_lock)
            {
                for (int ii = 0; ii < nodesToRead.Count; ii++)
                {
                    HistoryReadValueId nodeToRead = nodesToRead[ii];

                    // skip items that have already been processed.
                    if (nodeToRead.Processed)
                    {
                        continue;
                    }

                    // look up the node.
                    var node = GetLocalNode(nodeToRead.NodeId);

                    if (node == null)
                    {
                        continue;
                    }

                    // owned by this node manager.
                    nodeToRead.Processed = true;

                    errors[ii] = StatusCodes.BadNotReadable;
                }

            }

        }

        /// <see cref="INodeManager.Write" />
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1506:AvoidExcessiveClassCoupling"), System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1502:AvoidExcessiveComplexity")]
        public void Write(
            OperationContext context,
            IList<WriteValue> nodesToWrite,
            IList<ServiceResult> errors)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (nodesToWrite == null)
            {
                throw new ArgumentNullException(nameof(nodesToWrite));
            }

            if (errors == null)
            {
                throw new ArgumentNullException(nameof(errors));
            }

            lock (m_lock)
            {
                for (int ii = 0; ii < nodesToWrite.Count; ii++)
                {
                    WriteValue nodeToWrite = nodesToWrite[ii];

                    // skip items that have already been processed.
                    if (nodeToWrite.Processed)
                    {
                        continue;
                    }

                    // look up the node.
                    var node = GetLocalNode(nodeToWrite.NodeId);

                    if (node == null)
                    {
                        continue;
                    }

                    // owned by this node manager.
                    nodeToWrite.Processed = true;

                    if (!node.SupportsAttribute(nodeToWrite.AttributeId))
                    {
                        errors[ii] = StatusCodes.BadAttributeIdInvalid;
                        continue;
                    }

                    // fetch the node metadata.
                    NodeMetadata metadata = GetNodeMetadata(context, node, BrowseResultMask.All);

                    // check access.
                    bool writeable = true;
                    ServiceResult error = null;

                    // determine access rights.
                    switch (nodeToWrite.AttributeId)
                    {
                        case Attributes.NodeId:
                        case Attributes.NodeClass:
                        case Attributes.AccessLevel:
                        case Attributes.UserAccessLevel:
                        case Attributes.Executable:
                        case Attributes.UserExecutable:
                        case Attributes.EventNotifier:
                        {
                            writeable = false;
                            break;
                        }

                        case Attributes.Value:
                        {
                            writeable = ((metadata.AccessLevel & AccessLevels.CurrentWrite) != 0);
                            break;
                        }

                        default:
                        {
                            writeable = (metadata.WriteMask & Attributes.GetMask(nodeToWrite.AttributeId)) != 0;
                            break;
                        }
                    }

                    // error if not writeable.
                    if (!writeable)
                    {
                        errors[ii] = StatusCodes.BadNotWritable;
                        continue;
                    }

                    // determine expected datatype and value rank.
                    NodeId expectedDatatypeId = metadata.DataType;
                    int expectedValueRank = metadata.ValueRank;

                    if (nodeToWrite.AttributeId != Attributes.Value)
                    {
                        expectedDatatypeId = Attributes.GetDataTypeId(nodeToWrite.AttributeId);

                        DataValue value = nodeToWrite.Value;

                        if (value.StatusCode != StatusCodes.Good || value.ServerTimestamp != DateTime.MinValue || value.SourceTimestamp != DateTime.MinValue)
                        {
                            errors[ii] = StatusCodes.BadWriteNotSupported;
                            continue;
                        }

                        expectedValueRank = ValueRanks.Scalar;

                        if (nodeToWrite.AttributeId == Attributes.ArrayDimensions)
                        {
                            expectedValueRank = ValueRanks.OneDimension;
                        }
                    }

                    // check whether value being written is an instance of the expected data type.
                    object valueToWrite = nodeToWrite.Value.Value;

                    var typeInfo = TypeInfo.IsInstanceOfDataType(
                        valueToWrite,
                        expectedDatatypeId,
                        expectedValueRank,
                        m_server.NamespaceUris,
                        m_server.TypeTree);

                    if (typeInfo == null)
                    {
                        errors[ii] = StatusCodes.BadTypeMismatch;
                        continue;
                    }

                    // check index range.
                    if (nodeToWrite.ParsedIndexRange.Count > 0)
                    {
                        // check index range for scalars.
                        if (typeInfo.ValueRank < 0)
                        {
                            errors[ii] = StatusCodes.BadIndexRangeInvalid;
                            continue;
                        }

                        // check index range for arrays.
                        else
                        {
                            var array = (Array)valueToWrite;

                            if (nodeToWrite.ParsedIndexRange.Count != array.Length)
                            {
                                errors[ii] = StatusCodes.BadIndexRangeInvalid;
                                continue;
                            }
                        }
                    }

                    // write the default value.
                    error = node.Write(nodeToWrite.AttributeId, nodeToWrite.Value);

                    if (ServiceResult.IsBad(error))
                    {
                        errors[ii] = error;
                        continue;
                    }
                }
            }
        }

        /// <see cref="INodeManager.HistoryUpdate" />
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1502:AvoidExcessiveComplexity")]
        public void HistoryUpdate(
            OperationContext context,
            Type detailsType,
            IList<HistoryUpdateDetails> nodesToUpdate,
            IList<HistoryUpdateResult> results,
            IList<ServiceResult> errors)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (nodesToUpdate == null)
            {
                throw new ArgumentNullException(nameof(nodesToUpdate));
            }

            if (results == null)
            {
                throw new ArgumentNullException(nameof(results));
            }

            if (errors == null)
            {
                throw new ArgumentNullException(nameof(errors));
            }

            lock (m_lock)
            {
                for (int ii = 0; ii < nodesToUpdate.Count; ii++)
                {
                    HistoryUpdateDetails nodeToUpdate = nodesToUpdate[ii];

                    // skip items that have already been processed.
                    if (nodeToUpdate.Processed)
                    {
                        continue;
                    }

                    // look up the node.
                    var node = GetLocalNode(nodeToUpdate.NodeId);

                    if (node == null)
                    {
                        continue;
                    }

                    // owned by this node manager.
                    nodeToUpdate.Processed = true;

                    errors[ii] = StatusCodes.BadNotWritable;
                }
            }

        }

        /// <see cref="INodeManager.Call" />
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1502:AvoidExcessiveComplexity"), System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1506:AvoidExcessiveClassCoupling")]
        public void Call(
            OperationContext context,
            IList<CallMethodRequest> methodsToCall,
            IList<CallMethodResult> results,
            IList<ServiceResult> errors)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (methodsToCall == null)
            {
                throw new ArgumentNullException(nameof(methodsToCall));
            }

            if (results == null)
            {
                throw new ArgumentNullException(nameof(results));
            }

            if (errors == null)
            {
                throw new ArgumentNullException(nameof(errors));
            }

            lock (m_lock)
            {
                for (int ii = 0; ii < methodsToCall.Count; ii++)
                {
                    CallMethodRequest methodToCall = methodsToCall[ii];

                    // skip items that have already been processed.
                    if (methodToCall.Processed)
                    {
                        continue;
                    }

                    // look up the node.
                    var node = GetLocalNode(methodToCall.ObjectId);

                    if (node == null)
                    {
                        continue;
                    }

                    methodToCall.Processed = true;

                    // look up the method.
                    var method = GetLocalNode(methodToCall.MethodId);

                    if (method == null)
                    {
                        errors[ii] = ServiceResult.Create(StatusCodes.BadMethodInvalid, "Method is not in the address space.");
                        continue;
                    }

                    // check that the method is defined for the object.
                    if (!node.References.Exists(ReferenceTypeIds.HasComponent, false, methodToCall.MethodId, true, m_server.TypeTree))
                    {
                        errors[ii] = ServiceResult.Create(StatusCodes.BadMethodInvalid, "Method is not a component of the Object.");
                        continue;
                    }

                    errors[ii] = StatusCodes.BadNotImplemented;
                }
            }

        }

        /// <see cref="INodeManager.SubscribeToEvents" />
        public ServiceResult SubscribeToEvents(
            OperationContext context,
            object sourceId,
            uint subscriptionId,
            IEventMonitoredItem monitoredItem,
            bool unsubscribe)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (sourceId == null)
            {
                throw new ArgumentNullException(nameof(sourceId));
            }

            if (monitoredItem == null)
            {
                throw new ArgumentNullException(nameof(monitoredItem));
            }

            lock (m_lock)
            {
                // validate the node.
                NodeMetadata metadata = GetNodeMetadata(context, sourceId, BrowseResultMask.NodeClass);

                if (metadata == null)
                {
                    return StatusCodes.BadNodeIdUnknown;
                }

                // validate the node class.
                if (((metadata.NodeClass & NodeClass.Object | NodeClass.View)) == 0)
                {
                    return StatusCodes.BadNotSupported;
                }

                // check that it supports events.
                if ((metadata.EventNotifier & EventNotifiers.SubscribeToEvents) == 0)
                {
                    return StatusCodes.BadNotSupported;
                }

                return ServiceResult.Good;
            }
        }

        /// <see cref="INodeManager.SubscribeToAllEvents" />
        public ServiceResult SubscribeToAllEvents(
            OperationContext context,
            uint subscriptionId,
            IEventMonitoredItem monitoredItem,
            bool unsubscribe)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (monitoredItem == null)
            {
                throw new ArgumentNullException(nameof(monitoredItem));
            }

            return ServiceResult.Good;
        }

        /// <see cref="INodeManager.ConditionRefresh" />
        public ServiceResult ConditionRefresh(
            OperationContext context,
            IList<IEventMonitoredItem> monitoredItems)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return ServiceResult.Good;
        }

        /// <summary>
        /// Creates a set of monitored items.
        /// </summary>
        public void CreateMonitoredItems(
            OperationContext context,
            uint subscriptionId,
            double publishingInterval,
            TimestampsToReturn timestampsToReturn,
            IList<MonitoredItemCreateRequest> itemsToCreate,
            IList<ServiceResult> errors,
            IList<MonitoringFilterResult> filterErrors,
            IList<IMonitoredItem> monitoredItems,
            ref long globalIdCounter)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (itemsToCreate == null)
            {
                throw new ArgumentNullException(nameof(itemsToCreate));
            }

            if (errors == null)
            {
                throw new ArgumentNullException(nameof(errors));
            }

            if (monitoredItems == null)
            {
                throw new ArgumentNullException(nameof(monitoredItems));
            }

            lock (m_lock)
            {
                for (int ii = 0; ii < errors.Count; ii++)
                {
                    MonitoredItemCreateRequest itemToCreate = itemsToCreate[ii];

                    // skip items that have already been processed.
                    if (itemToCreate.Processed)
                    {
                        continue;
                    }

                    // look up the node.
                    var node = GetLocalNode(itemToCreate.ItemToMonitor.NodeId);

                    if (node == null)
                    {
                        continue;
                    }

                    // owned by this node manager.
                    itemToCreate.Processed = true;

                    if (!node.SupportsAttribute(itemToCreate.ItemToMonitor.AttributeId))
                    {
                        errors[ii] = StatusCodes.BadAttributeIdInvalid;
                        continue;
                    }

                    // fetch the metadata for the node.
                    NodeMetadata metadata = GetNodeMetadata(context, node, BrowseResultMask.All);

                    if (itemToCreate.ItemToMonitor.AttributeId == Attributes.Value)
                    {
                        if ((metadata.AccessLevel & AccessLevels.CurrentRead) == 0)
                        {
                            errors[ii] = StatusCodes.BadNotReadable;
                            continue;
                        }
                    }

                    // check value rank against index range.
                    if (itemToCreate.ItemToMonitor.ParsedIndexRange != NumericRange.Empty)
                    {
                        int valueRank = metadata.ValueRank;

                        if (itemToCreate.ItemToMonitor.AttributeId != Attributes.Value)
                        {
                            valueRank = Attributes.GetValueRank(itemToCreate.ItemToMonitor.AttributeId);
                        }

                        if (valueRank == ValueRanks.Scalar)
                        {
                            errors[ii] = StatusCodes.BadIndexRangeInvalid;
                            continue;
                        }
                    }

                    bool rangeRequired = false;

                    // validate the filter against the node/attribute being monitored.
                    errors[ii] = ValidateFilter(
                        metadata,
                        itemToCreate.ItemToMonitor.AttributeId,
                        itemToCreate.RequestedParameters.Filter,
                        out rangeRequired);

                    if (ServiceResult.IsBad(errors[ii]))
                    {
                        continue;
                    }

                    // lookup EU range if required.
                    Range range = null;

                    if (rangeRequired)
                    {
                        errors[ii] = ReadEURange(context, node, out range);

                        if (ServiceResult.IsBad(errors[ii]))
                        {
                            continue;
                        }
                    }

                    // create a globally unique identifier.
                    uint monitoredItemId = Utils.IncrementIdentifier(ref globalIdCounter);

                    // limit the sampling rate for non-value attributes.
                    double minimumSamplingInterval = m_defaultMinimumSamplingInterval;

                    if (itemToCreate.ItemToMonitor.AttributeId == Attributes.Value)
                    {
                        // use the MinimumSamplingInterval attribute to limit the sampling rate for value attributes.

                        if (node is IVariable variableNode)
                        {
                            minimumSamplingInterval = variableNode.MinimumSamplingInterval;

                            // use the default if the node does not specify one.
                            if (minimumSamplingInterval < 0)
                            {
                                minimumSamplingInterval = m_defaultMinimumSamplingInterval;
                            }
                        }
                    }

                    // create monitored item.
                    MonitoredItem monitoredItem = m_samplingGroupManager.CreateMonitoredItem(
                        context,
                        subscriptionId,
                        publishingInterval,
                        timestampsToReturn,
                        monitoredItemId,
                        node,
                        itemToCreate,
                        range,
                        minimumSamplingInterval);

                    // final check for initial value
                    ServiceResult error = ReadInitialValue(context, node, monitoredItem);
                    if (ServiceResult.IsBad(error))
                    {
                        if (error.StatusCode == StatusCodes.BadAttributeIdInvalid ||
                            error.StatusCode == StatusCodes.BadDataEncodingInvalid ||
                            error.StatusCode == StatusCodes.BadDataEncodingUnsupported)
                        {
                            errors[ii] = error;
                            continue;
                        }
                    }

                    // save monitored item.
                    m_monitoredItems.Add(monitoredItem.Id, monitoredItem);

                    // update monitored item list.
                    monitoredItems[ii] = monitoredItem;

                    // errors updating the monitoring groups will be reported in notifications.
                    errors[ii] = StatusCodes.Good;
                }
            }

            // update all groups with any new items.
            m_samplingGroupManager.ApplyChanges();
        }

        /// <summary>
        /// Reads the initial value for a monitored item.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="node">The node to read.</param>
        /// <param name="monitoredItem">The monitored item.</param>
        protected virtual ServiceResult ReadInitialValue(
            OperationContext context,
            ILocalNode node,
            IDataChangeMonitoredItem2 monitoredItem)
        {
            var initialValue = new DataValue {
                Value = null,
                ServerTimestamp = DateTime.UtcNow,
                SourceTimestamp = DateTime.MinValue,
                StatusCode = StatusCodes.BadWaitingForInitialData
            };

            ServiceResult error = node.Read(context, monitoredItem.AttributeId, initialValue);

            if (ServiceResult.IsBad(error))
            {
                initialValue.Value = null;
                initialValue.StatusCode = error.StatusCode;
            }

            monitoredItem.QueueValue(initialValue, error, true);

            return error;
        }

        /// <summary>
        /// Modifies a set of monitored items.
        /// </summary>
        public void ModifyMonitoredItems(
            OperationContext context,
            TimestampsToReturn timestampsToReturn,
            IList<IMonitoredItem> monitoredItems,
            IList<MonitoredItemModifyRequest> itemsToModify,
            IList<ServiceResult> errors,
            IList<MonitoringFilterResult> filterErrors)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (monitoredItems == null)
            {
                throw new ArgumentNullException(nameof(monitoredItems));
            }

            if (itemsToModify == null)
            {
                throw new ArgumentNullException(nameof(itemsToModify));
            }

            if (errors == null)
            {
                throw new ArgumentNullException(nameof(errors));
            }

            lock (m_lock)
            {
                for (int ii = 0; ii < errors.Count; ii++)
                {
                    MonitoredItemModifyRequest itemToModify = itemsToModify[ii];

                    // skip items that have already been processed.
                    if (itemToModify.Processed || monitoredItems[ii] == null)
                    {
                        continue;
                    }

                    // check if the node manager created the item.
                    if (!Object.ReferenceEquals(this, monitoredItems[ii].NodeManager))
                    {
                        continue;
                    }

                    // owned by this node manager.
                    itemToModify.Processed = true;

                    // validate monitored item.
                    MonitoredItem monitoredItem = null;

                    if (!m_monitoredItems.TryGetValue(monitoredItems[ii].Id, out monitoredItem))
                    {
                        errors[ii] = StatusCodes.BadMonitoredItemIdInvalid;
                        continue;
                    }

                    if (!Object.ReferenceEquals(monitoredItem, monitoredItems[ii]))
                    {
                        errors[ii] = StatusCodes.BadMonitoredItemIdInvalid;
                        continue;
                    }

                    // find the node being monitored.

                    if (!(monitoredItem.ManagerHandle is ILocalNode node))
                    {
                        errors[ii] = StatusCodes.BadNodeIdUnknown;
                        continue;
                    }

                    // fetch the metadata for the node.
                    NodeMetadata metadata = GetNodeMetadata(context, monitoredItem.ManagerHandle, BrowseResultMask.All);

                    bool rangeRequired = false;

                    // validate the filter against the node/attribute being monitored.
                    errors[ii] = ValidateFilter(
                        metadata,
                        monitoredItem.AttributeId,
                        itemToModify.RequestedParameters.Filter,
                        out rangeRequired);

                    if (ServiceResult.IsBad(errors[ii]))
                    {
                        continue;
                    }

                    // lookup EU range if required.
                    Range range = null;

                    if (rangeRequired)
                    {
                        // look up EU range.
                        errors[ii] = ReadEURange(context, node, out range);

                        if (ServiceResult.IsBad(errors[ii]))
                        {
                            continue;
                        }
                    }

                    // update sampling.
                    errors[ii] = m_samplingGroupManager.ModifyMonitoredItem(
                        context,
                        timestampsToReturn,
                        monitoredItem,
                        itemToModify,
                        range);

                    // state of item did not change if an error returned here.
                    if (ServiceResult.IsBad(errors[ii]))
                    {
                        continue;
                    }

                    // item has been modified successfully.
                    // errors updating the sampling groups will be reported in notifications.
                    errors[ii] = StatusCodes.Good;
                }
            }

            // update all sampling groups.
            m_samplingGroupManager.ApplyChanges();
        }

        /// <summary>
        /// Deletes a set of monitored items.
        /// </summary>
        public void DeleteMonitoredItems(
            OperationContext context,
            IList<IMonitoredItem> monitoredItems,
            IList<bool> processedItems,
            IList<ServiceResult> errors)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (monitoredItems == null)
            {
                throw new ArgumentNullException(nameof(monitoredItems));
            }

            if (errors == null)
            {
                throw new ArgumentNullException(nameof(errors));
            }

            lock (m_lock)
            {
                for (int ii = 0; ii < errors.Count; ii++)
                {
                    // skip items that have already been processed.
                    if (processedItems[ii] || monitoredItems[ii] == null)
                    {
                        continue;
                    }

                    // check if the node manager created the item.
                    if (!Object.ReferenceEquals(this, monitoredItems[ii].NodeManager))
                    {
                        continue;
                    }

                    // owned by this node manager.
                    processedItems[ii] = true;

                    // validate monitored item.
                    MonitoredItem monitoredItem = null;

                    if (!m_monitoredItems.TryGetValue(monitoredItems[ii].Id, out monitoredItem))
                    {
                        errors[ii] = StatusCodes.BadMonitoredItemIdInvalid;
                        continue;
                    }

                    if (!Object.ReferenceEquals(monitoredItem, monitoredItems[ii]))
                    {
                        errors[ii] = StatusCodes.BadMonitoredItemIdInvalid;
                        continue;
                    }

                    // remove item.
                    m_samplingGroupManager.StopMonitoring(monitoredItem);

                    // remove association with the group.
                    m_monitoredItems.Remove(monitoredItem.Id);

                    // delete successful.
                    errors[ii] = StatusCodes.Good;
                }
            }

            // remove all items from groups.
            m_samplingGroupManager.ApplyChanges();
        }

        /// <summary>
        /// Transfers a set of monitored items.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="sendInitialValues">Whether the subscription should send initial values after transfer.</param>
        /// <param name="monitoredItems">The set of monitoring items to update.</param>
        /// <param name="processedItems">The set of processed items.</param>
        /// <param name="errors">Any errors.</param>
        public virtual void TransferMonitoredItems(
            OperationContext context,
            bool sendInitialValues,
            IList<IMonitoredItem> monitoredItems,
            IList<bool> processedItems,
            IList<ServiceResult> errors)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (monitoredItems == null)
            {
                throw new ArgumentNullException(nameof(monitoredItems));
            }

            if (processedItems == null)
            {
                throw new ArgumentNullException(nameof(processedItems));
            }

            lock (m_lock)
            {
                for (int ii = 0; ii < monitoredItems.Count; ii++)
                {
                    // skip items that have already been processed.
                    if (processedItems[ii] || monitoredItems[ii] == null)
                    {
                        continue;
                    }

                    // check if the node manager created the item.
                    if (!Object.ReferenceEquals(this, monitoredItems[ii].NodeManager))
                    {
                        continue;
                    }

                    // owned by this node manager.
                    processedItems[ii] = true;

                    // validate monitored item.
                    IMonitoredItem monitoredItem = monitoredItems[ii];

                    // find the node being monitored.
                    if (!(monitoredItem.ManagerHandle is ILocalNode node))
                    {
                        continue;
                    }

                    if (sendInitialValues && !monitoredItem.IsReadyToPublish)
                    {
                        if (monitoredItem is IDataChangeMonitoredItem2 dataChangeMonitoredItem)
                        {
                            errors[ii] = ReadInitialValue(context, node, dataChangeMonitoredItem);
                        }
                    }
                    else
                    {
                        errors[ii] = StatusCodes.Good;
                    }
                }
            }
        }

        /// <summary>
        /// Changes the monitoring mode for a set of monitored items.
        /// </summary>
        public void SetMonitoringMode(
            OperationContext context,
            MonitoringMode monitoringMode,
            IList<IMonitoredItem> monitoredItems,
            IList<bool> processedItems,
            IList<ServiceResult> errors)
        {

            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (monitoredItems == null)
            {
                throw new ArgumentNullException(nameof(monitoredItems));
            }

            if (errors == null)
            {
                throw new ArgumentNullException(nameof(errors));
            }

            lock (m_lock)
            {
                for (int ii = 0; ii < errors.Count; ii++)
                {
                    // skip items that have already been processed.
                    if (processedItems[ii] || monitoredItems[ii] == null)
                    {
                        continue;
                    }

                    // check if the node manager created the item.
                    if (!Object.ReferenceEquals(this, monitoredItems[ii].NodeManager))
                    {
                        continue;
                    }

                    // owned by this node manager.
                    processedItems[ii] = true;

                    // validate monitored item.
                    MonitoredItem monitoredItem = null;

                    if (!m_monitoredItems.TryGetValue(monitoredItems[ii].Id, out monitoredItem))
                    {
                        errors[ii] = StatusCodes.BadMonitoredItemIdInvalid;
                        continue;
                    }

                    if (!Object.ReferenceEquals(monitoredItem, monitoredItems[ii]))
                    {
                        errors[ii] = StatusCodes.BadMonitoredItemIdInvalid;
                        continue;
                    }

                    // update monitoring mode.
                    MonitoringMode previousMode = monitoredItem.SetMonitoringMode(monitoringMode);

                    // need to provide an immediate update after enabling.
                    if (previousMode == MonitoringMode.Disabled && monitoringMode != MonitoringMode.Disabled)
                    {
                        var initialValue = new DataValue {
                            ServerTimestamp = DateTime.UtcNow,
                            StatusCode = StatusCodes.BadWaitingForInitialData
                        };

                        // read the initial value.

                        if (monitoredItem.ManagerHandle is Node node)
                        {
                            ServiceResult error = node.Read(context, monitoredItem.AttributeId, initialValue);

                            if (ServiceResult.IsBad(error))
                            {
                                initialValue.Value = null;
                                initialValue.StatusCode = error.StatusCode;
                            }
                        }

                        monitoredItem.QueueValue(initialValue, null);
                    }

                    // modify the item attributes.
                    m_samplingGroupManager.ModifyMonitoring(context, monitoredItem);

                    // item has been modified successfully.
                    // errors updating the sampling groups will be reported in notifications.
                    errors[ii] = StatusCodes.Good;
                }
            }

            // update all sampling groups.
            m_samplingGroupManager.ApplyChanges();
        }



        /// <summary>
        /// Returns true if the node class matches the node class mask.
        /// </summary>
        public static bool CheckNodeClassMask(uint nodeClassMask, NodeClass nodeClass)
        {
            if (nodeClassMask != 0)
            {
                return ((uint)nodeClass & nodeClassMask) != 0;
            }

            return true;
        }



        /// <summary>
        /// The server that the node manager belongs to.
        /// </summary>
        protected IServerInternal Server => m_server;

        /// <summary>
        /// A node in the type system that is used to instantiate objects or variables.
        /// </summary>
        private class DeclarationNode
        {
            public ILocalNode Node;
            public string BrowsePath;
        }

        /// <summary>
        /// Builds the list of declaration nodes for a type definition.
        /// </summary>
        private void BuildDeclarationList(ILocalNode typeDefinition, List<DeclarationNode> declarations)
        {
            if (typeDefinition == null)
            {
                throw new ArgumentNullException(nameof(typeDefinition));
            }

            if (declarations == null)
            {
                throw new ArgumentNullException(nameof(declarations));
            }

            // guard against loops (i.e. common grandparents).
            for (int ii = 0; ii < declarations.Count; ii++)
            {
                if (Object.ReferenceEquals(declarations[ii].Node, typeDefinition))
                {
                    return;
                }
            }

            // create the root declaration for the type.
            var declaration = new DeclarationNode {
                Node = typeDefinition,
                BrowsePath = string.Empty
            };

            declarations.Add(declaration);

            // follow references to supertypes first.
            foreach (IReference reference in typeDefinition.References.Find(ReferenceTypeIds.HasSubtype, true, false, null))
            {
                var supertype = GetLocalNode(reference.TargetId);

                if (supertype == null)
                {
                    continue;
                }

                BuildDeclarationList(supertype, declarations);
            }

            // add children of type.
            BuildDeclarationList(declaration, declarations);
        }

        /// <summary>
        /// Builds a list of declarations from the nodes aggregated by a parent.
        /// </summary>
        private void BuildDeclarationList(DeclarationNode parent, List<DeclarationNode> declarations)
        {
            if (parent == null)
            {
                throw new ArgumentNullException(nameof(parent));
            }

            if (declarations == null)
            {
                throw new ArgumentNullException(nameof(declarations));
            }

            // get list of children.
            IList<IReference> references = parent.Node.References.Find(ReferenceTypeIds.HierarchicalReferences, false, true, m_nodes.TypeTree);

            foreach (IReference reference in references)
            {
                // do not follow sub-type references.
                if (m_nodes.TypeTree.IsTypeOf(reference.ReferenceTypeId, ReferenceTypeIds.HasSubtype))
                {
                    continue;
                }

                // find child (ignore children that are not in the node table).
                var child = GetLocalNode(reference.TargetId);

                if (child == null)
                {
                    continue;
                }

                // create the declartion node.
                var declaration = new DeclarationNode {
                    Node = child,
                    BrowsePath = Utils.Format("{0}.{1}", parent.BrowsePath, child.BrowseName)
                };

                declarations.Add(declaration);

                // recursively include aggregated children.
                NodeId modellingRule = child.ModellingRule;

                if (modellingRule == Objects.ModellingRule_Mandatory || modellingRule == Objects.ModellingRule_Optional)
                {
                    BuildDeclarationList(declaration, declarations);
                }
            }
        }

        /// <summary>
        /// Builds a table of instances indexed by browse path from the nodes aggregated by a parent
        /// </summary>
        private void BuildInstanceList(ILocalNode parent, string browsePath, IDictionary<string, ILocalNode> instances)
        {
            if (parent == null)
            {
                throw new ArgumentNullException(nameof(parent));
            }

            if (instances == null)
            {
                throw new ArgumentNullException(nameof(instances));
            }

            // guard against loops.
            if (instances.ContainsKey(browsePath))
            {
                return;
            }

            // index parent by browse path.
            instances[browsePath] = parent;

            // get list of children.
            IList<IReference> references = parent.References.Find(ReferenceTypeIds.HierarchicalReferences, false, true, m_nodes.TypeTree);

            foreach (IReference reference in references)
            {
                // find child (ignore children that are not in the node table).
                var child = GetLocalNode(reference.TargetId);

                if (child == null)
                {
                    continue;
                }

                // recursively include aggregated children.
                BuildInstanceList(child, Utils.Format("{0}.{1}", browsePath, child.BrowseName), instances);
            }
        }

        /// <summary>
        /// Exports a node to a nodeset.
        /// </summary>
        public void ExportNode(ILocalNode node, NodeSet nodeSet, bool instance)
        {
            lock (m_lock)
            {
                // check if the node has already been added.
                NodeId exportedId = nodeSet.Export(node.NodeId, m_nodes.NamespaceUris);

                if (nodeSet.Contains(exportedId))
                {
                    return;
                }

                // add to nodeset.
                Node nodeToExport = nodeSet.Add(node, m_nodes.NamespaceUris, m_nodes.ServerUris);

                // follow children.
                foreach (ReferenceNode reference in node.References)
                {
                    // export all references.
                    bool export = true;

                    // unless it is a subtype reference.
                    if (m_server.TypeTree.IsTypeOf(reference.ReferenceTypeId, ReferenceTypeIds.HasSubtype))
                    {
                        export = false;
                    }

                    if (export)
                    {
                        nodeSet.AddReference(nodeToExport, reference, m_nodes.NamespaceUris, m_nodes.ServerUris);
                    }

                    if (reference.IsInverse || m_server.TypeTree.IsTypeOf(reference.ReferenceTypeId, ReferenceTypeIds.HasSubtype))
                    {
                        nodeSet.AddReference(nodeToExport, reference, m_nodes.NamespaceUris, m_nodes.ServerUris);
                    }

                    if (m_server.TypeTree.IsTypeOf(reference.ReferenceTypeId, ReferenceTypeIds.Aggregates))
                    {
                        if (reference.IsInverse)
                        {
                            continue;
                        }

                        var child = GetLocalNode(reference.TargetId);

                        if (child != null)
                        {
                            if (instance)
                            {
                                NodeId modellingRule = child.ModellingRule;

                                if (modellingRule != Objects.ModellingRule_Mandatory)
                                {
                                    continue;
                                }
                            }

                            ExportNode(child, nodeSet, instance);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Deletes a node from the address sapce.
        /// </summary>
        private void DeleteNode(ILocalNode node, bool deleteChildren, bool instance, Dictionary<NodeId, IList<IReference>> referencesToDelete)
        {
            if (node == null)
            {
                throw new ArgumentNullException(nameof(node));
            }

            var nodesToDelete = new List<ILocalNode>();
            var referencesForNode = new List<IReference>();

            lock (m_lock)
            {
                // remove the node.
                m_nodes.Remove(node.NodeId);

                // check need to connect subtypes to the supertype if they are being deleted.
                ExpandedNodeId supertypeId = m_server.TypeTree.FindSuperType(node.NodeId);

                if (!NodeId.IsNull(supertypeId))
                {
                    m_server.TypeTree.Remove(node.NodeId);
                }

                // remove any references to the node.
                foreach (IReference reference in node.References)
                {
                    // ignore remote references.
                    if (reference.TargetId.IsAbsolute)
                    {
                        continue;
                    }

                    // find the target.

                    if (!(GetManagerHandle(reference.TargetId) is ILocalNode target))
                    {
                        referencesForNode.Add(reference);
                        continue;
                    }

                    // delete the backward reference.
                    target.References.Remove(reference.ReferenceTypeId, !reference.IsInverse, node.NodeId);

                    // check for children that need to be deleted.
                    if (deleteChildren)
                    {
                        if (m_server.TypeTree.IsTypeOf(reference.ReferenceTypeId, ReferenceTypeIds.Aggregates) && !reference.IsInverse)
                        {
                            nodesToDelete.Add(target);
                        }
                    }
                }

                if (referencesForNode.Count > 0)
                {
                    referencesToDelete[node.NodeId] = referencesForNode;
                }
            }

            // delete the child nodes.
            foreach (ILocalNode nodeToDelete in nodesToDelete)
            {
                DeleteNode(nodeToDelete, deleteChildren, instance, referencesToDelete);
            }
        }

        /// <summary>
        /// Ensures any changes to built-in nodes are reflected in the diagnostics node manager.
        /// </summary>
        private void AddReferenceToLocalNode(
            ILocalNode source,
            NodeId referenceTypeId,
            bool isInverse,
            ExpandedNodeId targetId,
            bool isInternal)
        {
            source.References.Add(referenceTypeId, isInverse, targetId);

            if (!isInternal && source.NodeId.NamespaceIndex == 0)
            {
                lock (Server.DiagnosticsNodeManager.Lock)
                {
                    NodeState state = Server.DiagnosticsNodeManager.FindPredefinedNode(source.NodeId, null);

                    if (state != null)
                    {
                        INodeBrowser browser = state.CreateBrowser(
                            m_server.DefaultSystemContext,
                            null,
                            referenceTypeId,
                            true,
                            (isInverse) ? BrowseDirection.Inverse : BrowseDirection.Forward,
                            null,
                            null,
                            true);

                        bool found = false;

                        for (IReference reference = browser.Next(); reference != null; reference = browser.Next())
                        {
                            if (reference.TargetId == targetId)
                            {
                                found = true;
                                break;
                            }
                        }

                        if (!found)
                        {
                            state.AddReference(referenceTypeId, isInverse, targetId);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Adds a reference to the address space.
        /// </summary>
        private void AddReference(
            ILocalNode source,
            NodeId referenceTypeId,
            bool isInverse,
            ExpandedNodeId targetId)
        {
            AddReferenceToLocalNode(source, referenceTypeId, isInverse, targetId, false);
        }

        /// <summary>
        /// Deletes a reference.
        /// </summary>
        public ServiceResult DeleteReference(
            object sourceHandle,
            NodeId referenceTypeId,
            bool isInverse,
            ExpandedNodeId targetId,
            bool deleteBidirectional)
        {
            if (sourceHandle == null)
            {
                throw new ArgumentNullException(nameof(sourceHandle));
            }

            if (referenceTypeId == null)
            {
                throw new ArgumentNullException(nameof(referenceTypeId));
            }

            if (targetId == null)
            {
                throw new ArgumentNullException(nameof(targetId));
            }

            lock (m_lock)
            {
                if (!(sourceHandle is ILocalNode source))
                {
                    return StatusCodes.BadSourceNodeIdInvalid;
                }

                source.References.Remove(referenceTypeId, isInverse, targetId);

                if (deleteBidirectional)
                {
                    if (GetManagerHandle(targetId) is ILocalNode target)
                    {
                        target.References.Remove(referenceTypeId, !isInverse, source.NodeId);
                    }
                }

                return ServiceResult.Good;
            }
        }

        /// <summary>
        /// Adds a node to the address space.
        /// </summary>
        private void AddNode(ILocalNode node)
        {
            m_nodes.Attach(node);
        }


        /// <summary>
        /// Returns a node managed by the manager with the specified node id.
        /// </summary>
        public ILocalNode GetLocalNode(ExpandedNodeId nodeId)
        {
            if (nodeId == null)
            {
                return null;
            }

            // check for absolute declarations of local nodes.
            if (nodeId.IsAbsolute)
            {
                if (nodeId.ServerIndex != 0)
                {
                    return null;
                }

                int namespaceIndex = Server.NamespaceUris.GetIndex(nodeId.NamespaceUri);

                if (namespaceIndex < 0 || nodeId.NamespaceIndex >= Server.NamespaceUris.Count)
                {
                    return null;
                }

                return GetLocalNode(new NodeId(nodeId.Identifier, (ushort)namespaceIndex));
            }

            return GetLocalNode((NodeId)nodeId);
        }

        /// <summary>
        /// Returns a node managed by the manager with the specified node id.
        /// </summary>
        public ILocalNode GetLocalNode(NodeId nodeId)
        {
            lock (m_lock)
            {
                return m_nodes.Find(nodeId) as ILocalNode;
            }
        }

        /// <summary>
        /// Returns a node managed by the manager that has the specified browse name.
        /// </summary>
        private ILocalNode GetTargetNode(
            ILocalNode source,
            NodeId referenceTypeId,
            bool isInverse,
            bool includeSubtypes,
            QualifiedName browseName)
        {
            foreach (IReference reference in source.References.Find(referenceTypeId, isInverse, includeSubtypes, m_server.TypeTree))
            {
                var target = GetLocalNode(reference.TargetId);

                if (target == null)
                {
                    continue;
                }

                if (QualifiedName.IsNull(browseName) || browseName == target.BrowseName)
                {
                    return target;
                }
            }

            return null;
        }

        /// <summary>
        /// Attaches a node to the address space.
        /// </summary>
        private void AttachNode(ILocalNode node, bool isInternal)
        {
            if (node == null)
            {
                throw new ArgumentNullException(nameof(node));
            }

            lock (m_lock)
            {
                // check if node exists.
                if (m_nodes.Exists(node.NodeId))
                {
                    throw ServiceResultException.Create(
                        StatusCodes.BadNodeIdExists,
                        "A node with the same node id already exists: {0}",
                        node.NodeId);
                }

                // ensure reverse references exist.
                foreach (IReference reference in node.References)
                {
                    // ignore references that are always one way.
                    if (reference.ReferenceTypeId == ReferenceTypeIds.HasTypeDefinition || reference.ReferenceTypeId == ReferenceTypeIds.HasModellingRule)
                    {
                        continue;
                    }

                    // find target.
                    var target = GetLocalNode(reference.TargetId);

                    if (target != null)
                    {
                        AddReferenceToLocalNode(target, reference.ReferenceTypeId, !reference.IsInverse, node.NodeId, isInternal);
                    }
                }

                // must generate a model change event.
                AddNode(node);
            }
        }


        /// <see cref="INodeManager.GetManagerHandle" />
        private object GetManagerHandle(ExpandedNodeId nodeId)
        {
            lock (m_lock)
            {
                if (nodeId == null || nodeId.IsAbsolute)
                {
                    return null;
                }

                return GetLocalNode(nodeId);
            }
        }

        /// <summary>
        /// Reads the EU Range for a variable.
        /// </summary>
        private ServiceResult ReadEURange(OperationContext context, ILocalNode node, out Range range)
        {
            range = null;


            if (!(GetTargetNode(node, ReferenceTypes.HasProperty, false, true, BrowseNames.EURange) is IVariable target))
            {
                return StatusCodes.BadNodeIdUnknown;
            }

            range = target.Value as Range;

            if (range == null)
            {
                return StatusCodes.BadTypeMismatch;
            }

            return ServiceResult.Good;
        }

        /// <summary>
        /// Validates a filter for a monitored item.
        /// </summary>
        private ServiceResult ValidateFilter(
            NodeMetadata metadata,
            uint attributeId,
            ExtensionObject filter,
            out bool rangeRequired)
        {
            rangeRequired = false;

            // check filter.
            DataChangeFilter datachangeFilter = null;

            if (filter != null)
            {
                datachangeFilter = filter.Body as DataChangeFilter;
            }

            if (datachangeFilter != null)
            {
                // get the datatype of the node.
                NodeId datatypeId = metadata.DataType;

                // check that filter is valid.
                ServiceResult error = datachangeFilter.Validate();

                if (ServiceResult.IsBad(error))
                {
                    return error;
                }

                // check datatype of the variable.
                if (!m_server.TypeTree.IsTypeOf(datatypeId, DataTypes.Number))
                {
                    return StatusCodes.BadDeadbandFilterInvalid;
                }

                // percent deadbands only allowed for analog data items.
                if (datachangeFilter.DeadbandType == (int)DeadbandType.Percent)
                {
                    ExpandedNodeId typeDefinitionId = metadata.TypeDefinition;

                    if (typeDefinitionId == null)
                    {
                        return StatusCodes.BadDeadbandFilterInvalid;
                    }

                    // percent deadbands only allowed for analog data items.
                    if (!m_server.TypeTree.IsTypeOf(typeDefinitionId, VariableTypes.AnalogItemType))
                    {
                        return StatusCodes.BadDeadbandFilterInvalid;
                    }

                    // the EURange property is required to use the filter.
                    rangeRequired = true;
                }
            }

            // filter is valid
            return ServiceResult.Good;
        }



        private readonly object m_lock = new object();
        private readonly IServerInternal m_server;
        private readonly NodeTable m_nodes;
        private readonly SamplingGroupManager m_samplingGroupManager;
        private readonly Dictionary<uint, MonitoredItem> m_monitoredItems;
        private readonly double m_defaultMinimumSamplingInterval;
        private readonly List<string> m_namespaceUris;
        private readonly ushort m_dynamicNamespaceIndex;

    }

}
