/* ========================================================================
 * Copyright (c) 2005-2016 The OPC Foundation, Inc. All rights reserved.
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

namespace Opc.Ua
{
    #region ISessionServer Interface
    /// <summary>
    /// An interface to a UA server implementation.
    /// </summary>
    /// <exclude />
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.CodeGenerator", "1.0.0.0")]
    public interface ISessionServer : IServerBase
    {
        #if (!OPCUA_EXCLUDE_FindServers)
        /// <summary>
        /// Invokes the FindServers service.
        /// </summary>
        ResponseHeader FindServers(
            RequestHeader                        requestHeader,
            string                               endpointUrl,
            StringCollection                     localeIds,
            StringCollection                     serverUris,
            out ApplicationDescriptionCollection servers);
        #endif

        #if (!OPCUA_EXCLUDE_FindServersOnNetwork)
        /// <summary>
        /// Invokes the FindServersOnNetwork service.
        /// </summary>
        ResponseHeader FindServersOnNetwork(
            RequestHeader                 requestHeader,
            uint                          startingRecordId,
            uint                          maxRecordsToReturn,
            StringCollection              serverCapabilityFilter,
            out DateTime                  lastCounterResetTime,
            out ServerOnNetworkCollection servers);
        #endif

        #if (!OPCUA_EXCLUDE_GetEndpoints)
        /// <summary>
        /// Invokes the GetEndpoints service.
        /// </summary>
        ResponseHeader GetEndpoints(
            RequestHeader                     requestHeader,
            string                            endpointUrl,
            StringCollection                  localeIds,
            StringCollection                  profileUris,
            out EndpointDescriptionCollection endpoints);
        #endif

        #if (!OPCUA_EXCLUDE_CreateSession)
        /// <summary>
        /// Invokes the CreateSession service.
        /// </summary>
        ResponseHeader CreateSession(
            RequestHeader                           requestHeader,
            ApplicationDescription                  clientDescription,
            string                                  serverUri,
            string                                  endpointUrl,
            string                                  sessionName,
            byte[]                                  clientNonce,
            byte[]                                  clientCertificate,
            double                                  requestedSessionTimeout,
            uint                                    maxResponseMessageSize,
            out NodeId                              sessionId,
            out NodeId                              authenticationToken,
            out double                              revisedSessionTimeout,
            out byte[]                              serverNonce,
            out byte[]                              serverCertificate,
            out EndpointDescriptionCollection       serverEndpoints,
            out SignedSoftwareCertificateCollection serverSoftwareCertificates,
            out SignatureData                       serverSignature,
            out uint                                maxRequestMessageSize);
        #endif

        #if (!OPCUA_EXCLUDE_ActivateSession)
        /// <summary>
        /// Invokes the ActivateSession service.
        /// </summary>
        ResponseHeader ActivateSession(
            RequestHeader                       requestHeader,
            SignatureData                       clientSignature,
            SignedSoftwareCertificateCollection clientSoftwareCertificates,
            StringCollection                    localeIds,
            ExtensionObject                     userIdentityToken,
            SignatureData                       userTokenSignature,
            out byte[]                          serverNonce,
            out StatusCodeCollection            results,
            out DiagnosticInfoCollection        diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_CloseSession)
        /// <summary>
        /// Invokes the CloseSession service.
        /// </summary>
        ResponseHeader CloseSession(
            RequestHeader requestHeader,
            bool          deleteSubscriptions);
        #endif

        #if (!OPCUA_EXCLUDE_Cancel)
        /// <summary>
        /// Invokes the Cancel service.
        /// </summary>
        ResponseHeader Cancel(
            RequestHeader requestHeader,
            uint          requestHandle,
            out uint      cancelCount);
        #endif

        #if (!OPCUA_EXCLUDE_AddNodes)
        /// <summary>
        /// Invokes the AddNodes service.
        /// </summary>
        ResponseHeader AddNodes(
            RequestHeader                requestHeader,
            AddNodesItemCollection       nodesToAdd,
            out AddNodesResultCollection results,
            out DiagnosticInfoCollection diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_AddReferences)
        /// <summary>
        /// Invokes the AddReferences service.
        /// </summary>
        ResponseHeader AddReferences(
            RequestHeader                requestHeader,
            AddReferencesItemCollection  referencesToAdd,
            out StatusCodeCollection     results,
            out DiagnosticInfoCollection diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_DeleteNodes)
        /// <summary>
        /// Invokes the DeleteNodes service.
        /// </summary>
        ResponseHeader DeleteNodes(
            RequestHeader                requestHeader,
            DeleteNodesItemCollection    nodesToDelete,
            out StatusCodeCollection     results,
            out DiagnosticInfoCollection diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_DeleteReferences)
        /// <summary>
        /// Invokes the DeleteReferences service.
        /// </summary>
        ResponseHeader DeleteReferences(
            RequestHeader                  requestHeader,
            DeleteReferencesItemCollection referencesToDelete,
            out StatusCodeCollection       results,
            out DiagnosticInfoCollection   diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_Browse)
        /// <summary>
        /// Invokes the Browse service.
        /// </summary>
        ResponseHeader Browse(
            RequestHeader                requestHeader,
            ViewDescription              view,
            uint                         requestedMaxReferencesPerNode,
            BrowseDescriptionCollection  nodesToBrowse,
            out BrowseResultCollection   results,
            out DiagnosticInfoCollection diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_BrowseNext)
        /// <summary>
        /// Invokes the BrowseNext service.
        /// </summary>
        ResponseHeader BrowseNext(
            RequestHeader                requestHeader,
            bool                         releaseContinuationPoints,
            ByteStringCollection         continuationPoints,
            out BrowseResultCollection   results,
            out DiagnosticInfoCollection diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_TranslateBrowsePathsToNodeIds)
        /// <summary>
        /// Invokes the TranslateBrowsePathsToNodeIds service.
        /// </summary>
        ResponseHeader TranslateBrowsePathsToNodeIds(
            RequestHeader                  requestHeader,
            BrowsePathCollection           browsePaths,
            out BrowsePathResultCollection results,
            out DiagnosticInfoCollection   diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_RegisterNodes)
        /// <summary>
        /// Invokes the RegisterNodes service.
        /// </summary>
        ResponseHeader RegisterNodes(
            RequestHeader        requestHeader,
            NodeIdCollection     nodesToRegister,
            out NodeIdCollection registeredNodeIds);
        #endif

        #if (!OPCUA_EXCLUDE_UnregisterNodes)
        /// <summary>
        /// Invokes the UnregisterNodes service.
        /// </summary>
        ResponseHeader UnregisterNodes(
            RequestHeader    requestHeader,
            NodeIdCollection nodesToUnregister);
        #endif

        #if (!OPCUA_EXCLUDE_QueryFirst)
        /// <summary>
        /// Invokes the QueryFirst service.
        /// </summary>
        ResponseHeader QueryFirst(
            RequestHeader                 requestHeader,
            ViewDescription               view,
            NodeTypeDescriptionCollection nodeTypes,
            ContentFilter                 filter,
            uint                          maxDataSetsToReturn,
            uint                          maxReferencesToReturn,
            out QueryDataSetCollection    queryDataSets,
            out byte[]                    continuationPoint,
            out ParsingResultCollection   parsingResults,
            out DiagnosticInfoCollection  diagnosticInfos,
            out ContentFilterResult       filterResult);
        #endif

        #if (!OPCUA_EXCLUDE_QueryNext)
        /// <summary>
        /// Invokes the QueryNext service.
        /// </summary>
        ResponseHeader QueryNext(
            RequestHeader              requestHeader,
            bool                       releaseContinuationPoint,
            byte[]                     continuationPoint,
            out QueryDataSetCollection queryDataSets,
            out byte[]                 revisedContinuationPoint);
        #endif

        #if (!OPCUA_EXCLUDE_Read)
        /// <summary>
        /// Invokes the Read service.
        /// </summary>
        ResponseHeader Read(
            RequestHeader                requestHeader,
            double                       maxAge,
            TimestampsToReturn           timestampsToReturn,
            ReadValueIdCollection        nodesToRead,
            out DataValueCollection      results,
            out DiagnosticInfoCollection diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_HistoryRead)
        /// <summary>
        /// Invokes the HistoryRead service.
        /// </summary>
        ResponseHeader HistoryRead(
            RequestHeader                   requestHeader,
            ExtensionObject                 historyReadDetails,
            TimestampsToReturn              timestampsToReturn,
            bool                            releaseContinuationPoints,
            HistoryReadValueIdCollection    nodesToRead,
            out HistoryReadResultCollection results,
            out DiagnosticInfoCollection    diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_Write)
        /// <summary>
        /// Invokes the Write service.
        /// </summary>
        ResponseHeader Write(
            RequestHeader                requestHeader,
            WriteValueCollection         nodesToWrite,
            out StatusCodeCollection     results,
            out DiagnosticInfoCollection diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_HistoryUpdate)
        /// <summary>
        /// Invokes the HistoryUpdate service.
        /// </summary>
        ResponseHeader HistoryUpdate(
            RequestHeader                     requestHeader,
            ExtensionObjectCollection         historyUpdateDetails,
            out HistoryUpdateResultCollection results,
            out DiagnosticInfoCollection      diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_Call)
        /// <summary>
        /// Invokes the Call service.
        /// </summary>
        ResponseHeader Call(
            RequestHeader                  requestHeader,
            CallMethodRequestCollection    methodsToCall,
            out CallMethodResultCollection results,
            out DiagnosticInfoCollection   diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_CreateMonitoredItems)
        /// <summary>
        /// Invokes the CreateMonitoredItems service.
        /// </summary>
        ResponseHeader CreateMonitoredItems(
            RequestHeader                           requestHeader,
            uint                                    subscriptionId,
            TimestampsToReturn                      timestampsToReturn,
            MonitoredItemCreateRequestCollection    itemsToCreate,
            out MonitoredItemCreateResultCollection results,
            out DiagnosticInfoCollection            diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_ModifyMonitoredItems)
        /// <summary>
        /// Invokes the ModifyMonitoredItems service.
        /// </summary>
        ResponseHeader ModifyMonitoredItems(
            RequestHeader                           requestHeader,
            uint                                    subscriptionId,
            TimestampsToReturn                      timestampsToReturn,
            MonitoredItemModifyRequestCollection    itemsToModify,
            out MonitoredItemModifyResultCollection results,
            out DiagnosticInfoCollection            diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_SetMonitoringMode)
        /// <summary>
        /// Invokes the SetMonitoringMode service.
        /// </summary>
        ResponseHeader SetMonitoringMode(
            RequestHeader                requestHeader,
            uint                         subscriptionId,
            MonitoringMode               monitoringMode,
            UInt32Collection             monitoredItemIds,
            out StatusCodeCollection     results,
            out DiagnosticInfoCollection diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_SetTriggering)
        /// <summary>
        /// Invokes the SetTriggering service.
        /// </summary>
        ResponseHeader SetTriggering(
            RequestHeader                requestHeader,
            uint                         subscriptionId,
            uint                         triggeringItemId,
            UInt32Collection             linksToAdd,
            UInt32Collection             linksToRemove,
            out StatusCodeCollection     addResults,
            out DiagnosticInfoCollection addDiagnosticInfos,
            out StatusCodeCollection     removeResults,
            out DiagnosticInfoCollection removeDiagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_DeleteMonitoredItems)
        /// <summary>
        /// Invokes the DeleteMonitoredItems service.
        /// </summary>
        ResponseHeader DeleteMonitoredItems(
            RequestHeader                requestHeader,
            uint                         subscriptionId,
            UInt32Collection             monitoredItemIds,
            out StatusCodeCollection     results,
            out DiagnosticInfoCollection diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_CreateSubscription)
        /// <summary>
        /// Invokes the CreateSubscription service.
        /// </summary>
        ResponseHeader CreateSubscription(
            RequestHeader requestHeader,
            double        requestedPublishingInterval,
            uint          requestedLifetimeCount,
            uint          requestedMaxKeepAliveCount,
            uint          maxNotificationsPerPublish,
            bool          publishingEnabled,
            byte          priority,
            out uint      subscriptionId,
            out double    revisedPublishingInterval,
            out uint      revisedLifetimeCount,
            out uint      revisedMaxKeepAliveCount);
        #endif

        #if (!OPCUA_EXCLUDE_ModifySubscription)
        /// <summary>
        /// Invokes the ModifySubscription service.
        /// </summary>
        ResponseHeader ModifySubscription(
            RequestHeader requestHeader,
            uint          subscriptionId,
            double        requestedPublishingInterval,
            uint          requestedLifetimeCount,
            uint          requestedMaxKeepAliveCount,
            uint          maxNotificationsPerPublish,
            byte          priority,
            out double    revisedPublishingInterval,
            out uint      revisedLifetimeCount,
            out uint      revisedMaxKeepAliveCount);
        #endif

        #if (!OPCUA_EXCLUDE_SetPublishingMode)
        /// <summary>
        /// Invokes the SetPublishingMode service.
        /// </summary>
        ResponseHeader SetPublishingMode(
            RequestHeader                requestHeader,
            bool                         publishingEnabled,
            UInt32Collection             subscriptionIds,
            out StatusCodeCollection     results,
            out DiagnosticInfoCollection diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_Publish)
        /// <summary>
        /// Invokes the Publish service.
        /// </summary>
        ResponseHeader Publish(
            RequestHeader                         requestHeader,
            SubscriptionAcknowledgementCollection subscriptionAcknowledgements,
            out uint                              subscriptionId,
            out UInt32Collection                  availableSequenceNumbers,
            out bool                              moreNotifications,
            out NotificationMessage               notificationMessage,
            out StatusCodeCollection              results,
            out DiagnosticInfoCollection          diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_Republish)
        /// <summary>
        /// Invokes the Republish service.
        /// </summary>
        ResponseHeader Republish(
            RequestHeader           requestHeader,
            uint                    subscriptionId,
            uint                    retransmitSequenceNumber,
            out NotificationMessage notificationMessage);
        #endif

        #if (!OPCUA_EXCLUDE_TransferSubscriptions)
        /// <summary>
        /// Invokes the TransferSubscriptions service.
        /// </summary>
        ResponseHeader TransferSubscriptions(
            RequestHeader                requestHeader,
            UInt32Collection             subscriptionIds,
            bool                         sendInitialValues,
            out TransferResultCollection results,
            out DiagnosticInfoCollection diagnosticInfos);
        #endif

        #if (!OPCUA_EXCLUDE_DeleteSubscriptions)
        /// <summary>
        /// Invokes the DeleteSubscriptions service.
        /// </summary>
        ResponseHeader DeleteSubscriptions(
            RequestHeader                requestHeader,
            UInt32Collection             subscriptionIds,
            out StatusCodeCollection     results,
            out DiagnosticInfoCollection diagnosticInfos);
        #endif
    }
    #endregion

    #if (OPCUA_ASYNC_TASK || NET_STANDARD)
    #region ISessionServerAsync Interface
    /// <summary>
    /// An interface to a UA server implementation using asynchronous Task based callbacks.
    /// </summary>
    /// <exclude />
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.CodeGenerator", "1.0.0.0")]
    public interface ISessionServerAsync : IServerAsyncBase
    {
        #if (!OPCUA_EXCLUDE_FindServers)
        /// <summary>
        /// Invokes the FindServers service.
        /// </summary>
        System.Threading.Tasks.Task<FindServersResponse> FindServersAsync(
            RequestHeader                      requestHeader,
            string                             endpointUrl,
            StringCollection                   localeIds,
            StringCollection                   serverUris,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_FindServersOnNetwork)
        /// <summary>
        /// Invokes the FindServersOnNetwork service.
        /// </summary>
        System.Threading.Tasks.Task<FindServersOnNetworkResponse> FindServersOnNetworkAsync(
            RequestHeader                      requestHeader,
            uint                               startingRecordId,
            uint                               maxRecordsToReturn,
            StringCollection                   serverCapabilityFilter,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_GetEndpoints)
        /// <summary>
        /// Invokes the GetEndpoints service.
        /// </summary>
        System.Threading.Tasks.Task<GetEndpointsResponse> GetEndpointsAsync(
            RequestHeader                      requestHeader,
            string                             endpointUrl,
            StringCollection                   localeIds,
            StringCollection                   profileUris,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_CreateSession)
        /// <summary>
        /// Invokes the CreateSession service.
        /// </summary>
        System.Threading.Tasks.Task<CreateSessionResponse> CreateSessionAsync(
            RequestHeader                      requestHeader,
            ApplicationDescription             clientDescription,
            string                             serverUri,
            string                             endpointUrl,
            string                             sessionName,
            byte[]                             clientNonce,
            byte[]                             clientCertificate,
            double                             requestedSessionTimeout,
            uint                               maxResponseMessageSize,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_ActivateSession)
        /// <summary>
        /// Invokes the ActivateSession service.
        /// </summary>
        System.Threading.Tasks.Task<ActivateSessionResponse> ActivateSessionAsync(
            RequestHeader                       requestHeader,
            SignatureData                       clientSignature,
            SignedSoftwareCertificateCollection clientSoftwareCertificates,
            StringCollection                    localeIds,
            ExtensionObject                     userIdentityToken,
            SignatureData                       userTokenSignature,
            System.Threading.CancellationToken  cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_CloseSession)
        /// <summary>
        /// Invokes the CloseSession service.
        /// </summary>
        System.Threading.Tasks.Task<CloseSessionResponse> CloseSessionAsync(
            RequestHeader                      requestHeader,
            bool                               deleteSubscriptions,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_Cancel)
        /// <summary>
        /// Invokes the Cancel service.
        /// </summary>
        System.Threading.Tasks.Task<CancelResponse> CancelAsync(
            RequestHeader                      requestHeader,
            uint                               requestHandle,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_AddNodes)
        /// <summary>
        /// Invokes the AddNodes service.
        /// </summary>
        System.Threading.Tasks.Task<AddNodesResponse> AddNodesAsync(
            RequestHeader                      requestHeader,
            AddNodesItemCollection             nodesToAdd,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_AddReferences)
        /// <summary>
        /// Invokes the AddReferences service.
        /// </summary>
        System.Threading.Tasks.Task<AddReferencesResponse> AddReferencesAsync(
            RequestHeader                      requestHeader,
            AddReferencesItemCollection        referencesToAdd,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_DeleteNodes)
        /// <summary>
        /// Invokes the DeleteNodes service.
        /// </summary>
        System.Threading.Tasks.Task<DeleteNodesResponse> DeleteNodesAsync(
            RequestHeader                      requestHeader,
            DeleteNodesItemCollection          nodesToDelete,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_DeleteReferences)
        /// <summary>
        /// Invokes the DeleteReferences service.
        /// </summary>
        System.Threading.Tasks.Task<DeleteReferencesResponse> DeleteReferencesAsync(
            RequestHeader                      requestHeader,
            DeleteReferencesItemCollection     referencesToDelete,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_Browse)
        /// <summary>
        /// Invokes the Browse service.
        /// </summary>
        System.Threading.Tasks.Task<BrowseResponse> BrowseAsync(
            RequestHeader                      requestHeader,
            ViewDescription                    view,
            uint                               requestedMaxReferencesPerNode,
            BrowseDescriptionCollection        nodesToBrowse,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_BrowseNext)
        /// <summary>
        /// Invokes the BrowseNext service.
        /// </summary>
        System.Threading.Tasks.Task<BrowseNextResponse> BrowseNextAsync(
            RequestHeader                      requestHeader,
            bool                               releaseContinuationPoints,
            ByteStringCollection               continuationPoints,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_TranslateBrowsePathsToNodeIds)
        /// <summary>
        /// Invokes the TranslateBrowsePathsToNodeIds service.
        /// </summary>
        System.Threading.Tasks.Task<TranslateBrowsePathsToNodeIdsResponse> TranslateBrowsePathsToNodeIdsAsync(
            RequestHeader                      requestHeader,
            BrowsePathCollection               browsePaths,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_RegisterNodes)
        /// <summary>
        /// Invokes the RegisterNodes service.
        /// </summary>
        System.Threading.Tasks.Task<RegisterNodesResponse> RegisterNodesAsync(
            RequestHeader                      requestHeader,
            NodeIdCollection                   nodesToRegister,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_UnregisterNodes)
        /// <summary>
        /// Invokes the UnregisterNodes service.
        /// </summary>
        System.Threading.Tasks.Task<UnregisterNodesResponse> UnregisterNodesAsync(
            RequestHeader                      requestHeader,
            NodeIdCollection                   nodesToUnregister,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_QueryFirst)
        /// <summary>
        /// Invokes the QueryFirst service.
        /// </summary>
        System.Threading.Tasks.Task<QueryFirstResponse> QueryFirstAsync(
            RequestHeader                      requestHeader,
            ViewDescription                    view,
            NodeTypeDescriptionCollection      nodeTypes,
            ContentFilter                      filter,
            uint                               maxDataSetsToReturn,
            uint                               maxReferencesToReturn,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_QueryNext)
        /// <summary>
        /// Invokes the QueryNext service.
        /// </summary>
        System.Threading.Tasks.Task<QueryNextResponse> QueryNextAsync(
            RequestHeader                      requestHeader,
            bool                               releaseContinuationPoint,
            byte[]                             continuationPoint,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_Read)
        /// <summary>
        /// Invokes the Read service.
        /// </summary>
        System.Threading.Tasks.Task<ReadResponse> ReadAsync(
            RequestHeader                      requestHeader,
            double                             maxAge,
            TimestampsToReturn                 timestampsToReturn,
            ReadValueIdCollection              nodesToRead,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_HistoryRead)
        /// <summary>
        /// Invokes the HistoryRead service.
        /// </summary>
        System.Threading.Tasks.Task<HistoryReadResponse> HistoryReadAsync(
            RequestHeader                      requestHeader,
            ExtensionObject                    historyReadDetails,
            TimestampsToReturn                 timestampsToReturn,
            bool                               releaseContinuationPoints,
            HistoryReadValueIdCollection       nodesToRead,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_Write)
        /// <summary>
        /// Invokes the Write service.
        /// </summary>
        System.Threading.Tasks.Task<WriteResponse> WriteAsync(
            RequestHeader                      requestHeader,
            WriteValueCollection               nodesToWrite,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_HistoryUpdate)
        /// <summary>
        /// Invokes the HistoryUpdate service.
        /// </summary>
        System.Threading.Tasks.Task<HistoryUpdateResponse> HistoryUpdateAsync(
            RequestHeader                      requestHeader,
            ExtensionObjectCollection          historyUpdateDetails,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_Call)
        /// <summary>
        /// Invokes the Call service.
        /// </summary>
        System.Threading.Tasks.Task<CallResponse> CallAsync(
            RequestHeader                      requestHeader,
            CallMethodRequestCollection        methodsToCall,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_CreateMonitoredItems)
        /// <summary>
        /// Invokes the CreateMonitoredItems service.
        /// </summary>
        System.Threading.Tasks.Task<CreateMonitoredItemsResponse> CreateMonitoredItemsAsync(
            RequestHeader                        requestHeader,
            uint                                 subscriptionId,
            TimestampsToReturn                   timestampsToReturn,
            MonitoredItemCreateRequestCollection itemsToCreate,
            System.Threading.CancellationToken   cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_ModifyMonitoredItems)
        /// <summary>
        /// Invokes the ModifyMonitoredItems service.
        /// </summary>
        System.Threading.Tasks.Task<ModifyMonitoredItemsResponse> ModifyMonitoredItemsAsync(
            RequestHeader                        requestHeader,
            uint                                 subscriptionId,
            TimestampsToReturn                   timestampsToReturn,
            MonitoredItemModifyRequestCollection itemsToModify,
            System.Threading.CancellationToken   cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_SetMonitoringMode)
        /// <summary>
        /// Invokes the SetMonitoringMode service.
        /// </summary>
        System.Threading.Tasks.Task<SetMonitoringModeResponse> SetMonitoringModeAsync(
            RequestHeader                      requestHeader,
            uint                               subscriptionId,
            MonitoringMode                     monitoringMode,
            UInt32Collection                   monitoredItemIds,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_SetTriggering)
        /// <summary>
        /// Invokes the SetTriggering service.
        /// </summary>
        System.Threading.Tasks.Task<SetTriggeringResponse> SetTriggeringAsync(
            RequestHeader                      requestHeader,
            uint                               subscriptionId,
            uint                               triggeringItemId,
            UInt32Collection                   linksToAdd,
            UInt32Collection                   linksToRemove,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_DeleteMonitoredItems)
        /// <summary>
        /// Invokes the DeleteMonitoredItems service.
        /// </summary>
        System.Threading.Tasks.Task<DeleteMonitoredItemsResponse> DeleteMonitoredItemsAsync(
            RequestHeader                      requestHeader,
            uint                               subscriptionId,
            UInt32Collection                   monitoredItemIds,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_CreateSubscription)
        /// <summary>
        /// Invokes the CreateSubscription service.
        /// </summary>
        System.Threading.Tasks.Task<CreateSubscriptionResponse> CreateSubscriptionAsync(
            RequestHeader                      requestHeader,
            double                             requestedPublishingInterval,
            uint                               requestedLifetimeCount,
            uint                               requestedMaxKeepAliveCount,
            uint                               maxNotificationsPerPublish,
            bool                               publishingEnabled,
            byte                               priority,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_ModifySubscription)
        /// <summary>
        /// Invokes the ModifySubscription service.
        /// </summary>
        System.Threading.Tasks.Task<ModifySubscriptionResponse> ModifySubscriptionAsync(
            RequestHeader                      requestHeader,
            uint                               subscriptionId,
            double                             requestedPublishingInterval,
            uint                               requestedLifetimeCount,
            uint                               requestedMaxKeepAliveCount,
            uint                               maxNotificationsPerPublish,
            byte                               priority,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_SetPublishingMode)
        /// <summary>
        /// Invokes the SetPublishingMode service.
        /// </summary>
        System.Threading.Tasks.Task<SetPublishingModeResponse> SetPublishingModeAsync(
            RequestHeader                      requestHeader,
            bool                               publishingEnabled,
            UInt32Collection                   subscriptionIds,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_Publish)
        /// <summary>
        /// Invokes the Publish service.
        /// </summary>
        System.Threading.Tasks.Task<PublishResponse> PublishAsync(
            RequestHeader                         requestHeader,
            SubscriptionAcknowledgementCollection subscriptionAcknowledgements,
            System.Threading.CancellationToken    cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_Republish)
        /// <summary>
        /// Invokes the Republish service.
        /// </summary>
        System.Threading.Tasks.Task<RepublishResponse> RepublishAsync(
            RequestHeader                      requestHeader,
            uint                               subscriptionId,
            uint                               retransmitSequenceNumber,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_TransferSubscriptions)
        /// <summary>
        /// Invokes the TransferSubscriptions service.
        /// </summary>
        System.Threading.Tasks.Task<TransferSubscriptionsResponse> TransferSubscriptionsAsync(
            RequestHeader                      requestHeader,
            UInt32Collection                   subscriptionIds,
            bool                               sendInitialValues,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_DeleteSubscriptions)
        /// <summary>
        /// Invokes the DeleteSubscriptions service.
        /// </summary>
        System.Threading.Tasks.Task<DeleteSubscriptionsResponse> DeleteSubscriptionsAsync(
            RequestHeader                      requestHeader,
            UInt32Collection                   subscriptionIds,
            System.Threading.CancellationToken cancellationToken);
        #endif
    }
    #endregion
    #endif

    #region SessionServerBase Class
    /// <summary>
    /// A basic implementation of the UA server.
    /// </summary>
    /// <exclude />
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.CodeGenerator", "1.0.0.0")]
    public partial class SessionServerBase : ServerBase, ISessionServer
    {
        #if (!OPCUA_EXCLUDE_FindServers)
        /// <summary>
        /// Invokes the FindServers service.
        /// </summary>
        public virtual ResponseHeader FindServers(
            RequestHeader                        requestHeader,
            string                               endpointUrl,
            StringCollection                     localeIds,
            StringCollection                     serverUris,
            out ApplicationDescriptionCollection servers)
        {
            servers = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_FindServersOnNetwork)
        /// <summary>
        /// Invokes the FindServersOnNetwork service.
        /// </summary>
        public virtual ResponseHeader FindServersOnNetwork(
            RequestHeader                 requestHeader,
            uint                          startingRecordId,
            uint                          maxRecordsToReturn,
            StringCollection              serverCapabilityFilter,
            out DateTime                  lastCounterResetTime,
            out ServerOnNetworkCollection servers)
        {
            lastCounterResetTime = DateTime.MinValue;
            servers = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_GetEndpoints)
        /// <summary>
        /// Invokes the GetEndpoints service.
        /// </summary>
        public virtual ResponseHeader GetEndpoints(
            RequestHeader                     requestHeader,
            string                            endpointUrl,
            StringCollection                  localeIds,
            StringCollection                  profileUris,
            out EndpointDescriptionCollection endpoints)
        {
            endpoints = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_CreateSession)
        /// <summary>
        /// Invokes the CreateSession service.
        /// </summary>
        public virtual ResponseHeader CreateSession(
            RequestHeader                           requestHeader,
            ApplicationDescription                  clientDescription,
            string                                  serverUri,
            string                                  endpointUrl,
            string                                  sessionName,
            byte[]                                  clientNonce,
            byte[]                                  clientCertificate,
            double                                  requestedSessionTimeout,
            uint                                    maxResponseMessageSize,
            out NodeId                              sessionId,
            out NodeId                              authenticationToken,
            out double                              revisedSessionTimeout,
            out byte[]                              serverNonce,
            out byte[]                              serverCertificate,
            out EndpointDescriptionCollection       serverEndpoints,
            out SignedSoftwareCertificateCollection serverSoftwareCertificates,
            out SignatureData                       serverSignature,
            out uint                                maxRequestMessageSize)
        {
            sessionId = null;
            authenticationToken = null;
            revisedSessionTimeout = 0;
            serverNonce = null;
            serverCertificate = null;
            serverEndpoints = null;
            serverSoftwareCertificates = null;
            serverSignature = null;
            maxRequestMessageSize = 0;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_ActivateSession)
        /// <summary>
        /// Invokes the ActivateSession service.
        /// </summary>
        public virtual ResponseHeader ActivateSession(
            RequestHeader                       requestHeader,
            SignatureData                       clientSignature,
            SignedSoftwareCertificateCollection clientSoftwareCertificates,
            StringCollection                    localeIds,
            ExtensionObject                     userIdentityToken,
            SignatureData                       userTokenSignature,
            out byte[]                          serverNonce,
            out StatusCodeCollection            results,
            out DiagnosticInfoCollection        diagnosticInfos)
        {
            serverNonce = null;
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_CloseSession)
        /// <summary>
        /// Invokes the CloseSession service.
        /// </summary>
        public virtual ResponseHeader CloseSession(
            RequestHeader requestHeader,
            bool          deleteSubscriptions)
        {

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_Cancel)
        /// <summary>
        /// Invokes the Cancel service.
        /// </summary>
        public virtual ResponseHeader Cancel(
            RequestHeader requestHeader,
            uint          requestHandle,
            out uint      cancelCount)
        {
            cancelCount = 0;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_AddNodes)
        /// <summary>
        /// Invokes the AddNodes service.
        /// </summary>
        public virtual ResponseHeader AddNodes(
            RequestHeader                requestHeader,
            AddNodesItemCollection       nodesToAdd,
            out AddNodesResultCollection results,
            out DiagnosticInfoCollection diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_AddReferences)
        /// <summary>
        /// Invokes the AddReferences service.
        /// </summary>
        public virtual ResponseHeader AddReferences(
            RequestHeader                requestHeader,
            AddReferencesItemCollection  referencesToAdd,
            out StatusCodeCollection     results,
            out DiagnosticInfoCollection diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_DeleteNodes)
        /// <summary>
        /// Invokes the DeleteNodes service.
        /// </summary>
        public virtual ResponseHeader DeleteNodes(
            RequestHeader                requestHeader,
            DeleteNodesItemCollection    nodesToDelete,
            out StatusCodeCollection     results,
            out DiagnosticInfoCollection diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_DeleteReferences)
        /// <summary>
        /// Invokes the DeleteReferences service.
        /// </summary>
        public virtual ResponseHeader DeleteReferences(
            RequestHeader                  requestHeader,
            DeleteReferencesItemCollection referencesToDelete,
            out StatusCodeCollection       results,
            out DiagnosticInfoCollection   diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_Browse)
        /// <summary>
        /// Invokes the Browse service.
        /// </summary>
        public virtual ResponseHeader Browse(
            RequestHeader                requestHeader,
            ViewDescription              view,
            uint                         requestedMaxReferencesPerNode,
            BrowseDescriptionCollection  nodesToBrowse,
            out BrowseResultCollection   results,
            out DiagnosticInfoCollection diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_BrowseNext)
        /// <summary>
        /// Invokes the BrowseNext service.
        /// </summary>
        public virtual ResponseHeader BrowseNext(
            RequestHeader                requestHeader,
            bool                         releaseContinuationPoints,
            ByteStringCollection         continuationPoints,
            out BrowseResultCollection   results,
            out DiagnosticInfoCollection diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_TranslateBrowsePathsToNodeIds)
        /// <summary>
        /// Invokes the TranslateBrowsePathsToNodeIds service.
        /// </summary>
        public virtual ResponseHeader TranslateBrowsePathsToNodeIds(
            RequestHeader                  requestHeader,
            BrowsePathCollection           browsePaths,
            out BrowsePathResultCollection results,
            out DiagnosticInfoCollection   diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_RegisterNodes)
        /// <summary>
        /// Invokes the RegisterNodes service.
        /// </summary>
        public virtual ResponseHeader RegisterNodes(
            RequestHeader        requestHeader,
            NodeIdCollection     nodesToRegister,
            out NodeIdCollection registeredNodeIds)
        {
            registeredNodeIds = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_UnregisterNodes)
        /// <summary>
        /// Invokes the UnregisterNodes service.
        /// </summary>
        public virtual ResponseHeader UnregisterNodes(
            RequestHeader    requestHeader,
            NodeIdCollection nodesToUnregister)
        {

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_QueryFirst)
        /// <summary>
        /// Invokes the QueryFirst service.
        /// </summary>
        public virtual ResponseHeader QueryFirst(
            RequestHeader                 requestHeader,
            ViewDescription               view,
            NodeTypeDescriptionCollection nodeTypes,
            ContentFilter                 filter,
            uint                          maxDataSetsToReturn,
            uint                          maxReferencesToReturn,
            out QueryDataSetCollection    queryDataSets,
            out byte[]                    continuationPoint,
            out ParsingResultCollection   parsingResults,
            out DiagnosticInfoCollection  diagnosticInfos,
            out ContentFilterResult       filterResult)
        {
            queryDataSets = null;
            continuationPoint = null;
            parsingResults = null;
            diagnosticInfos = null;
            filterResult = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_QueryNext)
        /// <summary>
        /// Invokes the QueryNext service.
        /// </summary>
        public virtual ResponseHeader QueryNext(
            RequestHeader              requestHeader,
            bool                       releaseContinuationPoint,
            byte[]                     continuationPoint,
            out QueryDataSetCollection queryDataSets,
            out byte[]                 revisedContinuationPoint)
        {
            queryDataSets = null;
            revisedContinuationPoint = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_Read)
        /// <summary>
        /// Invokes the Read service.
        /// </summary>
        public virtual ResponseHeader Read(
            RequestHeader                requestHeader,
            double                       maxAge,
            TimestampsToReturn           timestampsToReturn,
            ReadValueIdCollection        nodesToRead,
            out DataValueCollection      results,
            out DiagnosticInfoCollection diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_HistoryRead)
        /// <summary>
        /// Invokes the HistoryRead service.
        /// </summary>
        public virtual ResponseHeader HistoryRead(
            RequestHeader                   requestHeader,
            ExtensionObject                 historyReadDetails,
            TimestampsToReturn              timestampsToReturn,
            bool                            releaseContinuationPoints,
            HistoryReadValueIdCollection    nodesToRead,
            out HistoryReadResultCollection results,
            out DiagnosticInfoCollection    diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_Write)
        /// <summary>
        /// Invokes the Write service.
        /// </summary>
        public virtual ResponseHeader Write(
            RequestHeader                requestHeader,
            WriteValueCollection         nodesToWrite,
            out StatusCodeCollection     results,
            out DiagnosticInfoCollection diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_HistoryUpdate)
        /// <summary>
        /// Invokes the HistoryUpdate service.
        /// </summary>
        public virtual ResponseHeader HistoryUpdate(
            RequestHeader                     requestHeader,
            ExtensionObjectCollection         historyUpdateDetails,
            out HistoryUpdateResultCollection results,
            out DiagnosticInfoCollection      diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_Call)
        /// <summary>
        /// Invokes the Call service.
        /// </summary>
        public virtual ResponseHeader Call(
            RequestHeader                  requestHeader,
            CallMethodRequestCollection    methodsToCall,
            out CallMethodResultCollection results,
            out DiagnosticInfoCollection   diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_CreateMonitoredItems)
        /// <summary>
        /// Invokes the CreateMonitoredItems service.
        /// </summary>
        public virtual ResponseHeader CreateMonitoredItems(
            RequestHeader                           requestHeader,
            uint                                    subscriptionId,
            TimestampsToReturn                      timestampsToReturn,
            MonitoredItemCreateRequestCollection    itemsToCreate,
            out MonitoredItemCreateResultCollection results,
            out DiagnosticInfoCollection            diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_ModifyMonitoredItems)
        /// <summary>
        /// Invokes the ModifyMonitoredItems service.
        /// </summary>
        public virtual ResponseHeader ModifyMonitoredItems(
            RequestHeader                           requestHeader,
            uint                                    subscriptionId,
            TimestampsToReturn                      timestampsToReturn,
            MonitoredItemModifyRequestCollection    itemsToModify,
            out MonitoredItemModifyResultCollection results,
            out DiagnosticInfoCollection            diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_SetMonitoringMode)
        /// <summary>
        /// Invokes the SetMonitoringMode service.
        /// </summary>
        public virtual ResponseHeader SetMonitoringMode(
            RequestHeader                requestHeader,
            uint                         subscriptionId,
            MonitoringMode               monitoringMode,
            UInt32Collection             monitoredItemIds,
            out StatusCodeCollection     results,
            out DiagnosticInfoCollection diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_SetTriggering)
        /// <summary>
        /// Invokes the SetTriggering service.
        /// </summary>
        public virtual ResponseHeader SetTriggering(
            RequestHeader                requestHeader,
            uint                         subscriptionId,
            uint                         triggeringItemId,
            UInt32Collection             linksToAdd,
            UInt32Collection             linksToRemove,
            out StatusCodeCollection     addResults,
            out DiagnosticInfoCollection addDiagnosticInfos,
            out StatusCodeCollection     removeResults,
            out DiagnosticInfoCollection removeDiagnosticInfos)
        {
            addResults = null;
            addDiagnosticInfos = null;
            removeResults = null;
            removeDiagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_DeleteMonitoredItems)
        /// <summary>
        /// Invokes the DeleteMonitoredItems service.
        /// </summary>
        public virtual ResponseHeader DeleteMonitoredItems(
            RequestHeader                requestHeader,
            uint                         subscriptionId,
            UInt32Collection             monitoredItemIds,
            out StatusCodeCollection     results,
            out DiagnosticInfoCollection diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_CreateSubscription)
        /// <summary>
        /// Invokes the CreateSubscription service.
        /// </summary>
        public virtual ResponseHeader CreateSubscription(
            RequestHeader requestHeader,
            double        requestedPublishingInterval,
            uint          requestedLifetimeCount,
            uint          requestedMaxKeepAliveCount,
            uint          maxNotificationsPerPublish,
            bool          publishingEnabled,
            byte          priority,
            out uint      subscriptionId,
            out double    revisedPublishingInterval,
            out uint      revisedLifetimeCount,
            out uint      revisedMaxKeepAliveCount)
        {
            subscriptionId = 0;
            revisedPublishingInterval = 0;
            revisedLifetimeCount = 0;
            revisedMaxKeepAliveCount = 0;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_ModifySubscription)
        /// <summary>
        /// Invokes the ModifySubscription service.
        /// </summary>
        public virtual ResponseHeader ModifySubscription(
            RequestHeader requestHeader,
            uint          subscriptionId,
            double        requestedPublishingInterval,
            uint          requestedLifetimeCount,
            uint          requestedMaxKeepAliveCount,
            uint          maxNotificationsPerPublish,
            byte          priority,
            out double    revisedPublishingInterval,
            out uint      revisedLifetimeCount,
            out uint      revisedMaxKeepAliveCount)
        {
            revisedPublishingInterval = 0;
            revisedLifetimeCount = 0;
            revisedMaxKeepAliveCount = 0;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_SetPublishingMode)
        /// <summary>
        /// Invokes the SetPublishingMode service.
        /// </summary>
        public virtual ResponseHeader SetPublishingMode(
            RequestHeader                requestHeader,
            bool                         publishingEnabled,
            UInt32Collection             subscriptionIds,
            out StatusCodeCollection     results,
            out DiagnosticInfoCollection diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_Publish)
        /// <summary>
        /// Invokes the Publish service.
        /// </summary>
        public virtual ResponseHeader Publish(
            RequestHeader                         requestHeader,
            SubscriptionAcknowledgementCollection subscriptionAcknowledgements,
            out uint                              subscriptionId,
            out UInt32Collection                  availableSequenceNumbers,
            out bool                              moreNotifications,
            out NotificationMessage               notificationMessage,
            out StatusCodeCollection              results,
            out DiagnosticInfoCollection          diagnosticInfos)
        {
            subscriptionId = 0;
            availableSequenceNumbers = null;
            moreNotifications = false;
            notificationMessage = null;
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_Republish)
        /// <summary>
        /// Invokes the Republish service.
        /// </summary>
        public virtual ResponseHeader Republish(
            RequestHeader           requestHeader,
            uint                    subscriptionId,
            uint                    retransmitSequenceNumber,
            out NotificationMessage notificationMessage)
        {
            notificationMessage = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_TransferSubscriptions)
        /// <summary>
        /// Invokes the TransferSubscriptions service.
        /// </summary>
        public virtual ResponseHeader TransferSubscriptions(
            RequestHeader                requestHeader,
            UInt32Collection             subscriptionIds,
            bool                         sendInitialValues,
            out TransferResultCollection results,
            out DiagnosticInfoCollection diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_DeleteSubscriptions)
        /// <summary>
        /// Invokes the DeleteSubscriptions service.
        /// </summary>
        public virtual ResponseHeader DeleteSubscriptions(
            RequestHeader                requestHeader,
            UInt32Collection             subscriptionIds,
            out StatusCodeCollection     results,
            out DiagnosticInfoCollection diagnosticInfos)
        {
            results = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif
    }
    #endregion

    #region IDiscoveryServer Interface
    /// <summary>
    /// An interface to a UA server implementation.
    /// </summary>
    /// <exclude />
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.CodeGenerator", "1.0.0.0")]
    public interface IDiscoveryServer : IServerBase
    {
        #if (!OPCUA_EXCLUDE_FindServers)
        /// <summary>
        /// Invokes the FindServers service.
        /// </summary>
        ResponseHeader FindServers(
            RequestHeader                        requestHeader,
            string                               endpointUrl,
            StringCollection                     localeIds,
            StringCollection                     serverUris,
            out ApplicationDescriptionCollection servers);
        #endif

        #if (!OPCUA_EXCLUDE_FindServersOnNetwork)
        /// <summary>
        /// Invokes the FindServersOnNetwork service.
        /// </summary>
        ResponseHeader FindServersOnNetwork(
            RequestHeader                 requestHeader,
            uint                          startingRecordId,
            uint                          maxRecordsToReturn,
            StringCollection              serverCapabilityFilter,
            out DateTime                  lastCounterResetTime,
            out ServerOnNetworkCollection servers);
        #endif

        #if (!OPCUA_EXCLUDE_GetEndpoints)
        /// <summary>
        /// Invokes the GetEndpoints service.
        /// </summary>
        ResponseHeader GetEndpoints(
            RequestHeader                     requestHeader,
            string                            endpointUrl,
            StringCollection                  localeIds,
            StringCollection                  profileUris,
            out EndpointDescriptionCollection endpoints);
        #endif

        #if (!OPCUA_EXCLUDE_RegisterServer)
        /// <summary>
        /// Invokes the RegisterServer service.
        /// </summary>
        ResponseHeader RegisterServer(
            RequestHeader    requestHeader,
            RegisteredServer server);
        #endif

        #if (!OPCUA_EXCLUDE_RegisterServer2)
        /// <summary>
        /// Invokes the RegisterServer2 service.
        /// </summary>
        ResponseHeader RegisterServer2(
            RequestHeader                requestHeader,
            RegisteredServer             server,
            ExtensionObjectCollection    discoveryConfiguration,
            out StatusCodeCollection     configurationResults,
            out DiagnosticInfoCollection diagnosticInfos);
        #endif
    }
    #endregion

    #if (OPCUA_ASYNC_TASK || NET_STANDARD)
    #region IDiscoveryServerAsync Interface
    /// <summary>
    /// An interface to a UA server implementation using asynchronous Task based callbacks.
    /// </summary>
    /// <exclude />
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.CodeGenerator", "1.0.0.0")]
    public interface IDiscoveryServerAsync : IServerAsyncBase
    {
        #if (!OPCUA_EXCLUDE_FindServers)
        /// <summary>
        /// Invokes the FindServers service.
        /// </summary>
        System.Threading.Tasks.Task<FindServersResponse> FindServersAsync(
            RequestHeader                      requestHeader,
            string                             endpointUrl,
            StringCollection                   localeIds,
            StringCollection                   serverUris,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_FindServersOnNetwork)
        /// <summary>
        /// Invokes the FindServersOnNetwork service.
        /// </summary>
        System.Threading.Tasks.Task<FindServersOnNetworkResponse> FindServersOnNetworkAsync(
            RequestHeader                      requestHeader,
            uint                               startingRecordId,
            uint                               maxRecordsToReturn,
            StringCollection                   serverCapabilityFilter,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_GetEndpoints)
        /// <summary>
        /// Invokes the GetEndpoints service.
        /// </summary>
        System.Threading.Tasks.Task<GetEndpointsResponse> GetEndpointsAsync(
            RequestHeader                      requestHeader,
            string                             endpointUrl,
            StringCollection                   localeIds,
            StringCollection                   profileUris,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_RegisterServer)
        /// <summary>
        /// Invokes the RegisterServer service.
        /// </summary>
        System.Threading.Tasks.Task<RegisterServerResponse> RegisterServerAsync(
            RequestHeader                      requestHeader,
            RegisteredServer                   server,
            System.Threading.CancellationToken cancellationToken);
        #endif

        #if (!OPCUA_EXCLUDE_RegisterServer2)
        /// <summary>
        /// Invokes the RegisterServer2 service.
        /// </summary>
        System.Threading.Tasks.Task<RegisterServer2Response> RegisterServer2Async(
            RequestHeader                      requestHeader,
            RegisteredServer                   server,
            ExtensionObjectCollection          discoveryConfiguration,
            System.Threading.CancellationToken cancellationToken);
        #endif
    }
    #endregion
    #endif

    #region DiscoveryServerBase Class
    /// <summary>
    /// A basic implementation of the UA server.
    /// </summary>
    /// <exclude />
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.CodeGenerator", "1.0.0.0")]
    public partial class DiscoveryServerBase : ServerBase, IDiscoveryServer
    {
        #if (!OPCUA_EXCLUDE_FindServers)
        /// <summary>
        /// Invokes the FindServers service.
        /// </summary>
        public virtual ResponseHeader FindServers(
            RequestHeader                        requestHeader,
            string                               endpointUrl,
            StringCollection                     localeIds,
            StringCollection                     serverUris,
            out ApplicationDescriptionCollection servers)
        {
            servers = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_FindServersOnNetwork)
        /// <summary>
        /// Invokes the FindServersOnNetwork service.
        /// </summary>
        public virtual ResponseHeader FindServersOnNetwork(
            RequestHeader                 requestHeader,
            uint                          startingRecordId,
            uint                          maxRecordsToReturn,
            StringCollection              serverCapabilityFilter,
            out DateTime                  lastCounterResetTime,
            out ServerOnNetworkCollection servers)
        {
            lastCounterResetTime = DateTime.MinValue;
            servers = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_GetEndpoints)
        /// <summary>
        /// Invokes the GetEndpoints service.
        /// </summary>
        public virtual ResponseHeader GetEndpoints(
            RequestHeader                     requestHeader,
            string                            endpointUrl,
            StringCollection                  localeIds,
            StringCollection                  profileUris,
            out EndpointDescriptionCollection endpoints)
        {
            endpoints = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_RegisterServer)
        /// <summary>
        /// Invokes the RegisterServer service.
        /// </summary>
        public virtual ResponseHeader RegisterServer(
            RequestHeader    requestHeader,
            RegisteredServer server)
        {

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif

        #if (!OPCUA_EXCLUDE_RegisterServer2)
        /// <summary>
        /// Invokes the RegisterServer2 service.
        /// </summary>
        public virtual ResponseHeader RegisterServer2(
            RequestHeader                requestHeader,
            RegisteredServer             server,
            ExtensionObjectCollection    discoveryConfiguration,
            out StatusCodeCollection     configurationResults,
            out DiagnosticInfoCollection diagnosticInfos)
        {
            configurationResults = null;
            diagnosticInfos = null;

            ValidateRequest(requestHeader);

            // Insert implementation.

            return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
        }
        #endif
    }
    #endregion
}