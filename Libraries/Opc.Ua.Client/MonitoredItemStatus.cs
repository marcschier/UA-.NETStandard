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

namespace Opc.Ua.Client
{
    /// <summary>
    /// The current status of monitored item.
    /// </summary>
    public class MonitoredItemStatus
    {

        /// <summary>
        /// Creates a empty object.
        /// </summary>
        internal MonitoredItemStatus()
        {
            Initialize();
        }

        private void Initialize()
        {
            m_id = 0;
            m_nodeId = null;
            m_attributeId = Attributes.Value;
            m_indexRange = null;
            m_encoding = null;
            m_monitoringMode = MonitoringMode.Disabled;
            m_clientHandle = 0;
            m_samplingInterval = 0;
            m_filter = null;
            m_queueSize = 0;
            m_discardOldest = true;
        }



        /// <summary>
        /// The identifier assigned by the server.
        /// </summary>
        public uint Id { get => m_id; set => m_id = value; }

        /// <summary>
        /// Whether the item has been created on the server.
        /// </summary>
        public bool Created => m_id != 0;

        /// <summary>
        /// Updates the object with the results of a translate browse paths request.
        /// </summary>
        internal void SetResolvePathResult(
            BrowsePathResult result,
            ServiceResult error)
        {
            m_error = error;
        }

        /// <summary>
        /// Updates the object with the results of a create monitored item request.
        /// </summary>
        internal void SetCreateResult(
            MonitoredItemCreateRequest request,
            MonitoredItemCreateResult result,
            ServiceResult error)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            m_nodeId = request.ItemToMonitor.NodeId;
            m_attributeId = request.ItemToMonitor.AttributeId;
            m_indexRange = request.ItemToMonitor.IndexRange;
            m_encoding = request.ItemToMonitor.DataEncoding;
            m_monitoringMode = request.MonitoringMode;
            m_clientHandle = request.RequestedParameters.ClientHandle;
            m_samplingInterval = request.RequestedParameters.SamplingInterval;
            m_queueSize = request.RequestedParameters.QueueSize;
            m_discardOldest = request.RequestedParameters.DiscardOldest;
            m_filter = null;
            m_error = error;

            if (request.RequestedParameters.Filter != null)
            {
                m_filter = Utils.Clone(request.RequestedParameters.Filter.Body) as MonitoringFilter;
            }

            if (ServiceResult.IsGood(error))
            {
                m_id = result.MonitoredItemId;
                m_samplingInterval = result.RevisedSamplingInterval;
                m_queueSize = result.RevisedQueueSize;
            }
        }

        /// <summary>
        /// Updates the object with the results of a transfer monitored item request.
        /// </summary>
        internal void SetTransferResult(MonitoredItem monitoredItem)
        {
            if (monitoredItem == null)
            {
                throw new ArgumentNullException(nameof(monitoredItem));
            }

            m_nodeId = monitoredItem.ResolvedNodeId;
            m_attributeId = monitoredItem.AttributeId;
            m_indexRange = monitoredItem.IndexRange;
            m_encoding = monitoredItem.Encoding;
            m_monitoringMode = monitoredItem.MonitoringMode;
            m_clientHandle = monitoredItem.ClientHandle;
            m_samplingInterval = monitoredItem.SamplingInterval;
            m_queueSize = monitoredItem.QueueSize;
            m_discardOldest = monitoredItem.DiscardOldest;
            m_filter = null;

            if (monitoredItem.Filter != null)
            {
                m_filter = Utils.Clone(monitoredItem.Filter) as MonitoringFilter;
            }
        }

        /// <summary>
        /// Updates the object with the results of a modify monitored item request.
        /// </summary>
        internal void SetModifyResult(
            MonitoredItemModifyRequest request,
            MonitoredItemModifyResult result,
            ServiceResult error)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            m_error = error;

            if (ServiceResult.IsGood(error))
            {
                m_clientHandle = request.RequestedParameters.ClientHandle;
                m_samplingInterval = request.RequestedParameters.SamplingInterval;
                m_queueSize = request.RequestedParameters.QueueSize;
                m_discardOldest = request.RequestedParameters.DiscardOldest;
                m_filter = null;

                if (request.RequestedParameters.Filter != null)
                {
                    m_filter = Utils.Clone(request.RequestedParameters.Filter.Body) as MonitoringFilter;
                }

                m_samplingInterval = result.RevisedSamplingInterval;
                m_queueSize = result.RevisedQueueSize;
            }
        }

        /// <summary>
        /// Sets the error state for the monitored item status.
        /// </summary>
        internal void SetError(ServiceResult error)
        {
            m_error = error;
        }



        private uint m_id;
        private ServiceResult m_error;
        private NodeId m_nodeId;
        private uint m_attributeId;
        private string m_indexRange;
        private QualifiedName m_encoding;
        private MonitoringMode m_monitoringMode;
        private uint m_clientHandle;
        private double m_samplingInterval;
        private MonitoringFilter m_filter;
        private uint m_queueSize;
        private bool m_discardOldest;

    }
}
