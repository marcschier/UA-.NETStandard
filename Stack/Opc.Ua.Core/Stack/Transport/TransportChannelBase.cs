/* Copyright (c) 1996-2016, OPC Foundation. All rights reserved.
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
using System.Threading;
using System.Threading.Tasks;

namespace Opc.Ua
{
    /// <summary>
    /// Base channel implementation that only requires an implementer to provide the async 
    /// Open, Close, and SendRequest functionality.
    /// </summary>
    public abstract class TransportChannelBase : ITransportChannel
    {
        #region IDisposable Members
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
        protected abstract void Dispose(bool disposing);

        #endregion

        #region ITransportChannel Members

        /// <summary>
        /// A masking indicating which features are implemented.
        /// </summary>
        public virtual TransportChannelFeatures SupportedFeatures
        {
            get { return TransportChannelFeatures.Open | TransportChannelFeatures.BeginOpen |
                    TransportChannelFeatures.Reconnect | TransportChannelFeatures.BeginReconnect |
                   TransportChannelFeatures.BeginClose | TransportChannelFeatures.BeginSendRequest; }
        }

        /// <summary>
        /// Gets the description for the endpoint used by the channel.
        /// </summary>
        public EndpointDescription EndpointDescription
        {
            get { return m_settings.Description; }
        }

        /// <summary>
        /// Gets the configuration for the channel.
        /// </summary>
        public EndpointConfiguration EndpointConfiguration
        {
            get { return m_settings.Configuration; }
        }

        /// <summary>
        /// Gets the context used when serializing messages exchanged via the channel.
        /// </summary>
        public ServiceMessageContext MessageContext
        {
            get { return m_messageContext; }
        }

        /// <summary>
        /// Timeout
        /// </summary>
        public int OperationTimeout { get; set; }

        /// <summary>
        /// Uri to connect to
        /// </summary>
        public Uri Url { get; set; }

        /// <summary>
        /// Initializes a secure channel with the endpoint identified by the URL.
        /// </summary>
        /// <param name="url">The URL for the endpoint.</param>
        /// <param name="settings">The settings to use when creating the channel.</param>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        public virtual void Initialize(Uri url, TransportChannelSettings settings)
        {
            Url = url;
            m_settings = settings;

            m_messageContext = new ServiceMessageContext
            {
                MaxArrayLength = m_settings.Configuration.MaxArrayLength,
                MaxByteStringLength = m_settings.Configuration.MaxByteStringLength,
                MaxMessageSize = m_settings.Configuration.MaxMessageSize,
                MaxStringLength = m_settings.Configuration.MaxStringLength,
                NamespaceUris = m_settings.NamespaceUris,
                Factory = m_settings.Factory,
                ServerUris = new StringTable()
            };

            OperationTimeout = settings.Configuration.OperationTimeout;
        }
        #endregion

        #region Open

        /// <summary>
        /// Opens a secure channel with the endpoint identified by the URL.
        /// </summary>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        public virtual void Open() =>
            OpenAsync(new CancellationTokenSource(OperationTimeout).Token).GetAwaiter().GetResult();

        /// <summary>
        /// Opens the channel before sending the request.
        /// </summary>
        /// <param name="cancellationToken">Token to cancel the operation</param>
        /// <returns></returns>
        public abstract Task OpenAsync(CancellationToken cancellationToken);

        /// <summary>
        /// Begins an asynchronous operation to open a secure channel with the endpoint identified by the URL.
        /// </summary>
        /// <param name="callback">The callback to call when the operation completes.</param>
        /// <param name="callbackData">The callback data to return with the callback.</param>
        /// <returns>
        /// The result which must be passed to the EndOpen method.
        /// </returns>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        /// <seealso cref="Open"/>
        public virtual IAsyncResult BeginOpen(AsyncCallback callback, object callbackData) =>
            TaskToApm.Begin(OpenAsync(new CancellationTokenSource(OperationTimeout).Token), callback, callbackData);

        /// <summary>
        /// Completes an asynchronous operation to open a secure channel.
        /// </summary>
        /// <param name="result">The result returned from the BeginOpen call.</param>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        /// <seealso cref="Open"/>
        public virtual void EndOpen(IAsyncResult result) =>
            TaskToApm.End(result);

        #endregion Open

        #region Reconnect
        /// <summary>
        /// Closes any existing secure channel and opens a new one.
        /// </summary>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        /// <remarks>
        /// Calling this method will cause outstanding requests over the current secure channel to fail.
        /// </remarks>
        public virtual void Reconnect() =>
            ReconnectAsync(new CancellationTokenSource(OperationTimeout).Token).GetAwaiter().GetResult();

        /// <summary>
        /// Closes any existing secure channel and opens a new one async.
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <remarks>
        /// Calling this method will cause outstanding requests over the current secure channel to fail.
        /// </remarks>
        public abstract Task ReconnectAsync(CancellationToken cancellationToken);

        /// <summary>
        /// Begins an asynchronous operation to close the existing secure channel and open a new one.
        /// </summary>
        /// <param name="callback">The callback to call when the operation completes.</param>
        /// <param name="callbackData">The callback data to return with the callback.</param>
        /// <returns>
        /// The result which must be passed to the EndReconnect method.
        /// </returns>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        /// <seealso cref="Reconnect"/>
        public virtual IAsyncResult BeginReconnect(AsyncCallback callback, object callbackData) =>
            TaskToApm.Begin(ReconnectAsync(new CancellationTokenSource(OperationTimeout).Token), callback, callbackData);

        /// <summary>
        /// Completes an asynchronous operation to close the existing secure channel and open a new one.
        /// </summary>
        /// <param name="result">The result returned from the BeginReconnect call.</param>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        /// <seealso cref="Reconnect"/>
        public virtual void EndReconnect(IAsyncResult result) =>
            TaskToApm.End(result);
        #endregion Reconnect

        #region Close
        /// <summary>
        /// Closes the secure channel.
        /// </summary>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        public virtual void Close() =>
            CloseAsync(new CancellationTokenSource(OperationTimeout).Token).GetAwaiter().GetResult();

        /// <summary>
        /// Closes the secure channel.
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        public abstract Task CloseAsync(CancellationToken cancellationToken);

        /// <summary>
        /// Begins an asynchronous operation to close the secure channel.
        /// </summary>
        /// <param name="callback">The callback to call when the operation completes.</param>
        /// <param name="callbackData">The callback data to return with the callback.</param>
        /// <returns>
        /// The result which must be passed to the EndClose method.
        /// </returns>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        /// <seealso cref="Close"/>
        public virtual IAsyncResult BeginClose(AsyncCallback callback, object callbackData) =>
             TaskToApm.Begin(CloseAsync(new CancellationTokenSource(OperationTimeout).Token), callback, callbackData);

        /// <summary>
        /// Completes an asynchronous operation to close the secure channel.
        /// </summary>
        /// <param name="result">The result returned from the BeginClose call.</param>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        /// <seealso cref="Close"/>
        public virtual void EndClose(IAsyncResult result) =>
            TaskToApm.End(result);

        #endregion Close

        #region SendRequest
        /// <summary>
        /// Sends a request over the secure channel.
        /// </summary>
        /// <param name="request">The request to send.</param>
        /// <returns>The response returned by the server.</returns>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        public virtual IServiceResponse SendRequest(IServiceRequest request) =>
            SendRequestAsync(request, new CancellationTokenSource(OperationTimeout).Token).Result;

        /// <summary>
        /// Send request over channel
        /// </summary>
        /// <param name="request"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public abstract Task<IServiceResponse> SendRequestAsync(IServiceRequest request, CancellationToken cancellationToken);

        /// <summary>
        /// Begins an asynchronous operation to send a request over the secure channel.
        /// </summary>
        /// <param name="request">The request to send.</param>
        /// <param name="callback">The callback to call when the operation completes.</param>
        /// <param name="callbackData">The callback data to return with the callback.</param>
        /// <returns>
        /// The result which must be passed to the EndSendRequest method.
        /// </returns>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        /// <seealso cref="SendRequest"/>
        public IAsyncResult BeginSendRequest(IServiceRequest request, AsyncCallback callback, object callbackData) =>
            TaskToApm.Begin(SendRequestAsync(request, new CancellationTokenSource(OperationTimeout).Token), callback, callbackData);

        /// <summary>
        /// Completes an asynchronous operation to send a request over the secure channel.
        /// </summary>
        /// <param name="result">The result returned from the BeginSendRequest call.</param>
        /// <returns></returns>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        /// <seealso cref="SendRequest"/>
        public IServiceResponse EndSendRequest(IAsyncResult result) =>
            TaskToApm.End<IServiceResponse>(result);
        #endregion SendRequest

        private TransportChannelSettings m_settings;
        private ServiceMessageContext m_messageContext;
    }
}
