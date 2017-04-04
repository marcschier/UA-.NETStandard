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
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Opc.Ua.Bindings
{
    /// <summary>
    /// Wraps the HttpsTransportChannel and provides an ITransportChannel implementation.
    /// </summary>
    public class HttpsTransportChannel : ITransportChannel
    {
        public void Dispose()
        {   
        }

        public TransportChannelFeatures SupportedFeatures
        {
            get { return TransportChannelFeatures.Open | TransportChannelFeatures.Reconnect | TransportChannelFeatures.BeginSendRequest; }
        }

        public EndpointDescription EndpointDescription
        {
            get { return m_settings.Description; }
        }

        public EndpointConfiguration EndpointConfiguration
        {
            get { return m_settings.Configuration; }
        }

        public ServiceMessageContext MessageContext
        {
            get { return m_quotas.MessageContext; }
        }

        public int OperationTimeout
        {
            get { return m_operationTimeout;  }
            set { m_operationTimeout = value; }
        }

        public void Initialize(
            Uri url,
            TransportChannelSettings settings)
        {
            SaveSettings(url, settings);
        }

        #region Open
        /// <summary>
        /// Open synchronously
        /// </summary>
        public void Open()
        {
            try
            {
                m_client = new HttpClient();
            }
            catch (Exception ex)
            {
                Utils.Trace("Exception creating HTTPS Client: " + ex.Message);
                throw ex;
            }
        }

        /// <summary>
        /// Open async
        /// </summary>
        /// <param name="ct"></param>
        /// <returns></returns>
        public Task OpenAsync(CancellationToken ct)
        {
            Open();
            return Task.FromResult(true);
        }

        /// <summary>
        /// Begin open
        /// </summary>
        /// <param name="callback"></param>
        /// <param name="callbackData"></param>
        /// <returns></returns>
        public IAsyncResult BeginOpen(AsyncCallback callback, object callbackData)
        {
            return TaskToApm.Begin(OpenAsync(CancellationToken.None), callback, callbackData);
        }

        /// <summary>
        /// Complete open
        /// </summary>
        /// <param name="result"></param>
        public void EndOpen(IAsyncResult result)
        {
            TaskToApm.End(result);
        }
        #endregion Open

        #region Reconnect
        /// <summary>
        /// No op
        /// </summary>
        public void Reconnect()
        {
            Utils.Trace("HttpsTransportChannel RECONNECT: Reconnecting to {0}.", m_url);
        }

        /// <summary>
        /// No op
        /// </summary>
        /// <param name="ct"></param>
        /// <returns></returns>
        public Task ReconnectAsync(CancellationToken ct)
        {
            Reconnect();
            return Task.FromResult(true);
        }

        /// <summary>
        /// Begin reconnect
        /// </summary>
        /// <param name="callback"></param>
        /// <param name="callbackData"></param>
        /// <returns></returns>
        public IAsyncResult BeginReconnect(AsyncCallback callback, object callbackData)
        {
            return TaskToApm.Begin(ReconnectAsync(CancellationToken.None), callback, callbackData);
        }

        /// <summary>
        /// Complete reconnect
        /// </summary>
        /// <param name="result"></param>
        public void EndReconnect(IAsyncResult result)
        {
            TaskToApm.End(result);
        }

        #endregion Reconnect

        #region Close
        /// <summary>
        /// Close
        /// </summary>
        public void Close()
        {
            if (m_client != null)
            {
                m_client.Dispose();
            }
        }

        /// <summary>
        /// Close async
        /// </summary>
        /// <param name="ct"></param>
        /// <returns></returns>
        public Task CloseAsync(CancellationToken ct)
        {
            Close();
            return Task.FromResult(true);
        }

        /// <summary>
        /// Begin close
        /// </summary>
        /// <param name="callback"></param>
        /// <param name="callbackData"></param>
        /// <returns></returns>
        public IAsyncResult BeginClose(AsyncCallback callback, object callbackData)
        {
            return TaskToApm.Begin(CloseAsync(CancellationToken.None), callback, callbackData);
        }

        /// <summary>
        /// Complete close
        /// </summary>
        /// <param name="result"></param>
        public void EndClose(IAsyncResult result)
        {
            TaskToApm.End(result);
        }
        #endregion Close

        #region SendRequest

        /// <summary>
        /// Send request synchronously
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        public IServiceResponse SendRequest(IServiceRequest request)
        {
            return SendRequestAsync(request, CancellationToken.None).Result;
        }

        /// <summary>
        /// Send request asynchronously
        /// </summary>
        /// <param name="request"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        public async Task<IServiceResponse> SendRequestAsync(IServiceRequest request, CancellationToken ct)
        {
            try
            {
                HttpResponseMessage response = null;
                var content = new ByteArrayContent(BinaryEncoder.EncodeMessage(request, m_quotas.MessageContext));
                content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                response = await m_client.PostAsync(m_url, content).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();

                using (var responseContent = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
                {
                    return BinaryDecoder.DecodeMessage(responseContent, null, m_quotas.MessageContext) as IServiceResponse;
                }
            }
            catch (Exception ex)
            {
                Utils.Trace("Exception reading HTTPS response: " + ex.Message);

                // TODO: Old begin/end code cast async result to IServiceResponse, which should be null, since there is no inheritance from it.
                // We throw, but this is a breaking change...
                throw;
            }
        }

        /// <summary>
        /// Begin send
        /// </summary>
        /// <param name="request"></param>
        /// <param name="callback"></param>
        /// <param name="callbackData"></param>
        /// <returns></returns>
        public IAsyncResult BeginSendRequest(IServiceRequest request, AsyncCallback callback, object callbackData)
        {
            return TaskToApm.Begin(SendRequestAsync(request, CancellationToken.None), callback, callbackData);
        }

        /// <summary>
        /// End sending
        /// </summary>
        /// <param name="result"></param>
        /// <returns></returns>
        public IServiceResponse EndSendRequest(IAsyncResult result)
        {
            return TaskToApm.End<IServiceResponse>(result);
        }

        #endregion SendRequest

        #region Misc
        /// <summary>
        /// Save settings
        /// </summary>
        /// <param name="url"></param>
        /// <param name="settings"></param>
        private void SaveSettings(Uri url, TransportChannelSettings settings)
        {
            m_url = new Uri(Utils.ReplaceLocalhost(url.ToString()));

            m_settings = settings;
            m_operationTimeout = settings.Configuration.OperationTimeout;

            // initialize the quotas.
            m_quotas = new ChannelQuotas();

            m_quotas.MaxBufferSize = m_settings.Configuration.MaxBufferSize;
            m_quotas.MaxMessageSize = m_settings.Configuration.MaxMessageSize;
            m_quotas.ChannelLifetime = m_settings.Configuration.ChannelLifetime;
            m_quotas.SecurityTokenLifetime = m_settings.Configuration.SecurityTokenLifetime;

            m_quotas.MessageContext = new ServiceMessageContext();

            m_quotas.MessageContext.MaxArrayLength = m_settings.Configuration.MaxArrayLength;
            m_quotas.MessageContext.MaxByteStringLength = m_settings.Configuration.MaxByteStringLength;
            m_quotas.MessageContext.MaxMessageSize = m_settings.Configuration.MaxMessageSize;
            m_quotas.MessageContext.MaxStringLength = m_settings.Configuration.MaxStringLength;
            m_quotas.MessageContext.NamespaceUris = m_settings.NamespaceUris;
            m_quotas.MessageContext.ServerUris = new StringTable();
            m_quotas.MessageContext.Factory = m_settings.Factory;

            m_quotas.CertificateValidator = settings.CertificateValidator;
        }

        #endregion Misc

        private Uri m_url;
        private int m_operationTimeout;
        private TransportChannelSettings m_settings;
        private ChannelQuotas m_quotas;
        private HttpClient m_client;
    }
}
