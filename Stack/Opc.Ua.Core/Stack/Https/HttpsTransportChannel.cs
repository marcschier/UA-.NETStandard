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
    public class HttpsTransportChannel : TransportChannelBase
    {
        /// <summary>
        /// Initialize
        /// </summary>
        /// <param name="url"></param>
        /// <param name="settings"></param>
        public override void Initialize(Uri url, TransportChannelSettings settings)
        {
            base.Initialize(new Uri(Utils.ReplaceLocalhost(url.ToString())), settings);
        }

        #region Open

        /// <summary>
        /// Open async
        /// </summary>
        /// <param name="ct"></param>
        /// <returns></returns>
        public override Task OpenAsync(CancellationToken ct)
        {
            try
            {
                var handler = new HttpClientHandler();
#if DEBUG
                handler.ClientCertificateOptions = ClientCertificateOption.Manual;
                handler.ServerCertificateCustomValidationCallback =
                    (httpRequestMessage, cert, cetChain, policyErrors) =>
                    {
                        return true;
                    };
#endif
                m_client = new HttpClient(handler);
                return Task.FromResult(true);
            }
            catch (Exception ex)
            {
                Utils.Trace("Exception creating HTTPS Client: " + ex.Message);
                throw ex;
            }
        }

        #endregion Open

        #region Reconnect
        /// <summary>
        /// No op
        /// </summary>
        /// <param name="ct"></param>
        /// <returns></returns>
        public override Task ReconnectAsync(CancellationToken ct)
        {
            Utils.Trace("HttpsTransportChannel RECONNECT: Reconnecting to {0}.", Url);
            return Task.FromResult(true);
        }

        #endregion Reconnect

        #region Close
        /// <summary>
        /// Close
        /// </summary>
        public override void Close()
        {
            if (m_client != null)
            {
                m_client.Dispose();
                m_client = null;
            }
        }

        /// <summary>
        /// Close async
        /// </summary>
        /// <param name="ct"></param>
        /// <returns></returns>
        public override Task CloseAsync(CancellationToken ct)
        {
            Close();
            return Task.FromResult(true);
        }

        /// <summary>
        /// Dispose = Close
        /// </summary>
        /// <param name="disposing"></param>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Close();
            }
        }
        #endregion Close

        #region SendRequest

        /// <summary>
        /// Send request asynchronously
        /// </summary>
        /// <param name="request"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        public override async Task<IServiceResponse> SendRequestAsync(IServiceRequest request, CancellationToken ct)
        {
            try
            {
                HttpResponseMessage response = null;
                var content = new ByteArrayContent(BinaryEncoder.EncodeMessage(request, MessageContext));
                content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                response = await m_client.PostAsync(Url, content).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                using (var responseContent = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
                {
                    return BinaryDecoder.DecodeMessage(responseContent, null, MessageContext) as IServiceResponse;
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
        #endregion SendRequest


        private HttpClient m_client;
    }
}
