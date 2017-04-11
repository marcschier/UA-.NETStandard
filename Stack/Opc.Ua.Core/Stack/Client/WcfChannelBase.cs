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
using System.ServiceModel;
using Opc.Ua.Bindings;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Opc.Ua
{
    /// <summary>
    /// A base class for WCF channel objects used access UA interfaces
    /// </summary>
    public abstract class WcfChannelBase : IChannelBase, ITransportChannel
    {
        public static ITransportChannelFactory g_CustomTransportChannel = null;
        
        #region Constructors
        /// <summary>
        /// Initializes the object with the specified binding and endpoint address.
        /// </summary>
        public WcfChannelBase()
        {
            m_messageContext = null;
            m_settings = null;
            m_wcfBypassChannel = null;
        }
        #endregion
        
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
        protected virtual void Dispose(bool disposing)
        {
            // nothing to do.
        }
        #endregion

        #region IChannelBase Members
        /// <summary>
        /// Returns true if the channel uses the UA Binary encoding.
        /// </summary>
        public bool UseBinaryEncoding
        {
            get
            {
                if (m_settings != null && m_settings.Configuration != null)
                {
                    return m_settings.Configuration.UseBinaryEncoding;
                }

                return false;
            }
        }

        /// <summary>
        /// Gets the binary encoding support.
        /// </summary>
        public BinaryEncodingSupport BinaryEncodingSupport
        {
            get
            {
                if (m_settings != null && m_settings.Configuration != null)
                {
                    if (m_settings != null && m_settings.Configuration.UseBinaryEncoding)
                    {
                        return BinaryEncodingSupport.Required;
                    }

                    return BinaryEncodingSupport.None;
                }

                return BinaryEncodingSupport.Optional;
            }
        }

        #endregion

        #region ITransportChannel Members
        /// <summary>
        /// A masking indicating which features are implemented.
        /// </summary>
        public TransportChannelFeatures SupportedFeatures 
        {
            get 
            {
                if (m_wcfBypassChannel != null)
                {
                    return m_wcfBypassChannel.SupportedFeatures;
                }
            
                return TransportChannelFeatures.Reconnect | TransportChannelFeatures.BeginSendRequest | TransportChannelFeatures.BeginClose;
            }
        }

        /// <summary>
        /// Gets the description for the endpoint used by the channel.
        /// </summary>
        public EndpointDescription EndpointDescription
        {
            get
            {
                if (m_wcfBypassChannel != null)
                {
                    return m_wcfBypassChannel.EndpointDescription;
                }
            
                if (m_settings != null)
                {
                    return m_settings.Description;
                }

                return null; 
            }
        }

        /// <summary>
        /// Gets the configuration for the channel.
        /// </summary>
        public EndpointConfiguration EndpointConfiguration
        {
            get
            {
                if (m_wcfBypassChannel != null)
                {
                    return m_wcfBypassChannel.EndpointConfiguration;
                }

                if (m_settings != null)
                {
                    return m_settings.Configuration;
                }

                return null; 
            }
        }

        /// <summary>
        /// Gets the context used when serializing messages exchanged via the channel.
        /// </summary>
        public ServiceMessageContext MessageContext
        {
            get
            {
                if (m_wcfBypassChannel != null)
                {
                    return m_wcfBypassChannel.MessageContext;
                }
             
                return m_messageContext; 
            }
        }

        /// <summary>
        /// Gets or sets the default timeout for requests send via the channel.
        /// </summary>
        public int OperationTimeout
        {
            get
            {
                if (m_wcfBypassChannel != null)
                {
                    return m_wcfBypassChannel.OperationTimeout;
                }
             
                return m_operationTimeout;
            }

            set
            {
                if (m_wcfBypassChannel != null)
                {
                    m_wcfBypassChannel.OperationTimeout = value;
                    return;
                }

                m_operationTimeout = value;
            }
        }

        /// <summary>
        /// Initializes a secure channel with the endpoint identified by the URL.
        /// </summary>
        /// <param name="url">The URL for the endpoint.</param>
        /// <param name="settings">The settings to use when creating the channel.</param>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        public void Initialize(
            Uri url,
            TransportChannelSettings settings)
        {
            if (m_wcfBypassChannel != null)
            {
                m_wcfBypassChannel.Initialize(url, settings);
                return;
            }

            throw new NotSupportedException("WCF channels must be configured when they are constructed.");
        }

        /// <summary>
        /// Opens a secure channel with the endpoint identified by the URL.
        /// </summary>
        public void Open()
        {
            if (m_wcfBypassChannel != null)
            {
                m_wcfBypassChannel.Open();
                return;
            }
        }

        /// <summary>
        /// Opens a secure channel with the endpoint identified by the URL.
        /// </summary>
        /// <param name="ct"></param>
        /// <returns></returns>
        public async Task OpenAsync(CancellationToken ct)
        {
            if (m_wcfBypassChannel != null)
            {
                await m_wcfBypassChannel.OpenAsync(ct).ConfigureAwait(false);
                return;
            }

            throw new NotSupportedException("WCF channels must be configured when they are constructed.");
        }

        /// <summary>
        /// Begins an asynchronous operation to open a secure channel with the endpoint identified by the URL.
        /// </summary>
        public IAsyncResult BeginOpen(AsyncCallback callback, object callbackData)
        {
            if (m_wcfBypassChannel != null)
            {
                return m_wcfBypassChannel.BeginOpen(callback, callbackData);
            }
             
            throw new NotSupportedException("WCF channels must be configured when they are constructed.");
        }

        /// <summary>
        /// Completes an asynchronous operation to open a communication object.
        /// </summary>
        public void EndOpen(IAsyncResult result)
        {
            if (m_wcfBypassChannel != null)
            {
                m_wcfBypassChannel.EndOpen(result);
                return;
            }

            throw new NotSupportedException("WCF channels must be configured when they are constructed.");
        }

        /// <summary>
        /// Closes any existing secure channel and opens a new one.
        /// </summary>
        /// <exception cref="ServiceResultException">Thrown if any communication error occurs.</exception>
        /// <remarks>
        /// Calling this method will cause outstanding requests over the current secure channel to fail.
        /// </remarks>
        public abstract void Reconnect();

        /// <summary>
        /// Closes any existing secure channel and opens a new one.
        /// </summary>
        /// <param name="ct"></param>
        /// <returns></returns>
        public async Task ReconnectAsync(CancellationToken ct)
        {
            if (m_wcfBypassChannel != null)
            {
                await m_wcfBypassChannel.ReconnectAsync(ct).ConfigureAwait(false);
                return;
            }

            throw new NotSupportedException("WCF channels cannot be reconnected.");
        }

        /// <summary>
        /// Begins an asynchronous operation to close the existing secure channel and open a new one.
        /// </summary>
        public IAsyncResult BeginReconnect(AsyncCallback callback, object callbackData)
        {
            if (m_wcfBypassChannel != null)
            {
                return m_wcfBypassChannel.BeginReconnect(callback, callbackData);
            }

            throw new NotSupportedException("WCF channels cannot be reconnected.");
        }

        /// <summary>
        /// Completes an asynchronous operation to close the existing secure channel and open a new one.
        /// </summary>
        public void EndReconnect(IAsyncResult result)
        {
            if (m_wcfBypassChannel != null)
            {
                m_wcfBypassChannel.EndReconnect(result);
                return;
            }

            throw new NotSupportedException("WCF channels cannot be reconnected.");
        }

        /// <summary>
        /// Closes any existing secure channel.
        /// </summary>
        public void Close()
        {
            if (m_wcfBypassChannel != null)
            {
                m_wcfBypassChannel.Close();
                return;
            }

            CloseChannel();
        }

        /// <summary>
        /// Closes any existing secure channel.
        /// </summary>
        public Task CloseAsync(CancellationToken ct)
        {
            if (m_wcfBypassChannel != null)
            {
                return m_wcfBypassChannel.CloseAsync(ct);
            }

            return Task.Factory.FromAsync(BeginClose, EndClose, TaskCreationOptions.None);
        }

        /// <summary>
        /// Begins an asynchronous operation to close the secure channel.
        /// </summary>
        public IAsyncResult BeginClose(AsyncCallback callback, object callbackData)
        {
            if (m_wcfBypassChannel != null)
            {
                return m_wcfBypassChannel.BeginClose(callback, callbackData);
            }

            AsyncResultBase result = new AsyncResultBase(callback, callbackData, 0);
            result.OperationCompleted();
            return result;
        }

        /// <summary>
        /// Completes an asynchronous operation to close a communication object.
        /// </summary>
        public void EndClose(IAsyncResult result)
        {
            if (m_wcfBypassChannel != null)
            {
                m_wcfBypassChannel.EndClose(result);
                return;
            }

            AsyncResultBase.WaitForComplete(result);
            CloseChannel();
        }

        /// <summary>
        /// Sends a request over the secure channel.
        /// </summary>
        public IServiceResponse SendRequest(IServiceRequest request)
        {
            if (m_wcfBypassChannel != null)
            {
                return m_wcfBypassChannel.SendRequest(request);
            }

            byte[] requestMessage = BinaryEncoder.EncodeMessage(request, m_messageContext);
            InvokeServiceResponseMessage responseMessage = InvokeService(new InvokeServiceMessage(requestMessage, request.ChannelContext));
            return (IServiceResponse)BinaryDecoder.DecodeMessage(responseMessage.InvokeServiceResponse, null, m_messageContext);            
        }

        /// <summary>
        /// Sends a request over the secure channel.
        /// </summary>
        public Task<IServiceResponse> SendRequestAsync(IServiceRequest request, CancellationToken ct)
        {
            if (m_wcfBypassChannel != null)
            {
                return m_wcfBypassChannel.SendRequestAsync(request, ct);
            }

            return Task.Factory.FromAsync(BeginSendRequest, EndSendRequest, request, null, TaskCreationOptions.None);
        }

        /// <summary>
        /// Begins an asynchronous operation to send a request over the secure channel.
        /// </summary>
        public IAsyncResult BeginSendRequest(IServiceRequest request, AsyncCallback callback, object callbackData)
        {
            if (m_wcfBypassChannel != null)
            {
                return m_wcfBypassChannel.BeginSendRequest(request, callback, callbackData);
            }

            byte[] requestMessage = BinaryEncoder.EncodeMessage(request, m_messageContext);
            return BeginInvokeService(new InvokeServiceMessage(requestMessage, request.ChannelContext), callback, callbackData);
        }

        /// <summary>
        /// Completes an asynchronous operation to send a request over the secure channel.
        /// </summary>
        public IServiceResponse EndSendRequest(IAsyncResult result)
        {
            if (m_wcfBypassChannel != null)
            {
                return m_wcfBypassChannel.EndSendRequest(result);
            }

            InvokeServiceResponseMessage responseMessage = EndInvokeService(result);
            return (IServiceResponse)BinaryDecoder.DecodeMessage(responseMessage.InvokeServiceResponse, null, m_messageContext);
        }

        /// <summary>
        /// The client side implementation of the InvokeService service contract.
        /// </summary>
        public abstract InvokeServiceResponseMessage InvokeService(InvokeServiceMessage request);

        /// <summary>
        /// The client side implementation of the InvokeService service contract.
        /// </summary>
        public abstract Task<InvokeServiceResponseMessage> InvokeServiceAsync(InvokeServiceMessage request);

        /// <summary>
        /// The client side implementation of the BeginInvokeService service contract.
        /// </summary>
        public abstract IAsyncResult BeginInvokeService(InvokeServiceMessage request, AsyncCallback callback, object asyncState);

        /// <summary>
        /// The client side implementation of the EndInvokeService service contract.
        /// </summary>
        public abstract InvokeServiceResponseMessage EndInvokeService(IAsyncResult result);
        #endregion

        #region Protected Methods
        /// <summary>
        /// Creates a new UA-binary transport channel if requested. Null otherwise.
        /// </summary>
        /// <param name="configuration">The application configuration.</param>
        /// <param name="description">The description for the endpoint.</param>
        /// <param name="endpointConfiguration">The configuration to use with the endpoint.</param>
        /// <param name="clientCertificate">The client certificate.</param>
        /// <param name="messageContext">The message context to use when serializing the messages.</param>
        /// <returns></returns>
        public static ITransportChannel CreateUaBinaryChannel(
            ApplicationConfiguration configuration,
            EndpointDescription description,
            EndpointConfiguration endpointConfiguration,
            X509Certificate2 clientCertificate,
            ServiceMessageContext messageContext)
        {
            bool useUaTcp = description.EndpointUrl.StartsWith(Utils.UriSchemeOpcTcp);
            bool useHttps = description.EndpointUrl.StartsWith(Utils.UriSchemeHttps);


            switch (description.TransportProfileUri)
            {
                case Profiles.UaTcpTransport:
                    {
                        useUaTcp = true;
                        break;
                    }

                case Profiles.HttpsBinaryTransport:
                    {
                        useHttps = true;
                        break;
                    }
            }

            // note: WCF channels are not supported
            if (!useUaTcp && !useHttps)
            {
                throw ServiceResultException.Create(
                    StatusCodes.BadServiceUnsupported,
                    "Unsupported transport profile\r\n");
            }

            // initialize the channel which will be created with the server.
            ITransportChannel channel = null;

            // create a UA-TCP channel.
            TransportChannelSettings settings = new TransportChannelSettings();

            settings.Description = description;
            settings.Configuration = endpointConfiguration;
            settings.ClientCertificate = clientCertificate;

            if (description.ServerCertificate != null && description.ServerCertificate.Length > 0)
            {
                settings.ServerCertificate = Utils.ParseCertificateBlob(description.ServerCertificate);
            }

            if (configuration != null)
            {
                settings.CertificateValidator = configuration.CertificateValidator.GetChannelValidator();
            }

            settings.NamespaceUris = messageContext.NamespaceUris;
            settings.Factory = messageContext.Factory;

            if (useUaTcp)
            {
                if (g_CustomTransportChannel != null)
                {
                    channel = g_CustomTransportChannel.Create();
                }
                else
                {
                    channel = new TcpTransportChannel();
                }
            }
            else if (useHttps)
            {
                channel = new HttpsTransportChannel();
            }

            channel.Initialize(new Uri(description.EndpointUrl), settings);
            channel.Open();

            return channel;
        }

        /// <summary>
        /// Handles the Opened event of the InnerChannel control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="System.EventArgs"/> instance containing the event data.</param>
        internal void InnerChannel_Opened(object sender, EventArgs e)
        {
            Uri endpointUrl = this.m_channelFactory.Endpoint.Address.Uri;

            X509Certificate2 clientCertificate = null;
            X509Certificate2 serverCertificate = null;
            
            Security.Audit.SecureChannelCreated(
                    g_ImplementationString,
                    m_channelFactory.Endpoint.Address.Uri.ToString(),
                    null,
                    EndpointDescription,
                    clientCertificate,
                    serverCertificate,
                    BinaryEncodingSupport.Optional);
        }

        /// <summary>
        /// Converts a FaultException into a ServiceResultException.
        /// </summary>
        public ServiceResultException HandleSoapFault(System.ServiceModel.FaultException<ServiceFault> exception)
        {
            if (exception == null || exception.Detail == null || exception.Detail.ResponseHeader == null)
            {
                return ServiceResultException.Create(StatusCodes.BadUnexpectedError, exception, "SOAP fault did not contain any details.");
            }

            ResponseHeader header = exception.Detail.ResponseHeader;

            return new ServiceResultException(new ServiceResult(
                header.ServiceResult,
                header.ServiceDiagnostics, 
                header.StringTable));
        }
        #endregion

        /// <summary>
        /// Closes the channel with the server.
        /// </summary>
        internal void CloseChannel()
        {
            ICommunicationObject channel = m_channel as ICommunicationObject;

            if (channel != null && channel.State == CommunicationState.Opened)
            {
                channel.Abort();
            }
        }

        #region Private Fields

        internal TransportChannelSettings m_settings;
        internal ServiceMessageContext m_messageContext;
        internal ITransportChannel m_wcfBypassChannel;
        internal int m_operationTimeout;
        internal ChannelFactory m_channelFactory;
        internal IChannelBase m_channel;
        internal const string g_ImplementationString = "Opc.Ua.ChannelBase WCF Client " + AssemblyVersionInfo.CurrentVersion;
        #endregion
    }
    
    /// <summary>
    /// A base class for WCF channel objects used access UA interfaces
    /// </summary>
    public class WcfChannelBase<TChannel> : WcfChannelBase where TChannel : class, IChannelBase
    {
        #region Constructors
        /// <summary>
        /// Initializes the object with the specified binding and endpoint address.
        /// </summary>
        public WcfChannelBase()
        {
        }
        
        #endregion

        #region IDisposable Members
        /// <summary>
        /// An overrideable version of the Dispose.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Utils.SilentDispose(m_channel);
                m_channel = null;

                Utils.SilentDispose(m_channelFactory);
                m_channelFactory = null;
            }

            base.Dispose(disposing);
        }
        #endregion

        #region IChannelBase Members
        /// <summary>
        /// The client side implementation of the InvokeService service contract.
        /// </summary>
        public override InvokeServiceResponseMessage InvokeService(InvokeServiceMessage request)
        {
            IAsyncResult result = null;

            lock (this.Channel)
            {
                result = this.Channel.BeginInvokeService(request, null, null);
            }

           return this.Channel.EndInvokeService(result);
        }

        /// <summary>
        /// The client side implementation of the InvokeService service contract.
        /// </summary>
        public override Task<InvokeServiceResponseMessage> InvokeServiceAsync(InvokeServiceMessage request)
        {
            return this.Channel.InvokeServiceAsync(request);
        }

        /// <summary>
        /// The client side implementation of the BeginInvokeService service contract.
        /// </summary>
        public override IAsyncResult BeginInvokeService(InvokeServiceMessage request, AsyncCallback callback, object asyncState)
        {
            WcfChannelAsyncResult asyncResult = new WcfChannelAsyncResult(m_channel, callback, asyncState);

            lock (asyncResult.Lock)
            {
                asyncResult.InnerResult = asyncResult.Channel.BeginInvokeService(request, asyncResult.OnOperationCompleted, null);
            }

            return asyncResult;
        }

        /// <summary>
        /// The client side implementation of the EndInvokeService service contract.
        /// </summary>
        public override InvokeServiceResponseMessage EndInvokeService(IAsyncResult result)
        {
            WcfChannelAsyncResult asyncResult = WcfChannelAsyncResult.WaitForComplete(result);
            return asyncResult.Channel.EndInvokeService(asyncResult.InnerResult);
        }
        #endregion

        #region ITransportChannel Members
        /// <summary>
        /// Closes any existing secure channel and opens a new one.
        /// </summary>
        public override void Reconnect()
        {
            if (m_wcfBypassChannel != null)
            {
                m_wcfBypassChannel.Reconnect();
                return;
            }

            Utils.Trace("RECONNECT: Reconnecting to {0}.", m_settings.Description.EndpointUrl);

            // grap the existing channel.
            TChannel channel = m_channel;
            ChannelFactory<TChannel> channelFactory = m_channelFactory as ChannelFactory<TChannel>;

            // create the new channel.
            base.m_channel = m_channel = channelFactory.CreateChannel();

            ICommunicationObject communicationObject = null;

            if (channel != null)
            {
                try
                {
                    communicationObject = channel as ICommunicationObject;

                    if (communicationObject != null)
                    {
                        communicationObject.Close();
                    }
                }
                catch (Exception)
                {
                    // ignore errors.
                }
            }

            // register callback with new channel.
            communicationObject = m_channel as ICommunicationObject;

            if (communicationObject != null)
            {
                communicationObject.Opened += new EventHandler(InnerChannel_Opened);
            }
        }
        #endregion

        #region WcfChannelAsyncResult Class
        /// <summary>
        /// An async result object that wraps the WCF channel.
        /// </summary>
        protected class WcfChannelAsyncResult : AsyncResultBase
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="WcfChannelAsyncResult"/> class.
            /// </summary>
            /// <param name="channel">The channel.</param>
            /// <param name="callback">The callback.</param>
            /// <param name="callbackData">The callback data.</param>
            public WcfChannelAsyncResult(
                TChannel channel,
                AsyncCallback callback,
                object callbackData)
                :
                    base(callback, callbackData, 0)
            {
                m_channel = channel;
            }

            /// <summary>
            /// Gets the wrapped channel.
            /// </summary>
            /// <value>The wrapped channel.</value>
            public TChannel Channel
            {
                get { return m_channel; }
            }

            /// <summary>
            /// Called when asynchronous operation completes.
            /// </summary>
            /// <param name="ar">The asynchronous result object.</param>
            public void OnOperationCompleted(IAsyncResult ar)
            {
                try
                {
                    // check if the begin operation has had a chance to complete.
                    lock (Lock)
                    {
                        if (InnerResult == null)
                        {
                            InnerResult = ar;
                        }
                    }

                    // signal that the operation is complete.
                    OperationCompleted();
                }
                catch (Exception e)
                {
                    Utils.Trace(e, "Unexpected exception invoking WcfChannelAsyncResult callback function.");
                }
            }

            /// <summary>
            /// Checks for a valid IAsyncResult object and waits for the operation to complete.
            /// </summary>
            /// <param name="ar">The IAsyncResult object for the operation.</param>
            /// <returns>The oject that </returns>
            public static new WcfChannelAsyncResult WaitForComplete(IAsyncResult ar)
            {
                WcfChannelAsyncResult asyncResult = ar as WcfChannelAsyncResult;

                if (asyncResult == null)
                {
                    throw new ArgumentException("End called with an invalid IAsyncResult object.", "ar");
                }

                if (!asyncResult.WaitForComplete())
                {
                    throw new ServiceResultException(StatusCodes.BadTimeout);
                }

                return asyncResult;
            }

            private TChannel m_channel;
        }
        #endregion

        #region Protected Methods
        /// <summary>
        /// Gets the inner channel.
        /// </summary>
        /// <value>The channel.</value>
        protected TChannel Channel
        {
            get { return m_channel; }
        }
        #endregion

        #region Private Fields
        private new TChannel m_channel;
        #endregion
    }
}
