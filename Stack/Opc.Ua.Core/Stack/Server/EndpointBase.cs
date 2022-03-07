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
	/// A base class for UA endpoints.
	/// </summary>
    public abstract class EndpointBase : IEndpointBase, ITransportListenerCallback
    {

        /// <summary>
        /// Initializes the object when it is created by the WCF framework.
        /// </summary>
        protected EndpointBase()
        {
            SupportedServices = new Dictionary<ExpandedNodeId, ServiceDefinition>();

            try
            {
                m_host = GetHostForContext();
                m_server = GetServerForContext();

                MessageContext = m_server.MessageContext;

                EndpointDescription = GetEndpointDescription();
            }
            catch (Exception e)
            {
                ServerError = new ServiceResult(e);
                EndpointDescription = null;

                m_host = null;
                m_server = null;
            }
        }

        /// <summary>
        /// Initializes the when it is created directly.
        /// </summary>
        /// <param name="host">The host.</param>
        protected EndpointBase(IServiceHostBase host)
        {
            if (host == null)
            {
                throw new ArgumentNullException(nameof(host));
            }

            m_host = host;
            m_server = host.Server;

            SupportedServices = new Dictionary<ExpandedNodeId, ServiceDefinition>();
        }

        /// <summary>
        /// Initializes the endpoint with a server instead of a host.
        /// </summary>
        protected EndpointBase(ServerBase server)
        {
            if (server == null)
            {
                throw new ArgumentNullException(nameof(server));
            }

            m_host = null;
            m_server = server;

            SupportedServices = new Dictionary<ExpandedNodeId, ServiceDefinition>();
        }



        /// <summary>
        /// Begins processing a request received via a binary encoded channel.
        /// </summary>
        /// <param name="channeId">A unique identifier for the secure channel which is the source of the request.</param>
        /// <param name="endpointDescription">The description of the endpoint which the secure channel is using.</param>
        /// <param name="request">The incoming request.</param>
        /// <param name="callback">The callback.</param>
        /// <param name="callbackData">The callback data.</param>
        /// <returns>
        /// The result which must be passed to the EndProcessRequest method.
        /// </returns>
        /// <seealso cref="EndProcessRequest"/>
        /// <seealso cref="ITransportListener"/>
        public IAsyncResult BeginProcessRequest(
            string channeId,
            EndpointDescription endpointDescription,
            IServiceRequest request,
            AsyncCallback callback,
            object callbackData)
        {
            if (channeId == null)
            {
                throw new ArgumentNullException(nameof(channeId));
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            // create operation.
            var result = new ProcessRequestAsyncResult(this, callback, callbackData, 0);

            var context = new SecureChannelContext(
                channeId,
                endpointDescription,
                RequestEncoding.Binary);

            // begin invoke service.
            return result.BeginProcessRequest(context, request);
        }

        /// <summary>
        /// Ends processing a request received via a binary encoded channel.
        /// </summary>
        /// <param name="result">The result returned by the BeginProcessRequest method.</param>
        /// <returns>
        /// The response to return over the secure channel.
        /// </returns>
        /// <seealso cref="BeginProcessRequest"/>
        public IServiceResponse EndProcessRequest(IAsyncResult result)
        {
            return ProcessRequestAsyncResult.WaitForComplete(result, false);
        }

        /// <summary>
        /// Returns the host associated with the current context.
        /// </summary>
        /// <value>The host associated with the current context.</value>
        protected IServiceHostBase HostForContext
        {
            get
            {
                if (m_host == null)
                {
                    m_host = GetHostForContext();
                }

                return m_host;
            }
        }

        /// <summary>
        /// Returns the host associated with the current context.
        /// </summary>
        /// <returns>The host associated with the current context.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate")]
        protected static IServiceHostBase GetHostForContext()
        {
            throw new ServiceResultException(StatusCodes.BadInternalError, "The endpoint is not associated with a host that supports IServerHostBase.");
        }

        /// <summary>
        /// Gets the server object from the operation context.
        /// </summary>
        /// <value>The server object from the operation context.</value>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1721:PropertyNamesShouldNotMatchGetMethods")]
        protected IServerBase ServerForContext
        {
            get
            {
                if (m_server == null)
                {
                    m_server = GetServerForContext();
                }

                return m_server;
            }
        }

        /// <summary>
        /// Gets the server object from the operation context.
        /// </summary>
        /// <returns>The server object from the operation context.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate")]
        protected IServerBase GetServerForContext()
        {
            // get the server associated with the host.
            IServerBase server = HostForContext.Server;

            if (server == null)
            {
                throw new ServiceResultException(StatusCodes.BadInternalError, "The endpoint is not associated with a server instance.");
            }

            // check the server status.
            if (ServiceResult.IsBad(server.ServerError))
            {
                throw new ServiceResultException(server.ServerError);
            }

            return server;
        }



        /// <summary>
        /// Find the endpoint description for the endpoint.
        /// </summary>
        protected EndpointDescription GetEndpointDescription()
        {
            return null;
        }

        /// <summary>
        /// Finds the service identified by the request type.
        /// </summary>
        protected ServiceDefinition FindService(ExpandedNodeId requestTypeId)
        {
            ServiceDefinition service = null;

            if (!SupportedServices.TryGetValue(requestTypeId, out service))
            {
                throw ServiceResultException.Create(
                    StatusCodes.BadServiceUnsupported,
                    "'{0}' is an unrecognized service identifier.",
                    requestTypeId);
            }

            return service;
        }

        /// <summary>
        /// Creates a fault message.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="exception">The exception.</param>
        /// <returns>A fault message.</returns>
        protected static ServiceFault CreateFault(IServiceRequest request, Exception exception)
        {
            DiagnosticsMasks diagnosticsMask = DiagnosticsMasks.ServiceNoInnerStatus;

            var fault = new ServiceFault();

            if (request != null)
            {
                fault.ResponseHeader.Timestamp = DateTime.UtcNow;
                fault.ResponseHeader.RequestHandle = request.RequestHeader.RequestHandle;

                if (request.RequestHeader != null)
                {
                    diagnosticsMask = (DiagnosticsMasks)request.RequestHeader.ReturnDiagnostics;
                }
            }

            ServiceResult result = null;


            if (exception is ServiceResultException sre)
            {
                result = new ServiceResult(sre);
                Utils.LogWarning("SERVER - Service Fault Occured. Reason={0}", result.StatusCode);
                if (sre.StatusCode == StatusCodes.BadUnexpectedError)
                {
                    Utils.LogWarning(Utils.TraceMasks.StackTrace, sre, sre.ToString());
                }
            }
            else
            {
                result = new ServiceResult(exception, StatusCodes.BadUnexpectedError);
                Utils.LogError(exception, "SERVER - Unexpected Service Fault: {0}", exception.Message);
            }

            fault.ResponseHeader.ServiceResult = result.Code;

            var stringTable = new StringTable();

            fault.ResponseHeader.ServiceDiagnostics = new DiagnosticInfo(
                result,
                diagnosticsMask,
                true,
                stringTable);

            fault.ResponseHeader.StringTable = stringTable.ToArray();

            return fault;
        }

        /// <summary>
        /// Creates a fault message.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="exception">The exception.</param>
        /// <returns>A fault message.</returns>
        protected static Exception CreateSoapFault(IServiceRequest request, Exception exception)
        {
            ServiceFault fault = CreateFault(request, exception);

            // get the error from the header.
            ServiceResult error = fault.ResponseHeader.ServiceResult;

            if (error == null)
            {
                error = ServiceResult.Create(StatusCodes.BadUnexpectedError, "An unknown error occurred.");
            }

            // construct the fault code and fault reason.
            string codeName = StatusCodes.GetBrowseName(error.Code);

            return new ServiceResultException((uint)error.StatusCode, codeName, exception);
        }

        /// <summary>
        /// Returns the message context used by the server associated with the endpoint.
        /// </summary>
        /// <value>The message context.</value>
        protected IServiceMessageContext MessageContext
        {
            get => m_messageContext;
            set => m_messageContext = value;
        }

        /// <summary>
        /// Returns the description for the endpoint
        /// </summary>
        /// <value>The endpoint description.</value>
        protected EndpointDescription EndpointDescription
        {
            get => m_endpointDescription;
            set => m_endpointDescription = value;
        }

        /// <summary>
        /// Returns the error of the server.
        /// </summary>
        /// <value>The server error.</value>
        protected ServiceResult ServerError
        {
            get => m_serverError;
            set => m_serverError = value;
        }

        /// <summary>
        /// The types of services known to the server.
        /// </summary>
        protected Dictionary<ExpandedNodeId, ServiceDefinition> SupportedServices
        {
            get => m_supportedServices;
            set => m_supportedServices = value;
        }

        /// <summary>
        /// Sets the request context for the thread.
        /// </summary>
        /// <param name="encoding">The encoding.</param>
        protected void SetRequestContext(RequestEncoding encoding)
        {
        }

        /// <summary>
        /// Called when a new request is received by the endpoint.
        /// </summary>
        /// <param name="request">The request.</param>
        protected virtual void OnRequestReceived(IServiceRequest request)
        {
        }

        /// <summary>
        /// Called when a response sent via the endpoint.
        /// </summary>
        /// <param name="response">The response.</param>
        protected virtual void OnResponseSent(IServiceResponse response)
        {
        }

        /// <summary>
        /// Called when a response fault sent via the endpoint.
        /// </summary>
        /// <param name="fault">The fault.</param>
        protected virtual void OnResponseFaultSent(Exception fault)
        {
        }



        /// <summary>
        /// Stores the definition of a service supported by the server.
        /// </summary>
        protected class ServiceDefinition
        {
            /// <summary>
            /// Initializes the object with its request type and implementation.
            /// </summary>
            /// <param name="requestType">Type of the request.</param>
            /// <param name="invokeMethod">The invoke method.</param>
            public ServiceDefinition(
                Type requestType,
                InvokeServiceEventHandler invokeMethod)
            {
                m_requestType = requestType;
                m_InvokeService = invokeMethod;
            }

            /// <summary>
            /// Processes the request.
            /// </summary>
            /// <param name="request">The request.</param>
            /// <returns></returns>
            public IServiceResponse Invoke(IServiceRequest request)
            {
                if (m_InvokeService != null)
                {
                    return m_InvokeService(request);
                }

                return null;
            }


            private readonly Type m_requestType;
            private readonly InvokeServiceEventHandler m_InvokeService;

        }

        /// <summary>
        /// A delegate used to dispatch incoming service requests.
        /// </summary>
        protected delegate IServiceResponse InvokeServiceEventHandler(IServiceRequest request);



        /// <summary>
        /// An AsyncResult object when handling an asynchronous request.
        /// </summary>
        protected class ProcessRequestAsyncResult : AsyncResultBase, IEndpointIncomingRequest
        {

            /// <summary>
            /// Initializes a new instance of the <see cref="ProcessRequestAsyncResult"/> class.
            /// </summary>
            /// <param name="endpoint">The endpoint being called.</param>
            /// <param name="callback">The callback to use when the operation completes.</param>
            /// <param name="callbackData">The callback data.</param>
            /// <param name="timeout">The timeout in milliseconds</param>
            public ProcessRequestAsyncResult(
                EndpointBase endpoint,
                AsyncCallback callback,
                object callbackData,
                int timeout)
            :
                base(callback, callbackData, timeout)
            {
                m_endpoint = endpoint;
            }

            /// <summary>
            /// Gets or sets the call data associated with the request.
            /// </summary>
            /// <value>The call data.</value>
            public object Calldata
            {
                get => m_calldata;
                set => m_calldata = value;
            }

            /// <summary>
            /// Used to call the default synchronous handler.
            /// </summary>
            /// <remarks>
            /// This method may block the current thread so the caller must not call in the
            /// thread that calls IServerBase.ScheduleIncomingRequest().
            /// This method always traps any exceptions and reports them to the client as a fault.
            /// </remarks>
            public void CallSynchronously()
            {
                OnProcessRequest(null);
            }

            /// <summary>
            /// Used to indicate that the asynchronous operation has completed.
            /// </summary>
            /// <param name="response">The response. May be null if an error is provided.</param>
            /// <param name="error"></param>
            public void OperationCompleted(IServiceResponse response, ServiceResult error)
            {
                // save response and/or error.
                m_error = null;
                m_response = response;

                if (ServiceResult.IsBad(error))
                {
                    m_error = new ServiceResultException(error);
                    m_response = SaveExceptionAsResponse(m_error);
                }

                // operation completed.
                OperationCompleted();
            }

            /// <summary>
            /// Begins processing an incoming request.
            /// </summary>
            /// <param name="context">The security context for the request</param>
            /// <param name="request">The request.</param>
            /// <returns>The result object that is used to call the EndProcessRequest method.</returns>
            public IAsyncResult BeginProcessRequest(
                SecureChannelContext context,
                IServiceRequest request)
            {
                m_context = context;
                m_request = request;

                try
                {
                    // find service.
                    m_service = m_endpoint.FindService(m_request.TypeId);

                    if (m_service == null)
                    {
                        throw ServiceResultException.Create(StatusCodes.BadServiceUnsupported, "'{0}' is an unrecognized service type.", m_request.TypeId);
                    }

                    // queue request.
                    m_endpoint.ServerForContext.ScheduleIncomingRequest(this);
                }
                catch (Exception e)
                {
                    m_error = e;
                    m_response = SaveExceptionAsResponse(e);

                    // operation completed.
                    OperationCompleted();
                }

                return this;
            }

            /// <summary>
            /// Checks for a valid IAsyncResult object and waits for the operation to complete.
            /// </summary>
            /// <param name="ar">The IAsyncResult object for the operation.</param>
            /// <param name="throwOnError">if set to <c>true</c> an exception is thrown if an error occurred.</param>
            /// <returns>The response.</returns>
            public static IServiceResponse WaitForComplete(IAsyncResult ar, bool throwOnError)
            {
                if (!(ar is ProcessRequestAsyncResult result))
                {
                    throw new ArgumentException("End called with an invalid IAsyncResult object.", nameof(ar));
                }

                if (result.m_response == null)
                {
                    if (!result.WaitForComplete())
                    {
                        throw new TimeoutException();
                    }
                }

                if (throwOnError && result.m_error != null)
                {
                    throw new ServiceResultException(result.m_error, StatusCodes.BadInternalError);
                }

                return result.m_response;
            }

            /// <summary>
            /// Checks for a valid IAsyncResult object and returns the original request object.
            /// </summary>
            /// <param name="ar">The IAsyncResult object for the operation.</param>
            /// <returns>The request object if available; otherwise null.</returns>
            public static IServiceRequest GetRequest(IAsyncResult ar)
            {
                if (ar is ProcessRequestAsyncResult result)
                {
                    return result.m_request;
                }

                return null;
            }



            /// <summary>
            /// Saves an exception as response.
            /// </summary>
            /// <param name="e">The exception.</param>
            private IServiceResponse SaveExceptionAsResponse(Exception e)
            {
                try
                {
                    return EndpointBase.CreateFault(m_request, e);
                }
                catch (Exception e2)
                {
                    return EndpointBase.CreateFault(null, e2);
                }
            }

            /// <summary>
            /// Processes the request.
            /// </summary>
            private void OnProcessRequest(object state)
            {
                try
                {
                    // set the context.
                    SecureChannelContext.Current = m_context;

                    // call the service.
                    m_response = m_service.Invoke(m_request);
                }
                catch (Exception e)
                {
                    // save any error.
                    m_error = e;
                    m_response = SaveExceptionAsResponse(e);
                }

                // report completion.
                OperationCompleted();
            }



            private readonly EndpointBase m_endpoint;
            private SecureChannelContext m_context;
            private IServiceRequest m_request;
            private IServiceResponse m_response;
            private ServiceDefinition m_service;
            private Exception m_error;
            private object m_calldata;

        }



        private ServiceResult m_serverError;
        private IServiceMessageContext m_messageContext;
        private EndpointDescription m_endpointDescription;
        private Dictionary<ExpandedNodeId, ServiceDefinition> m_supportedServices;
        private IServiceHostBase m_host;
        private IServerBase m_server;
        private readonly string g_ImplementationString = "Opc.Ua.EndpointBase UA Service " + Utils.GetAssemblySoftwareVersion();

    }
}
