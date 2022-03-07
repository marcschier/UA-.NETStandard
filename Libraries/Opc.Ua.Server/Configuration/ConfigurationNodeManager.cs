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
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml;

namespace Opc.Ua.Server
{
    /// <summary>
    /// Priviledged identity which can access the system configuration.
    /// </summary>
    public class SystemConfigurationIdentity : IUserIdentity
    {
        private readonly IUserIdentity m_identity;

        /// <summary>
        /// Create a user identity with the priviledge
        /// to modify the system configuration.
        /// </summary>
        /// <param name="identity">The user identity.</param>
        public SystemConfigurationIdentity(IUserIdentity identity)
        {
            m_identity = identity;
        }


        /// <inheritdoc/>
        public string DisplayName => m_identity.DisplayName;

        /// <inheritdoc/>
        public string PolicyId => m_identity.PolicyId;

        /// <inheritdoc/>
        public UserTokenType TokenType => m_identity.TokenType;

        /// <inheritdoc/>
        public XmlQualifiedName IssuedTokenType => m_identity.IssuedTokenType;

        /// <inheritdoc/>
        public bool SupportsSignatures => m_identity.SupportsSignatures;

        /// <inheritdoc/>
        public NodeIdCollection GrantedRoleIds
        {
            get => m_identity.GrantedRoleIds;
            set => m_identity.GrantedRoleIds = value;
        }

        /// <inheritdoc/>
        public UserIdentityToken GetIdentityToken()
        {
            return m_identity.GetIdentityToken();
        }

    }

    /// <summary>
    /// The Server Configuration Node Manager.
    /// </summary>
    public class ConfigurationNodeManager : DiagnosticsNodeManager
    {

        /// <summary>
        /// Initializes the configuration and diagnostics manager.
        /// </summary>
        public ConfigurationNodeManager(
            IServerInternal server,
            ApplicationConfiguration configuration
            )
            :
            base(server, configuration)
        {
            m_rejectedStorePath = configuration.SecurityConfiguration.RejectedCertificateStore.StorePath;
            m_certificateGroups = new List<ServerCertificateGroup>();
            m_configuration = configuration;
            // TODO: configure cert groups in configuration
            var defaultApplicationGroup = new ServerCertificateGroup {
                BrowseName = Opc.Ua.BrowseNames.DefaultApplicationGroup,
                CertificateTypes = new NodeId[] { ObjectTypeIds.RsaSha256ApplicationCertificateType },
                ApplicationCertificate = configuration.SecurityConfiguration.ApplicationCertificate,
                IssuerStorePath = configuration.SecurityConfiguration.TrustedIssuerCertificates.StorePath,
                TrustedStorePath = configuration.SecurityConfiguration.TrustedPeerCertificates.StorePath
            };
            m_certificateGroups.Add(defaultApplicationGroup);
        }



        /// <summary>
        /// Replaces the generic node with a node specific to the model.
        /// </summary>
        protected override NodeState AddBehaviourToPredefinedNode(
            ISystemContext context,
            NodeState predefinedNode)
        {
            if (predefinedNode is BaseObjectState passiveNode)
            {
                NodeId typeId = passiveNode.TypeDefinitionId;
                if (IsNodeIdInNamespace(typeId) && typeId.IdType == IdType.Numeric)
                {
                    switch ((uint)typeId.Identifier)
                    {

                        case ObjectTypes.ServerConfigurationType:
                        {
                            var activeNode = new ServerConfigurationState(passiveNode.Parent);
                            activeNode.Create(context, passiveNode);

                            m_serverConfigurationNode = activeNode;

                            // replace the node in the parent.
                            if (passiveNode.Parent != null)
                            {
                                passiveNode.Parent.ReplaceChild(context, activeNode);
                            }
                            return activeNode;
                        }

                        case ObjectTypes.CertificateGroupFolderType:
                        {
                            var activeNode = new CertificateGroupFolderState(passiveNode.Parent);
                            activeNode.Create(context, passiveNode);

                            // delete unsupported groups
                            if (m_certificateGroups.All(group => group.BrowseName != activeNode.DefaultHttpsGroup?.BrowseName))
                            {
                                activeNode.DefaultHttpsGroup = null;
                            }
                            if (m_certificateGroups.All(group => group.BrowseName != activeNode.DefaultUserTokenGroup?.BrowseName))
                            {
                                activeNode.DefaultUserTokenGroup = null;
                            }
                            if (m_certificateGroups.All(group => group.BrowseName != activeNode.DefaultApplicationGroup?.BrowseName))
                            {
                                activeNode.DefaultApplicationGroup = null;
                            }

                            // replace the node in the parent.
                            if (passiveNode.Parent != null)
                            {
                                passiveNode.Parent.ReplaceChild(context, activeNode);
                            }
                            return activeNode;
                        }

                        case ObjectTypes.CertificateGroupType:
                        {
                            ServerCertificateGroup result = m_certificateGroups.FirstOrDefault(group => group.BrowseName == passiveNode.BrowseName);
                            if (result != null)
                            {
                                var activeNode = new CertificateGroupState(passiveNode.Parent);
                                activeNode.Create(context, passiveNode);

                                result.NodeId = activeNode.NodeId;
                                result.Node = activeNode;

                                // replace the node in the parent.
                                if (passiveNode.Parent != null)
                                {
                                    passiveNode.Parent.ReplaceChild(context, activeNode);
                                }
                                return activeNode;
                            }
                        }
                        break;
                    }
                }
            }
            return base.AddBehaviourToPredefinedNode(context, predefinedNode);
        }



        /// <summary>
        /// Creates the configuration node for the server.
        /// </summary>
        public void CreateServerConfiguration(
            ServerSystemContext systemContext,
            ApplicationConfiguration configuration)
        {
            // setup server configuration node
            m_serverConfigurationNode.ServerCapabilities.Value = configuration.ServerConfiguration.ServerCapabilities.ToArray();
            m_serverConfigurationNode.ServerCapabilities.ValueRank = ValueRanks.OneDimension;
            m_serverConfigurationNode.ServerCapabilities.ArrayDimensions = new ReadOnlyList<uint>(new List<uint> { 0 });
            m_serverConfigurationNode.SupportedPrivateKeyFormats.Value = configuration.ServerConfiguration.SupportedPrivateKeyFormats.ToArray();
            m_serverConfigurationNode.SupportedPrivateKeyFormats.ValueRank = ValueRanks.OneDimension;
            m_serverConfigurationNode.SupportedPrivateKeyFormats.ArrayDimensions = new ReadOnlyList<uint>(new List<uint> { 0 });
            m_serverConfigurationNode.MaxTrustListSize.Value = (uint)configuration.ServerConfiguration.MaxTrustListSize;
            m_serverConfigurationNode.MulticastDnsEnabled.Value = configuration.ServerConfiguration.MultiCastDnsEnabled;

            m_serverConfigurationNode.UpdateCertificate.OnCall = new UpdateCertificateMethodStateMethodCallHandler(UpdateCertificate);
            m_serverConfigurationNode.CreateSigningRequest.OnCall = new CreateSigningRequestMethodStateMethodCallHandler(CreateSigningRequest);
            m_serverConfigurationNode.ApplyChanges.OnCallMethod = new GenericMethodCalledEventHandler(ApplyChanges);
            m_serverConfigurationNode.GetRejectedList.OnCall = new GetRejectedListMethodStateMethodCallHandler(GetRejectedList);
            m_serverConfigurationNode.ClearChangeMasks(systemContext, true);

            // setup certificate group trust list handlers
            foreach (ServerCertificateGroup certGroup in m_certificateGroups)
            {
                certGroup.Node.CertificateTypes.Value =
                    certGroup.CertificateTypes;
                certGroup.Node.TrustList.Handle = new TrustList(
                    certGroup.Node.TrustList,
                    certGroup.TrustedStorePath,
                    certGroup.IssuerStorePath,
                    new TrustList.SecureAccess(HasApplicationSecureAdminAccess),
                    new TrustList.SecureAccess(HasApplicationSecureAdminAccess)
                    );
                certGroup.Node.ClearChangeMasks(systemContext, true);
            }

            // find ServerNamespaces node and subscribe to StateChanged

            if (FindPredefinedNode(ObjectIds.Server_Namespaces, typeof(NamespacesState)) is NamespacesState serverNamespacesNode)
            {
                serverNamespacesNode.StateChanged += ServerNamespacesChanged;
            }
        }

        /// <summary>
        /// Gets and returns the <see cref="NamespaceMetadataState"/> node associated with the specified NamespaceUri
        /// </summary>
        /// <param name="namespaceUri"></param>
        /// <returns></returns>
        public NamespaceMetadataState GetNamespaceMetadataState(string namespaceUri)
        {
            if (namespaceUri == null)
            {
                return null;
            }

            if (m_namespaceMetadataStates.ContainsKey(namespaceUri))
            {
                return m_namespaceMetadataStates[namespaceUri];
            }

            NamespaceMetadataState namespaceMetadataState = FindNamespaceMetadataState(namespaceUri);

            lock (Lock)
            {
                // remember the result for faster access.
                m_namespaceMetadataStates[namespaceUri] = namespaceMetadataState;
            }

            return namespaceMetadataState;
        }

        /// <summary>
        /// Determine if the impersonated user has admin access.
        /// </summary>
        /// <param name="context"></param>
        /// <exception cref="ServiceResultException"/>
        /// <seealso cref="StatusCodes.BadUserAccessDenied"/>
        public void HasApplicationSecureAdminAccess(ISystemContext context)
        {
            if ((context as SystemContext)?.OperationContext is OperationContext operationContext)
            {
                if (operationContext.ChannelContext?.EndpointDescription?.SecurityMode != MessageSecurityMode.SignAndEncrypt)
                {
                    throw new ServiceResultException(StatusCodes.BadUserAccessDenied, "Secure Application Administrator access required.");
                }

                // allow access to system configuration only through special identity
                if (!(context.UserIdentity is SystemConfigurationIdentity user) || user.TokenType == UserTokenType.Anonymous)
                {
                    throw new ServiceResultException(StatusCodes.BadUserAccessDenied, "System Configuration Administrator access required.");
                }

            }
        }



        private ServiceResult UpdateCertificate(
            ISystemContext context,
            MethodState method,
            NodeId objectId,
            NodeId certificateGroupId,
            NodeId certificateTypeId,
            byte[] certificate,
            byte[][] issuerCertificates,
            string privateKeyFormat,
            byte[] privateKey,
            ref bool applyChangesRequired)
        {
            HasApplicationSecureAdminAccess(context);

            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            privateKeyFormat = privateKeyFormat?.ToUpper();
            if (!(string.IsNullOrEmpty(privateKeyFormat) || privateKeyFormat == "PEM" || privateKeyFormat == "PFX"))
            {
                throw new ServiceResultException(StatusCodes.BadNotSupported, "The private key format is not supported.");
            }

            ServerCertificateGroup certificateGroup = VerifyGroupAndTypeId(certificateGroupId, certificateTypeId);
            certificateGroup.UpdateCertificate = null;

            var newIssuerCollection = new X509Certificate2Collection();
            X509Certificate2 newCert;
            try
            {
                // build issuer chain
                if (issuerCertificates != null)
                {
                    foreach (byte[] issuerRawCert in issuerCertificates)
                    {
                        var newIssuerCert = new X509Certificate2(issuerRawCert);
                        newIssuerCollection.Add(newIssuerCert);
                    }
                }

                newCert = new X509Certificate2(certificate);
            }
            catch
            {
                throw new ServiceResultException(StatusCodes.BadCertificateInvalid, "Certificate data is invalid.");
            }

            // validate new subject matches the previous subject
            if (!X509Utils.CompareDistinguishedName(certificateGroup.ApplicationCertificate.SubjectName, newCert.SubjectName.Name))
            {
                throw new ServiceResultException(StatusCodes.BadSecurityChecksFailed, "Subject Name of new certificate doesn't match the application.");
            }

            // self signed
            bool selfSigned = X509Utils.CompareDistinguishedName(newCert.Subject, newCert.Issuer);
            if (selfSigned && newIssuerCollection.Count != 0)
            {
                throw new ServiceResultException(StatusCodes.BadCertificateInvalid, "Issuer list not empty for self signed certificate.");
            }

            if (!selfSigned)
            {
                try
                {
                    // verify cert with issuer chain
                    var certValidator = new CertificateValidator();
                    var issuerStore = new CertificateTrustList();
                    var issuerCollection = new CertificateIdentifierCollection();
                    foreach (X509Certificate2 issuerCert in newIssuerCollection)
                    {
                        issuerCollection.Add(new CertificateIdentifier(issuerCert));
                    }
                    issuerStore.TrustedCertificates = issuerCollection;
                    certValidator.Update(issuerStore, issuerStore, null);
                    certValidator.Validate(newCert);
                }
                catch
                {
                    throw new ServiceResultException(StatusCodes.BadSecurityChecksFailed, "Failed to verify integrity of the new certificate and the issuer list.");
                }
            }

            var updateCertificate = new UpdateCertificateData();
            try
            {
                ICertificatePasswordProvider passwordProvider = m_configuration.SecurityConfiguration.CertificatePasswordProvider;
                switch (privateKeyFormat)
                {
                    case null:
                    case "":
                    {
                        X509Certificate2 certWithPrivateKey = certificateGroup.ApplicationCertificate.LoadPrivateKeyEx(passwordProvider).Result;
                        updateCertificate.CertificateWithPrivateKey = CertificateFactory.CreateCertificateWithPrivateKey(newCert, certWithPrivateKey);
                        break;
                    }
                    case "PFX":
                    {
                        X509Certificate2 certWithPrivateKey = X509Utils.CreateCertificateFromPKCS12(privateKey, passwordProvider?.GetPassword(certificateGroup.ApplicationCertificate));
                        updateCertificate.CertificateWithPrivateKey = CertificateFactory.CreateCertificateWithPrivateKey(newCert, certWithPrivateKey);
                        break;
                    }
                    case "PEM":
                    {
                        updateCertificate.CertificateWithPrivateKey = CertificateFactory.CreateCertificateWithPEMPrivateKey(newCert, privateKey, passwordProvider?.GetPassword(certificateGroup.ApplicationCertificate));
                        break;
                    }
                }
                updateCertificate.IssuerCollection = newIssuerCollection;
                updateCertificate.SessionId = context.SessionId;
            }
            catch
            {
                throw new ServiceResultException(StatusCodes.BadSecurityChecksFailed, "Failed to verify integrity of the new certificate and the private key.");
            }

            certificateGroup.UpdateCertificate = updateCertificate;
            applyChangesRequired = true;

            if (updateCertificate != null)
            {
                try
                {
                    using (ICertificateStore appStore = certificateGroup.ApplicationCertificate.OpenStore())
                    {
                        Utils.LogCertificate(Utils.TraceMasks.Security, "Delete application certificate: ", certificateGroup.ApplicationCertificate.Certificate);
                        appStore.Delete(certificateGroup.ApplicationCertificate.Thumbprint).Wait();
                        Utils.LogCertificate(Utils.TraceMasks.Security, "Add new application certificate: ", updateCertificate.CertificateWithPrivateKey);
                        ICertificatePasswordProvider passwordProvider = m_configuration.SecurityConfiguration.CertificatePasswordProvider;
                        appStore.Add(updateCertificate.CertificateWithPrivateKey, passwordProvider?.GetPassword(certificateGroup.ApplicationCertificate)).Wait();
                        // keep only track of cert without private key
                        var certOnly = new X509Certificate2(updateCertificate.CertificateWithPrivateKey.RawData);
                        updateCertificate.CertificateWithPrivateKey.Dispose();
                        updateCertificate.CertificateWithPrivateKey = certOnly;
                    }
                    using (ICertificateStore issuerStore = CertificateStoreIdentifier.OpenStore(certificateGroup.IssuerStorePath))
                    {
                        foreach (X509Certificate2 issuer in updateCertificate.IssuerCollection)
                        {
                            try
                            {
                                Utils.LogCertificate(Utils.TraceMasks.Security, "Add new issuer certificate: ", issuer);
                                issuerStore.Add(issuer).Wait();
                            }
                            catch (ArgumentException)
                            {
                                // ignore error if issuer cert already exists
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Utils.LogError(Utils.TraceMasks.Security, ServiceResult.BuildExceptionTrace(ex));
                    throw new ServiceResultException(StatusCodes.BadSecurityChecksFailed, "Failed to update certificate.", ex);
                }
            }

            return ServiceResult.Good;
        }

        private ServiceResult CreateSigningRequest(
            ISystemContext context,
            MethodState method,
            NodeId objectId,
            NodeId certificateGroupId,
            NodeId certificateTypeId,
            string subjectName,
            bool regeneratePrivateKey,
            byte[] nonce,
            ref byte[] certificateRequest)
        {
            HasApplicationSecureAdminAccess(context);

            ServerCertificateGroup certificateGroup = VerifyGroupAndTypeId(certificateGroupId, certificateTypeId);

            if (!string.IsNullOrEmpty(subjectName))
            {
                throw new ArgumentNullException(nameof(subjectName));
            }

            // TODO: implement regeneratePrivateKey
            // TODO: use nonce for generating the private key

            ICertificatePasswordProvider passwordProvider = m_configuration.SecurityConfiguration.CertificatePasswordProvider;
            X509Certificate2 certWithPrivateKey = certificateGroup.ApplicationCertificate.LoadPrivateKeyEx(passwordProvider).Result;
            Utils.LogCertificate(Utils.TraceMasks.Security, "Create signing request: ", certWithPrivateKey);
            certificateRequest = CertificateFactory.CreateSigningRequest(certWithPrivateKey, X509Utils.GetDomainsFromCertficate(certWithPrivateKey));
            return ServiceResult.Good;
        }

        private ServiceResult ApplyChanges(
            ISystemContext context,
            MethodState method,
            IList<object> inputArguments,
            IList<object> outputArguments)
        {
            HasApplicationSecureAdminAccess(context);

            bool disconnectSessions = false;

            foreach (ServerCertificateGroup certificateGroup in m_certificateGroups)
            {
                try
                {
                    UpdateCertificateData updateCertificate = certificateGroup.UpdateCertificate;
                    if (updateCertificate != null)
                    {
                        disconnectSessions = true;
                        Utils.LogCertificate(Utils.TraceMasks.Security, "Apply Changes for certificate: ",
                            updateCertificate.CertificateWithPrivateKey);
                    }
                }
                finally
                {
                    certificateGroup.UpdateCertificate = null;
                }
            }

            if (disconnectSessions)
            {
                Task.Run(async () => {
                    Utils.LogInfo(Utils.TraceMasks.Security, "Apply Changes for application certificate update.");
                    // give the client some time to receive the response
                    // before the certificate update may disconnect all sessions
                    await Task.Delay(1000).ConfigureAwait(false);
                    await m_configuration.CertificateValidator.UpdateCertificate(m_configuration.SecurityConfiguration).ConfigureAwait(false);
                }
                );
            }

            return StatusCodes.Good;
        }

        private ServiceResult GetRejectedList(
            ISystemContext context,
            MethodState method,
            NodeId objectId,
            ref byte[][] certificates)
        {
            HasApplicationSecureAdminAccess(context);

            using (ICertificateStore store = CertificateStoreIdentifier.OpenStore(m_rejectedStorePath))
            {
                X509Certificate2Collection collection = store.Enumerate().Result;
                var rawList = new List<byte[]>();
                foreach (X509Certificate2 cert in collection)
                {
                    rawList.Add(cert.RawData);
                }
                certificates = rawList.ToArray();
            }

            return StatusCodes.Good;
        }

        private ServerCertificateGroup VerifyGroupAndTypeId(
            NodeId certificateGroupId,
            NodeId certificateTypeId
            )
        {
            // verify typeid must be set
            if (NodeId.IsNull(certificateTypeId))
            {
                throw new ServiceResultException(StatusCodes.BadInvalidArgument, "Certificate type not specified.");
            }

            // verify requested certificate group
            if (NodeId.IsNull(certificateGroupId))
            {
                certificateGroupId = ObjectIds.ServerConfiguration_CertificateGroups_DefaultApplicationGroup;
            }

            ServerCertificateGroup certificateGroup = m_certificateGroups.FirstOrDefault(group => Utils.IsEqual(group.NodeId, certificateGroupId));
            if (certificateGroup == null)
            {
                throw new ServiceResultException(StatusCodes.BadInvalidArgument, "Certificate group invalid.");
            }

            // verify certificate type
            bool foundCertType = certificateGroup.CertificateTypes.Any(t => Utils.IsEqual(t, certificateTypeId));
            if (!foundCertType)
            {
                throw new ServiceResultException(StatusCodes.BadInvalidArgument, "Certificate type not valid for certificate group.");
            }

            return certificateGroup;
        }

        /// <summary>
        /// Finds the <see cref="NamespaceMetadataState"/> node for the specified NamespaceUri.
        /// </summary>
        /// <param name="namespaceUri"></param>
        /// <returns></returns>
        private NamespaceMetadataState FindNamespaceMetadataState(string namespaceUri)
        {
            try
            {
                // find ServerNamespaces node
                if (!(FindPredefinedNode(ObjectIds.Server_Namespaces, typeof(NamespacesState)) is NamespacesState serverNamespacesNode))
                {
                    Utils.LogError("Cannot find ObjectIds.Server_Namespaces node.");
                    return null;
                }

                IList<BaseInstanceState> serverNamespacesChildren = new List<BaseInstanceState>();
                serverNamespacesNode.GetChildren(SystemContext, serverNamespacesChildren);

                foreach (BaseInstanceState namespacesReference in serverNamespacesChildren)
                {
                    // Find NamespaceMetadata node of NamespaceUri in Namespaces children

                    if (!(namespacesReference is NamespaceMetadataState namespaceMetadata))
                    {
                        continue;
                    }

                    if (namespaceMetadata.NamespaceUri.Value == namespaceUri)
                    {
                        return namespaceMetadata;
                    }
                    else
                    {
                        continue;
                    }
                }

                IList<IReference> serverNamespacesReferencs = new List<IReference>();
                serverNamespacesNode.GetReferences(SystemContext, serverNamespacesReferencs);

                foreach (IReference serverNamespacesReference in serverNamespacesReferencs)
                {
                    if (serverNamespacesReference.IsInverse == false)
                    {
                        // Find NamespaceMetadata node of NamespaceUri in Namespaces references
                        var nameSpaceNodeId = ExpandedNodeId.ToNodeId(serverNamespacesReference.TargetId, Server.NamespaceUris);

                        if (!(FindNodeInAddressSpace(nameSpaceNodeId) is NamespaceMetadataState namespaceMetadata))
                        {
                            continue;
                        }

                        if (namespaceMetadata.NamespaceUri.Value == namespaceUri)
                        {
                            return namespaceMetadata;
                        }
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                Utils.LogError(ex, "Error searching NamespaceMetadata for namespaceUri {0}.", namespaceUri);
                return null;
            }
        }

        /// <summary>
        /// Clear NamespaceMetadata nodes cache in case nodes are added or deleted
        /// </summary>
        private void ServerNamespacesChanged(ISystemContext context, NodeState node, NodeStateChangeMasks changes)
        {
            if ((changes & NodeStateChangeMasks.Children) != 0 ||
                (changes & NodeStateChangeMasks.References) != 0)
            {
                try
                {
                    lock (Lock)
                    {
                        m_namespaceMetadataStates.Clear();
                    }
                }
                catch
                {
                    // ignore errors
                }
            }
        }



        private class UpdateCertificateData
        {
            public NodeId SessionId;
            public X509Certificate2 CertificateWithPrivateKey;
            public X509Certificate2Collection IssuerCollection;
        }

        private class ServerCertificateGroup
        {
            public string BrowseName;
            public NodeId NodeId;
            public CertificateGroupState Node;
            public NodeId[] CertificateTypes;
            public CertificateIdentifier ApplicationCertificate;
            public string IssuerStorePath;
            public string TrustedStorePath;
            public UpdateCertificateData UpdateCertificate;
        }

        private ServerConfigurationState m_serverConfigurationNode;
        private readonly ApplicationConfiguration m_configuration;
        private readonly IList<ServerCertificateGroup> m_certificateGroups;
        private readonly string m_rejectedStorePath;
        private readonly Dictionary<string, NamespaceMetadataState> m_namespaceMetadataStates = new Dictionary<string, NamespaceMetadataState>();

    }
}
