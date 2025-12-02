/* Copyright (c) 1996-2022 The OPC Foundation. All rights reserved.
   The source code in this file is covered under a dual-license scenario:
     - RCL: for OPC Foundation Corporate Members in good-standing
     - GPL V2: everybody else
   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/
   GNU General Public License as published by the Free Software Foundation;
   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2
   This source code is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

using System;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

namespace Opc.Ua
{
    /// <summary>
    /// A generic user identity class.
    /// </summary>
    [DataContract(Namespace = Namespaces.OpcUaXsd)]
    public class UserIdentity : IUserIdentity, IDisposable
    {
        /// <summary>
        /// Initializes the object as an anonymous user.
        /// </summary>
        public UserIdentity()
        {
            m_token = new AnonymousIdentityTokenHandler();
        }

        /// <summary>
        /// Initializes the object with a username and utf8 password.
        /// </summary>
        /// <param name="username">The user name.</param>
        /// <param name="password">The password.</param>
        public UserIdentity(string username, byte[] password)
        {
            m_token = new UserNameIdentityTokenHandler(username, password);
        }

        /// <summary>
        /// Initializes the object with a username and utf8 password.
        /// </summary>
        /// <param name="username">The user name.</param>
        /// <param name="password">The password.</param>
        public UserIdentity(string username, ReadOnlySpan<byte> password)
        {
            m_token = new UserNameIdentityTokenHandler(username, password);
        }

        /// <summary>
        /// Initializes the object with an X509 certificate identifier
        /// and a CertificatePasswordProvider
        /// </summary>
        [Obsolete("Use CreateAsync method instead.")]
        public UserIdentity(
            CertificateIdentifier certificateId,
            CertificatePasswordProvider certificatePasswordProvider)
            : this(certificateId.LoadPrivateKeyExAsync(
                certificatePasswordProvider).GetAwaiter().GetResult())
        {
        }

        /// <summary>
        /// Initializes the object with an X509 certificate
        /// </summary>
        public UserIdentity(X509Certificate2 certificate)
        {
            m_token = new X509IdentityTokenHandler(certificate);
        }

        /// <summary>
        /// Initializes the object with a decrypted issued token.
        /// </summary>
        public UserIdentity(
            ReadOnlySpan<byte> decryptedTokenData,
            string issuedTokenTypeProfileUri)
        {
            m_token = new IssuedIdentityTokenHandler(issuedTokenTypeProfileUri, decryptedTokenData);
        }

        /// <summary>
        /// Create user identity with a custom token handler.
        /// </summary>
        /// <param name="token"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public UserIdentity(IUserIdentityTokenHandler token)
        {
            m_token = token?.Copy() ?? throw new ArgumentNullException(nameof(token));
        }

        /// <summary>
        /// Initializes the object with a UA identity token.
        /// </summary>
        /// <param name="token">The user identity token.</param>
        public UserIdentity(UserIdentityToken token)
        {
            m_token = token.AsTokenHandler() ??
                throw new ArgumentException(
                    "Unrecognized UA user identity token type.",
                    nameof(token));
        }

        /// <summary>
        /// Initializes the object with an X509 certificate identifier
        /// and a CertificatePasswordProvider
        /// </summary>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="certificateId"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="ServiceResultException"></exception>
        public static async Task<UserIdentity> CreateAsync(
            CertificateIdentifier certificateId,
            CertificatePasswordProvider certificatePasswordProvider,
            ITelemetryContext telemetry,
            CancellationToken ct = default)
        {
            if (certificateId == null)
            {
                throw new ArgumentNullException(nameof(certificateId));
            }

            X509Certificate2 certificate = await certificateId.LoadPrivateKeyExAsync(
                certificatePasswordProvider,
                applicationUri: null,
                telemetry,
                ct).ConfigureAwait(false);

            if (certificate == null || !certificate.HasPrivateKey)
            {
                throw new ServiceResultException(
                    "Cannot create User Identity with CertificateIdentifier that does not contain a private key");
            }

            return new UserIdentity(certificate);
        }

        /// <summary>
        /// Initializes the object with an X509 certificate identifier
        /// </summary>
        public static Task<UserIdentity> CreateAsync(
            CertificateIdentifier certificateId,
            ITelemetryContext telemetry,
            CancellationToken ct = default)
        {
            return CreateAsync(
                certificateId,
                new CertificatePasswordProvider(),
                telemetry,
                ct);
        }

        /// <summary>
        /// Initializes the object during deserialization.
        /// </summary>
        /// <remarks>
        /// The user identity encodes only the token type,
        /// the issued token and the policy id, if available.
        /// Hence, the default constructor
        /// is used to initialize the token as anonymous.
        /// </remarks>
        [OnDeserializing]
        private void Initialize(StreamingContext context)
        {
            m_token = new AnonymousIdentityTokenHandler();
        }

        /// <summary>
        /// Gets or sets the UserIdentityToken PolicyId associated
        /// with the UserIdentity.
        /// </summary>
        [DataMember(Name = "PolicyId", IsRequired = false, Order = 10)]
        public string PolicyId
        {
            get => m_token.Token.PolicyId;
            set => m_token.Token.PolicyId = value;
        }

        /// <inheritdoc/>
        [DataMember(Name = "TokenType", IsRequired = true, Order = 20)]
        public UserTokenType TokenType
        {
            get => m_typeBackingField ?? m_token.TokenType;
            set => m_typeBackingField = value;
        }
        // TODO Fix the save/restore asap
        private UserTokenType? m_typeBackingField;

        /// <inheritdoc/>
        [DataMember(Name = "IssuedTokenType", IsRequired = false, Order = 30)]
        public XmlQualifiedName IssuedTokenType
        {
            // Legacy support for issued token type as XmlQualifiedName.
            // This will be removed in future releases.
            // Use UpdatePolicy to set the policy and thus token type.
            get
            {
                if (m_token is IssuedIdentityTokenHandler issuedToken)
                {
                    return new(null, issuedToken.IssuedTokenTypeProfileUri);
                }
                return field;
            }
            set
            {
                if (m_token is IssuedIdentityTokenHandler issuedToken)
                {
                    issuedToken.IssuedTokenTypeProfileUri = value.Namespace;
                    return;
                }
                field = value;
            }
        }

        /// <inheritdoc/>
        public string DisplayName
        {
            get => field ?? m_token.DisplayName;
            set => field = value;
        }

        /// <inheritdoc/>
        public IUserIdentityTokenHandler TokenHandler => m_token;

        /// <inheritdoc/>
        public bool SupportsSignatures => false;

        /// <summary>
        ///  Get or sets the list of granted role ids associated to the UserIdentity.
        /// </summary>
        public NodeIdCollection GrantedRoleIds { get; } = [];

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            if (obj is UserIdentity identity)
            {
                return m_token.Equals(identity.m_token);
            }
            return base.Equals(obj);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return HashCode.Combine(
                PolicyId,
                TokenType,
                IssuedTokenType,
                DisplayName,
                GrantedRoleIds);
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Dispose the identity token.
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                Utils.SilentDispose(m_token);
            }
        }

        private IUserIdentityTokenHandler m_token;
    }

    /// <summary>
    /// Stores information about the user that is currently being impersonated.
    /// </summary>
    public class ImpersonationContext
    {
        /// <summary>
        /// The security principal being impersonated.
        /// </summary>
        public IPrincipal Principal { get; set; }
    }
}
