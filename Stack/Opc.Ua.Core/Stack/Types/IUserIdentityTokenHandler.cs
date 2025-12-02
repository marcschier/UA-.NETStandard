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
using System.Security.Cryptography.X509Certificates;

namespace Opc.Ua
{
    /// <summary>
    /// Handles user identity tokens. The individual token type handlers
    /// implement this interface. They wrap a token that they encrypt, decrypt,
    /// and sign / verify signatures for. The token can be retrieved using
    /// the Token property and passed as extension object in service calls.
    /// </summary>
    /// <remarks>
    /// Previously the tokens themselves implemented crypto operations, but
    /// for security and better separation of concerns, the handlers now
    /// perform these operations and are disposable/copyable to ensure better
    /// lifetime management of sensitive data.
    /// </remarks>
    public interface IUserIdentityTokenHandler :
        IDisposable, ICloneable, IEquatable<IUserIdentityTokenHandler>
    {
        /// <summary>
        /// The token the handler operates on.
        /// </summary>
        UserIdentityToken Token { get; }

        /// <summary>
        /// Get display name of the token. This is used only for logging and
        /// diagnostics.
        /// </summary>
        string DisplayName { get; }

        /// <summary>
        /// The type of the wrapped token
        /// </summary>
        UserTokenType TokenType { get; }

        /// <summary>
        /// Update the policy associated with the token
        /// </summary>
        /// <param name="userTokenPolicy"></param>
        void UpdatePolicy(UserTokenPolicy userTokenPolicy);

        /// <summary>
        /// Encrypts the token
        /// </summary>
        void Encrypt(
            X509Certificate2 receiverCertificate,
            byte[] receiverNonce,
            string securityPolicyUri,
            IServiceMessageContext context,
            Nonce receiverEphemeralKey = null,
            X509Certificate2 senderCertificate = null,
            X509Certificate2Collection senderIssuerCertificates = null,
            bool doNotEncodeSenderCertificate = false);

        /// <summary>
        /// Decrypts the token
        /// </summary>
        void Decrypt(
            X509Certificate2 certificate,
            Nonce receiverNonce,
            string securityPolicyUri,
            IServiceMessageContext context,
            Nonce ephemeralKey = null,
            X509Certificate2 senderCertificate = null,
            X509Certificate2Collection senderIssuerCertificates = null,
            CertificateValidator validator = null);

        /// <summary>
        /// Creates a signature with the token
        /// </summary>
        SignatureData Sign(
            byte[] dataToSign,
            string securityPolicyUri);

        /// <summary>
        /// Verifies a signature created with the token
        /// </summary>
        bool Verify(
            byte[] dataToVerify,
            SignatureData signatureData,
            string securityPolicyUri);
    }

    /// <summary>
    /// Extensions for user identity tokens.
    /// </summary>
    public static class UserIdentityTokenExtensions
    {
        /// <summary>
        /// Wraps the raw token inside a token handler to operate on it.
        /// Dispose the returned handler when done. When storing it for
        /// later use clone it and then dispose the original when done.
        /// </summary>
        /// <exception cref="ServiceResultException"></exception>
        public static IUserIdentityTokenHandler AsTokenHandler(
            this UserIdentityToken token)
        {
            switch (token)
            {
                case AnonymousIdentityToken:
                    return new AnonymousIdentityTokenHandler();
                case UserNameIdentityToken userNamePassword:
                    return new UserNameIdentityTokenHandler(userNamePassword);
                case X509IdentityToken x509Identity:
                    return new X509IdentityTokenHandler(x509Identity);
                case IssuedIdentityToken issuedToken:
                    return new IssuedIdentityTokenHandler(issuedToken);
                default:
                    throw ServiceResultException.Create(
                        StatusCodes.BadNotSupported,
                        "The token type {0} is not supported in this implementation.",
                        token.GetType().Name);
            }
        }

        /// <summary>
        /// Simplified clone to produce a copy of the token handler.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        public static T Copy<T>(this T tokenHandler)
            where T : IUserIdentityTokenHandler
        {
            return (T)tokenHandler.Clone();
        }
    }
}
