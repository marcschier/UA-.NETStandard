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
    /// Handles user identity tokens.
    /// </summary>
    public interface IUserIdentityTokenHandler : IDisposable
    {
        /// <summary>
        /// Token
        /// </summary>
        UserIdentityToken Token { get; }

        /// <summary>
        /// Get display name of the token
        /// </summary>
        string DisplayName { get; }

        /// <summary>
        /// Token type
        /// </summary>
        UserTokenType TokenType { get; }

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
        /// Clones the token.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static IUserIdentityTokenHandler AsTokenHandler(this UserIdentityToken token)
        {
            switch (token)
            {
                case AnonymousIdentityToken:
                    return new AnonymousIdentityTokenHandler();
                case UserNameIdentityToken userNamePassword:
                    return new UserNameIdentityTokenHandler(userNamePassword);
                case X509IdentityToken x509Identity:
                    return new X509IdentityTokenHandler(x509Identity);
                case IssuedIdentityToken issuedIdentity:
                    return new IssuedIdentityTokenHandler(issuedIdentity);
                default:
                    throw new ArgumentOutOfRangeException(
                        nameof(token),
                        token,
                        "Invalid token type");
            }
        }
    }


}
