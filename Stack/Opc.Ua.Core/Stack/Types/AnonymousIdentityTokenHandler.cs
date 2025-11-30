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

using System.Security.Cryptography.X509Certificates;

namespace Opc.Ua
{
    /// <summary>
    /// Anonymous identity token handler.
    /// </summary>
    public sealed class AnonymousIdentityTokenHandler : IUserIdentityTokenHandler
    {
        /// <inheritdoc/>
        public UserIdentityToken Token => new AnonymousIdentityToken();

        /// <inheritdoc/>
        public UserTokenType TokenType => UserTokenType.Anonymous;

        /// <inheritdoc/>
        public string DisplayName => "Anonymous";

        /// <inheritdoc/>
        public void Encrypt(
            X509Certificate2 receiverCertificate,
            byte[] receiverNonce,
            string securityPolicyUri,
            IServiceMessageContext context,
            Nonce receiverEphemeralKey = null,
            X509Certificate2 senderCertificate = null,
            X509Certificate2Collection senderIssuerCertificates = null,
            bool doNotEncodeSenderCertificate = false)
        {
        }

        /// <inheritdoc/>
        public void Decrypt(
            X509Certificate2 certificate,
            Nonce receiverNonce,
            string securityPolicyUri,
            IServiceMessageContext context,
            Nonce ephemeralKey = null,
            X509Certificate2 senderCertificate = null,
            X509Certificate2Collection senderIssuerCertificates = null,
            CertificateValidator validator = null)
        {
        }

        /// <inheritdoc/>
        public SignatureData Sign(
            byte[] dataToSign,
            string securityPolicyUri)
        {
            return new SignatureData();
        }

        /// <inheritdoc/>
        public bool Verify(
            byte[] dataToVerify,
            SignatureData signatureData,
            string securityPolicyUri)
        {
            return true;
        }

        /// <inheritdoc/>
        public void Dispose()
        {
        }
    }
}
