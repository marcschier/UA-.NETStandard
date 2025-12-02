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
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace Opc.Ua
{
    /// <summary>
    /// The UserIdentityToken class.
    /// </summary>
    public sealed class UserNameIdentityTokenHandler : IUserIdentityTokenHandler
    {
        /// <summary>
        /// Create token handler
        /// </summary>
        public UserNameIdentityTokenHandler(UserNameIdentityToken token)
        {
            DecryptedPassword = null;
            m_token = token;
        }

        /// <summary>
        /// Create token handler
        /// </summary>
        public UserNameIdentityTokenHandler(
            string username,
            ReadOnlySpan<byte> password)
        {
            DecryptedPassword = password.ToArray();
            m_token = new UserNameIdentityToken
            {
                UserName = username,
                Password = password.ToArray()
            };
        }

        /// <inheritdoc/>
        public UserIdentityToken Token => m_token;

        /// <inheritdoc/>
        public string DisplayName => m_token.UserName;

        /// <inheritdoc/>
        public UserTokenType TokenType => UserTokenType.UserName;

        /// <summary>
        /// The decrypted password associated with the token.
        /// </summary>
        public byte[] DecryptedPassword { get; set; }

        /// <summary>
        /// User name in the token.
        /// </summary>
        public string UserName => m_token.UserName;

        /// <inheritdoc/>
        public void UpdatePolicy(UserTokenPolicy userTokenPolicy)
        {
            m_token.PolicyId = userTokenPolicy.PolicyId;
        }

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
            if (DecryptedPassword == null)
            {
                m_token.Password = null;
                return;
            }

            // handle no encryption.
            if (string.IsNullOrEmpty(securityPolicyUri) ||
                securityPolicyUri == SecurityPolicies.None)
            {
                m_token.Password = DecryptedPassword;
                m_token.EncryptionAlgorithm = null;
                return;
            }

            // handle RSA encryption.
            if (!EccUtils.IsEccPolicy(securityPolicyUri))
            {
                byte[] dataToEncrypt = Utils.Append(DecryptedPassword, receiverNonce);

                ILogger logger = context.Telemetry.CreateLogger<UserNameIdentityToken>();
                EncryptedData encryptedData = SecurityPolicies.Encrypt(
                    receiverCertificate,
                    securityPolicyUri,
                    dataToEncrypt,
                    logger);

                m_token.Password = encryptedData.Data;
                m_token.EncryptionAlgorithm = encryptedData.Algorithm;
                Array.Clear(dataToEncrypt, 0, dataToEncrypt.Length);
            }
            // handle ECC encryption.
            else
            {
                // check if the complete chain is included in the sender issuers.
                if (senderIssuerCertificates != null &&
                    senderIssuerCertificates.Count > 0 &&
                    senderIssuerCertificates[0].Thumbprint == senderCertificate.Thumbprint)
                {
                    var issuers = new X509Certificate2Collection();

                    for (int ii = 1; ii < senderIssuerCertificates.Count; ii++)
                    {
                        issuers.Add(senderIssuerCertificates[ii]);
                    }

                    senderIssuerCertificates = issuers;
                }

                var secret = new EncryptedSecret(
                    context,
                    securityPolicyUri,
                    senderIssuerCertificates,
                    receiverCertificate,
                    receiverEphemeralKey,
                    senderCertificate,
                    Nonce.CreateNonce(securityPolicyUri),
                    null,
                    doNotEncodeSenderCertificate);

                m_token.Password = secret.Encrypt(DecryptedPassword, receiverNonce);
                m_token.EncryptionAlgorithm = null;
            }
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
            //zero out existing password
            if (DecryptedPassword != null)
            {
                Array.Clear(DecryptedPassword, 0, DecryptedPassword.Length);
            }

            // handle no encryption.
            if (string.IsNullOrEmpty(securityPolicyUri) ||
                securityPolicyUri == SecurityPolicies.None)
            {
                DecryptedPassword = new byte[m_token.Password.Length];
                Array.Copy(m_token.Password, DecryptedPassword, m_token.Password.Length);
                return;
            }

            // handle RSA encryption.
            if (!EccUtils.IsEccPolicy(securityPolicyUri))
            {
                var encryptedData = new EncryptedData
                {
                    Data = m_token.Password,
                    Algorithm = m_token.EncryptionAlgorithm
                };

                ILogger logger = context.Telemetry.CreateLogger<UserNameIdentityTokenHandler>();
                byte[] decryptedPassword = SecurityPolicies.Decrypt(
                    certificate,
                    securityPolicyUri,
                    encryptedData,
                    logger);

                if (decryptedPassword == null)
                {
                    DecryptedPassword = null;
                    return;
                }

                // verify the sender's nonce.
                int startOfNonce = decryptedPassword.Length;
                if (receiverNonce != null)
                {
                    startOfNonce -= receiverNonce.Data.Length;

                    int result = 0;
                    for (int ii = 0; ii < receiverNonce.Data.Length; ii++)
                    {
                        result |= receiverNonce.Data[ii] ^ decryptedPassword[ii + startOfNonce];
                    }

                    if (result != 0)
                    {
                        throw new ServiceResultException(StatusCodes.BadIdentityTokenRejected);
                    }
                }

                // copy result to m_decrypted password field
                DecryptedPassword = new byte[startOfNonce];
                Array.Copy(decryptedPassword, DecryptedPassword, startOfNonce);
                Array.Clear(decryptedPassword, 0, decryptedPassword.Length);
            }
            // handle ECC encryption.
            else
            {
                var secret = new EncryptedSecret(
                    context,
                    securityPolicyUri,
                    senderIssuerCertificates,
                    certificate,
                    ephemeralKey,
                    senderCertificate,
                    null,
                    validator);

                DecryptedPassword = secret.Decrypt(
                    DateTime.UtcNow.AddHours(-1),
                    receiverNonce.Data,
                    m_token.Password,
                    0,
                    m_token.Password.Length,
                    context.Telemetry);
            }
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
            if (DecryptedPassword != null)
            {
                Array.Clear(DecryptedPassword, 0, DecryptedPassword.Length);
                DecryptedPassword = null;
            }
            if (m_token.Password != null)
            {
                Array.Clear(m_token.Password, 0, m_token.Password.Length);
                m_token.Password = null;
            }
        }

        /// <inheritdoc/>
        public object Clone()
        {
            return new UserNameIdentityTokenHandler(Utils.Clone(m_token))
            {
                DecryptedPassword = DecryptedPassword == null ? null : [.. DecryptedPassword],
            };
        }

        /// <inheritdoc/>
        public bool Equals(IUserIdentityTokenHandler other)
        {
            if (other is not UserNameIdentityTokenHandler tokenHandler)
            {
                return false;
            }
            if (!string.Equals(UserName, tokenHandler.UserName, StringComparison.Ordinal))
            {
                return false;
            }
            // TODO: Should compare password too?
            return true;
        }

        private readonly UserNameIdentityToken m_token;
    }
}
