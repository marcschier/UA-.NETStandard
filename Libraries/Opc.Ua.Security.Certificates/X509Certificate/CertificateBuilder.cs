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

#if NETSTANDARD2_1 || NET472_OR_GREATER || NET5_0_OR_GREATER

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Linq;

namespace Opc.Ua.Security.Certificates
{
    /// <summary>
    /// Builds a Certificate.
    /// </summary>
    public class CertificateBuilder : CertificateBuilderBase
    {

        /// <summary>
        /// Create a Certificate builder.
        /// </summary>
        public static ICertificateBuilder Create(string subjectName)
        {
            return new CertificateBuilder(subjectName);
        }

        /// <summary>
        /// Constructor of a Certificate builder.
        /// </summary>
        private CertificateBuilder(X500DistinguishedName subjectName)
            : base(subjectName)
        {
        }

        /// <summary>
        /// Constructor of a Certificate builder.
        /// </summary>
        private CertificateBuilder(string subjectName)
            : base(subjectName)
        {
        }



        /// <inheritdoc/>
        public override X509Certificate2 CreateForRSA()
        {
            CreateDefaults();

            if (m_rsaPublicKey != null &&
               (IssuerCAKeyCert == null || !IssuerCAKeyCert.HasPrivateKey))
            {
                throw new NotSupportedException("Cannot use a public key without a issuer certificate with a private key.");
            }

            RSA rsaKeyPair = null;
            RSA rsaPublicKey = m_rsaPublicKey;
            if (rsaPublicKey == null)
            {
                rsaKeyPair = RSA.Create(m_keySize == 0 ? X509Defaults.RSAKeySize : m_keySize);
                rsaPublicKey = rsaKeyPair;
            }

            RSASignaturePadding padding = RSASignaturePadding.Pkcs1;
            var request = new CertificateRequest(SubjectName, rsaPublicKey, HashAlgorithmName, padding);

            CreateX509Extensions(request, false);

            X509Certificate2 signedCert;
            byte[] serialNumber = m_serialNumber.Reverse().ToArray();
            if (IssuerCAKeyCert != null)
            {
                X500DistinguishedName issuerSubjectName = IssuerCAKeyCert.SubjectName;
                using (RSA rsaIssuerKey = IssuerCAKeyCert.GetRSAPrivateKey())
                {
                    signedCert = request.Create(
                        IssuerCAKeyCert.SubjectName,
                        X509SignatureGenerator.CreateForRSA(rsaIssuerKey, padding),
                        NotBefore,
                        NotAfter,
                        serialNumber
                        );
                }
            }
            else
            {
                signedCert = request.Create(
                    SubjectName,
                    X509SignatureGenerator.CreateForRSA(rsaKeyPair, padding),
                    NotBefore,
                    NotAfter,
                    serialNumber
                    );
            }

            return (rsaKeyPair == null) ? signedCert : signedCert.CopyWithPrivateKey(rsaKeyPair);
        }

        /// <inheritdoc/>
        public ICertificateBuilderCreateForRSAAny SetRSAPublicKey(byte[] publicKey)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
#if NET472_OR_GREATER
            throw new NotSupportedException("Import a RSAPublicKey is not supported on this platform.");
#else
            int bytes = 0;
            try
            {
                m_rsaPublicKey = RSA.Create();
                m_rsaPublicKey.ImportSubjectPublicKeyInfo(publicKey, out bytes);
            }
            catch (Exception e)
            {
                throw new ArgumentException("Failed to decode the public key.", e);
            }

            if (publicKey.Length != bytes)
            {
                throw new ArgumentException("Decoded the public key but extra bytes were found.");
            }
            return this;
#endif
        }
#endif



        /// <summary>
        /// Create some defaults needed to build the certificate.
        /// </summary>
        private void CreateDefaults()
        {
            if (!m_presetSerial)
            {
                NewSerialNumber();
            }
            m_presetSerial = false;

            ValidateSettings();
        }

        /// <summary>
        /// Create the X509 extensions to build the certificate.
        /// </summary>
        /// <param name="request">A certificate request.</param>
        /// <param name="forECDsa">If the certificate is for ECDsa, not RSA.</param>
        private void CreateX509Extensions(CertificateRequest request, bool forECDsa)
        {
            // Basic Constraints
            X509BasicConstraintsExtension bc = GetBasicContraints();
            request.CertificateExtensions.Add(bc);

            // Subject Key Identifier
            var ski = new X509SubjectKeyIdentifierExtension(
                request.PublicKey,
                X509SubjectKeyIdentifierHashAlgorithm.Sha1,
                false);
            request.CertificateExtensions.Add(ski);

            // Authority Key Identifier
            X509Extension authorityKeyIdentifier = IssuerCAKeyCert != null
                ? X509Extensions.BuildAuthorityKeyIdentifier(IssuerCAKeyCert)
                : new X509AuthorityKeyIdentifierExtension(
                    ski.SubjectKeyIdentifier.FromHexString(),
                    IssuerName,
                    m_serialNumber);
            request.CertificateExtensions.Add(authorityKeyIdentifier);

            X509KeyUsageFlags keyUsageFlags;
            if (m_isCA)
            {
                keyUsageFlags = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign;
            }
            else
            {
                if (forECDsa)
                {
                    // Key Usage for ECDsa
                    keyUsageFlags = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation
                        | X509KeyUsageFlags.KeyAgreement;
                }
                else
                {
                    // Key usage for RSA
                    keyUsageFlags = X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment
                        | X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation;
                }
                if (IssuerCAKeyCert == null)
                {
                    // self signed case
                    keyUsageFlags |= X509KeyUsageFlags.KeyCertSign;
                }
            }

            request.CertificateExtensions.Add(
                                new X509KeyUsageExtension(
                                    keyUsageFlags,
                                    true));

            if (!m_isCA)
            {
                // Enhanced key usage
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection {
                            new Oid(Oids.ServerAuthentication),
                            new Oid(Oids.ClientAuthentication)
                        }, true));
            }

            foreach (X509Extension extension in m_extensions)
            {
                request.CertificateExtensions.Add(extension);
            }
        }

        /// <summary>
        /// Set the basic constraints for various cases.
        /// </summary>
        private X509BasicConstraintsExtension GetBasicContraints()
        {
            // Basic constraints
            if (!m_isCA && IssuerCAKeyCert == null)
            {
                // self signed
                return new X509BasicConstraintsExtension(true, true, 0, true);
            }
            else if (m_isCA && m_pathLengthConstraint >= 0)
            {
                // CA with constraints
                return new X509BasicConstraintsExtension(true, true, m_pathLengthConstraint, true);
            }
            else
            {
                return new X509BasicConstraintsExtension(m_isCA, false, 0, true);
            }
        }




    }
}
