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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Opc.Ua.Security.Certificates
{
    /// <summary>
    /// Builds a Certificate.
    /// </summary>
    public abstract class CertificateBuilderBase
        : IX509Certificate
        , ICertificateBuilder
        , ICertificateBuilderConfig
        , ICertificateBuilderSetIssuer
        , ICertificateBuilderParameter
        , ICertificateBuilderIssuer
        , ICertificateBuilderRSAParameter
        , ICertificateBuilderPublicKey
        , ICertificateBuilderRSAPublicKey
        , ICertificateBuilderCreateForRSA
        , ICertificateBuilderCreateForRSAAny
#if ECC_SUPPORT
        , ICertificateBuilderCreateForECDsa
        , ICertificateBuilderECDsaPublicKey
        , ICertificateBuilderECCParameter
        , ICertificateBuilderCreateForECDsaAny
#endif
    {

        /// <summary>
        /// Initialize a Certificate builder.
        /// </summary>
        protected CertificateBuilderBase(X500DistinguishedName subjectName, X509Certificate2 issuerCAKeyCert = null)
        {
            m_issuerName = m_subjectName = subjectName;
            Initialize();
            m_issuerCAKeyCert = issuerCAKeyCert;
        }

        /// <summary>
        /// Initialize a Certificate builder.
        /// </summary>
        protected CertificateBuilderBase(string subjectName)
        {
            m_issuerName = m_subjectName = new X500DistinguishedName(subjectName);
            Initialize();
        }

        /// <summary>
        /// Default constructor.
        /// </summary>
        protected virtual void Initialize()
        {
            m_notBefore = DateTime.UtcNow.AddDays(-1).Date;
            m_notAfter = NotBefore.AddMonths(X509Defaults.LifeTime);
            m_hashAlgorithmName = X509Defaults.HashAlgorithmName;
            m_serialNumberLength = X509Defaults.SerialNumberLengthMin;
            m_extensions = new X509ExtensionCollection();
        }



        /// <inheritdoc/>
        public X500DistinguishedName SubjectName => m_subjectName;

        /// <inheritdoc/>
        public X500DistinguishedName IssuerName => m_issuerName;

        /// <inheritdoc/>
        public DateTime NotBefore => m_notBefore;

        /// <inheritdoc/>
        public DateTime NotAfter => m_notAfter;

        /// <inheritdoc/>
        public HashAlgorithmName HashAlgorithmName => m_hashAlgorithmName;



        /// <inheritdoc/>
        public abstract X509Certificate2 CreateForRSA();

        /// <inheritdoc/>
        public ICertificateBuilder SetLifeTime(ushort months)
        {
            m_notAfter = m_notBefore.AddMonths(months == 0 ? X509Defaults.LifeTime : months);
            return this;
        }

        /// <inheritdoc/>
        public virtual ICertificateBuilderCreateForRSAAny SetRSAKeySize(ushort keySize)
        {
            if (keySize == 0)
            {
                keySize = X509Defaults.RSAKeySize;
            }

            if (keySize % 1024 != 0 || keySize < X509Defaults.RSAKeySizeMin || keySize > X509Defaults.RSAKeySizeMax)
            {
                throw new ArgumentException("KeySize must be a multiple of 1024 or is not in the allowed range.", nameof(keySize));
            }

            m_keySize = keySize;
            return this;
        }

        /// <inheritdoc/>
        public virtual ICertificateBuilder AddExtension(X509Extension extension)
        {
            if (extension == null)
            {
                throw new ArgumentNullException(nameof(extension));
            }

            m_extensions.Add(extension);
            return this;
        }



        /// <summary>
        /// The issuer CA certificate.
        /// </summary>
        protected X509Certificate2 IssuerCAKeyCert => m_issuerCAKeyCert;

        /// <summary>
        /// Validate and adjust settings to avoid creation of invalid certificates.
        /// </summary>
        protected void ValidateSettings()
        {
            // lifetime must be in range of issuer
            if (m_issuerCAKeyCert != null)
            {
                if (NotAfter.ToUniversalTime() > m_issuerCAKeyCert.NotAfter.ToUniversalTime())
                {
                    m_notAfter = m_issuerCAKeyCert.NotAfter.ToUniversalTime();
                }
                if (NotBefore.ToUniversalTime() < m_issuerCAKeyCert.NotBefore.ToUniversalTime())
                {
                    m_notBefore = m_issuerCAKeyCert.NotBefore.ToUniversalTime();
                }
            }
        }

        /// <summary>
        /// Create a new cryptographic random serial number.
        /// </summary>
        protected virtual void NewSerialNumber()
        {
            // new serial number
            using (var rnd = RandomNumberGenerator.Create())
            {
                m_serialNumber = new byte[m_serialNumberLength];
                rnd.GetBytes(m_serialNumber);
            }
            // A compliant certificate uses a positive serial number.
            m_serialNumber[m_serialNumberLength - 1] &= 0x7F;
        }



        /// <summary>
        /// If the certificate is a CA.
        /// </summary>
        protected bool m_isCA;
        /// <summary>
        /// The path length constraint to sue for a CA.
        /// </summary>
        protected int m_pathLengthConstraint;
        /// <summary>
        /// The serial number length in octets.
        /// </summary>
        protected int m_serialNumberLength;
        /// <summary>
        /// If the serial number is preset by the user.
        /// </summary>
        protected bool m_presetSerial;
        /// <summary>
        /// The serial number as a little endian byte array.
        /// </summary>
        protected byte[] m_serialNumber;
        /// <summary>
        /// The collection of X509Extension to add to the certificate.
        /// </summary>
        protected X509ExtensionCollection m_extensions;
        /// <summary>
        /// The RSA public to use when if a certificate is signed.
        /// </summary>
        protected RSA m_rsaPublicKey;
        /// <summary>
        /// The size of a RSA key pair to create.
        /// </summary>
        protected int m_keySize;
#if ECC_SUPPORT
        /// <summary>
        /// The ECDsa public to use when if a certificate is signed.
        /// </summary>
        protected ECDsa m_ecdsaPublicKey;
        /// <summary>
        /// The ECCurve to use.
        /// </summary>
        protected ECCurve? m_curve;
#endif



        private readonly X509Certificate2 m_issuerCAKeyCert;
        private DateTime m_notBefore;
        private DateTime m_notAfter;
        private HashAlgorithmName m_hashAlgorithmName;
        private readonly X500DistinguishedName m_subjectName;
        private readonly X500DistinguishedName m_issuerName;

    }
}
