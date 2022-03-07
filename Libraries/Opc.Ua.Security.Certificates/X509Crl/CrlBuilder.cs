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
using System.Collections.Generic;

namespace Opc.Ua.Security.Certificates
{
    /// <summary>
    /// Builds a CRL.
    /// </summary>
    public sealed class CrlBuilder : IX509CRL
    {

        /// <summary>
        /// Create a CRL builder initialized with a decoded CRL.
        /// </summary>
        /// <param name="crl">The decoded CRL</param>
        private CrlBuilder(IX509CRL crl)
        {
            IssuerName = crl.IssuerName;
            HashAlgorithmName = crl.HashAlgorithmName;
            ThisUpdate = crl.ThisUpdate;
            NextUpdate = crl.NextUpdate;
            RawData = crl.RawData;
            m_revokedCertificates = new List<RevokedCertificate>(crl.RevokedCertificates);
            m_crlExtensions = new X509ExtensionCollection();
            foreach (X509Extension extension in crl.CrlExtensions)
            {
                m_crlExtensions.Add(extension);
            }
        }

        /// <summary>
        /// Initialize the CRL builder with Issuer.
        /// </summary>
        /// <param name="issuerSubjectName">Issuer name</param>
        private CrlBuilder(X500DistinguishedName issuerSubjectName)
            : this(issuerSubjectName, X509Defaults.HashAlgorithmName)
        {
        }

        /// <summary>
        /// Initialize the CRL builder with Issuer and hash algorithm.
        /// </summary>
        /// <param name="issuerSubjectName">Issuer distinguished name</param>
        /// <param name="hashAlgorithmName">The signing algorithm to use.</param>
        private CrlBuilder(X500DistinguishedName issuerSubjectName, HashAlgorithmName hashAlgorithmName)
            : this()
        {
            IssuerName = issuerSubjectName;
            HashAlgorithmName = hashAlgorithmName;
        }

        /// <summary>
        /// Default constructor.
        /// </summary>
        private CrlBuilder()
        {
            ThisUpdate = DateTime.UtcNow;
            NextUpdate = DateTime.MinValue;
            m_revokedCertificates = new List<RevokedCertificate>();
            m_crlExtensions = new X509ExtensionCollection();
        }


        /// <inheritdoc/>
        public X500DistinguishedName IssuerName { get; }

        /// <inheritdoc/>
        public string Issuer => IssuerName.Name;

        /// <inheritdoc/>
        public DateTime ThisUpdate { get; private set; }

        /// <inheritdoc/>
        public DateTime NextUpdate { get; private set; }

        /// <inheritdoc/>
        public HashAlgorithmName HashAlgorithmName { get; private set; }

        /// <inheritdoc/>
        public IList<RevokedCertificate> RevokedCertificates => m_revokedCertificates;

        /// <inheritdoc/>
        public X509ExtensionCollection CrlExtensions => m_crlExtensions;

        /// <inheritdoc/>
        public byte[] RawData { get; private set; }



        private readonly List<RevokedCertificate> m_revokedCertificates;
        private readonly X509ExtensionCollection m_crlExtensions;

    }
}
