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
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Opc.Ua.Security.Certificates;

namespace Opc.Ua
{
    /// <summary>
    /// Creates certificates.
    /// </summary>
    public static class CertificateFactory
    {

        /// <summary>
        /// The default key size for RSA certificates in bits.
        /// </summary>
        /// <remarks>
        /// Supported values are 1024(deprecated), 2048, 3072 or 4096.
        /// </remarks>
        public static readonly ushort DefaultKeySize = 2048;
        /// <summary>
        /// The default hash size for RSA certificates in bits.
        /// </summary>
        /// <remarks>
        /// Supported values are 160 for SHA-1(deprecated) or 256, 384 and 512 for SHA-2.
        /// </remarks>
        public static readonly ushort DefaultHashSize = 256;
        /// <summary>
        /// The default lifetime of certificates in months.
        /// </summary>
        public static readonly ushort DefaultLifeTime = 12;



        /// <summary>
        /// Creates a certificate from a buffer with DER encoded certificate.
        /// </summary>
        /// <param name="encodedData">The encoded data.</param>
        /// <param name="useCache">if set to <c>true</c> the copy of the certificate in the cache is used.</param>
        /// <returns>The certificate.</returns>
        public static X509Certificate2 Create(byte[] encodedData, bool useCache)
        {
            if (useCache)
            {
                return Load(new X509Certificate2(encodedData), false);
            }
            return new X509Certificate2(encodedData);
        }

        /// <summary>
        /// Loads the cached version of a certificate.
        /// </summary>
        /// <param name="certificate">The certificate to load.</param>
        /// <param name="ensurePrivateKeyAccessible">If true a key container is created for a certificate that must be deleted by calling Cleanup.</param>
        /// <returns>The cached certificate.</returns>
        /// <remarks>
        /// This function is necessary because all private keys used for cryptography
        /// operations must be in a key container.
        /// Private keys stored in a PFX file have no key container by default.
        /// </remarks>
        public static X509Certificate2 Load(X509Certificate2 certificate, bool ensurePrivateKeyAccessible)
        {
            if (certificate == null)
            {
                return null;
            }

            lock (m_certificatesLock)
            {
                X509Certificate2 cachedCertificate = null;

                // check for existing cached certificate.
                if (m_certificates.TryGetValue(certificate.Thumbprint, out cachedCertificate))
                {
                    return cachedCertificate;
                }

                // nothing more to do if no private key or dont care about accessibility.
                if (!certificate.HasPrivateKey || !ensurePrivateKeyAccessible)
                {
                    return certificate;
                }

                if (ensurePrivateKeyAccessible)
                {
                    if (!X509Utils.VerifyRSAKeyPair(certificate, certificate))
                    {
                        Utils.LogWarning("Trying to add certificate to cache with invalid private key.");
                        return null;
                    }
                }

                // update the cache.
                m_certificates[certificate.Thumbprint] = certificate;

                if (m_certificates.Count > 100)
                {
                    Utils.LogWarning("Certificate cache has {0} certificates in it.", m_certificates.Count);
                }

            }
            return certificate;
        }

        /// <summary>
        /// Create a certificate for an OPC UA application.
        /// </summary>
        /// <param name="applicationUri">The application Uri</param>
        /// <param name="applicationName">The friendly name of the application</param>
        /// <param name="subjectName">The subject of the certificate</param>
        /// <param name="domainNames">The domain names for the alt name extension</param>
        /// <returns>
        /// Return the Certificate builder with X509 Subject Alt Name extension
        /// to create the certificate.
        /// </returns>
        public static ICertificateBuilder CreateCertificate(
            string applicationUri,
            string applicationName,
            string subjectName,
            IList<string> domainNames)
        {
            SetSuitableDefaults(
                ref applicationUri,
                ref applicationName,
                ref subjectName,
                ref domainNames);

            return CertificateBuilder.Create(subjectName)
                .AddExtension(new X509SubjectAltNameExtension(applicationUri, domainNames));
        }

        /// <summary>
        /// Creates a certificate signing request from an existing certificate.
        /// </summary>
        public static byte[] CreateSigningRequest(
            X509Certificate2 certificate,
            IList<string> domainNames = null
            )
        {
            if (!certificate.HasPrivateKey)
            {
                throw new NotSupportedException("Need a certificate with a private key.");
            }

            RSA rsaPublicKey = certificate.GetRSAPublicKey();
            var request = new CertificateRequest(certificate.SubjectName, rsaPublicKey,
                Oids.GetHashAlgorithmName(certificate.SignatureAlgorithm.Value), RSASignaturePadding.Pkcs1);

            X509SubjectAltNameExtension alternateName = X509Extensions.FindExtension<X509SubjectAltNameExtension>(certificate);
            domainNames = domainNames ?? new List<string>();
            if (alternateName != null)
            {
                foreach (string name in alternateName.DomainNames)
                {
                    if (!domainNames.Any(s => s.Equals(name, StringComparison.OrdinalIgnoreCase)))
                    {
                        domainNames.Add(name);
                    }
                }
                foreach (string ipAddress in alternateName.IPAddresses)
                {
                    if (!domainNames.Any(s => s.Equals(ipAddress, StringComparison.OrdinalIgnoreCase)))
                    {
                        domainNames.Add(ipAddress);
                    }
                }
            }

            string applicationUri = X509Utils.GetApplicationUriFromCertificate(certificate);

            // Subject Alternative Name
            var subjectAltName = new X509SubjectAltNameExtension(applicationUri, domainNames);
            request.CertificateExtensions.Add(new X509Extension(subjectAltName, false));

            using (RSA rsa = certificate.GetRSAPrivateKey())
            {
                var x509SignatureGenerator = X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1);
                return request.CreateSigningRequest(x509SignatureGenerator);
            }
        }


        /// <summary>
        /// Create a X509Certificate2 with a private key by combining
        /// the new certificate with a private key from an existing certificate
        /// </summary>
        public static X509Certificate2 CreateCertificateWithPrivateKey(
            X509Certificate2 certificate,
            X509Certificate2 certificateWithPrivateKey)
        {
            if (!certificateWithPrivateKey.HasPrivateKey)
            {
                throw new NotSupportedException("Need a certificate with a private key.");
            }

            if (!X509Utils.VerifyRSAKeyPair(certificate, certificateWithPrivateKey))
            {
                throw new NotSupportedException("The public and the private key pair doesn't match.");
            }

            return certificate.CopyWithPrivateKey(certificateWithPrivateKey.GetRSAPrivateKey());
        }

        /// <summary>
        /// Create a X509Certificate2 with a private key by combining
        /// the certificate with a private key from a PEM stream
        /// </summary>
        public static X509Certificate2 CreateCertificateWithPEMPrivateKey(
            X509Certificate2 certificate,
            byte[] pemDataBlob,
            string password = null)
        {
            RSA rsaPrivateKey = PEMReader.ImportPrivateKeyFromPEM(pemDataBlob, password);
            return new X509Certificate2(certificate.RawData).CopyWithPrivateKey(rsaPrivateKey);
        }



        /// <summary>
        /// Sets the parameters to suitable defaults.
        /// </summary>
        private static void SetSuitableDefaults(
            ref string applicationUri,
            ref string applicationName,
            ref string subjectName,
            ref IList<string> domainNames)
        {
            // parse the subject name if specified.
            List<string> subjectNameEntries = null;

            if (!string.IsNullOrEmpty(subjectName))
            {
                subjectNameEntries = X509Utils.ParseDistinguishedName(subjectName);
            }

            // check the application name.
            if (string.IsNullOrEmpty(applicationName))
            {
                if (subjectNameEntries == null)
                {
                    throw new ArgumentNullException(nameof(applicationName), "Must specify a applicationName or a subjectName.");
                }

                // use the common name as the application name.
                for (int ii = 0; ii < subjectNameEntries.Count; ii++)
                {
                    if (subjectNameEntries[ii].StartsWith("CN="))
                    {
                        applicationName = subjectNameEntries[ii].Substring(3).Trim();
                        break;
                    }
                }
            }

            if (string.IsNullOrEmpty(applicationName))
            {
                throw new ArgumentNullException(nameof(applicationName), "Must specify a applicationName or a subjectName.");
            }

            // remove special characters from name.
            var buffer = new StringBuilder();

            for (int ii = 0; ii < applicationName.Length; ii++)
            {
                char ch = applicationName[ii];

                if (char.IsControl(ch) || ch == '/' || ch == ',' || ch == ';')
                {
                    ch = '+';
                }

                buffer.Append(ch);
            }

            applicationName = buffer.ToString();

            // ensure at least one host name.
            if (domainNames == null || domainNames.Count == 0)
            {
                domainNames = new List<string> {
                    Utils.GetHostName()
                };
            }

            // create the application uri.
            if (string.IsNullOrEmpty(applicationUri))
            {
                var builder = new StringBuilder();

                builder.Append("urn:");
                builder.Append(domainNames[0]);
                builder.Append(':');
                builder.Append(applicationName);

                applicationUri = builder.ToString();
            }

            Uri uri = Utils.ParseUri(applicationUri);

            if (uri == null)
            {
                throw new ArgumentNullException(nameof(applicationUri), "Must specify a valid URL.");
            }

            // create the subject name,
            if (string.IsNullOrEmpty(subjectName))
            {
                subjectName = Utils.Format("CN={0}", applicationName);
            }

            if (!subjectName.Contains("CN="))
            {
                subjectName = Utils.Format("CN={0}", subjectName);
            }

            if (domainNames != null && domainNames.Count > 0)
            {
                if (!subjectName.Contains("DC=") && !subjectName.Contains('='))
                {
                    subjectName += Utils.Format(", DC={0}", domainNames[0]);
                }
                else
                {
                    subjectName = Utils.ReplaceDCLocalhost(subjectName, domainNames[0]);
                }
            }
        }


        private static readonly Dictionary<string, X509Certificate2> m_certificates = new Dictionary<string, X509Certificate2>();
        private static readonly object m_certificatesLock = new object();
    }
}
