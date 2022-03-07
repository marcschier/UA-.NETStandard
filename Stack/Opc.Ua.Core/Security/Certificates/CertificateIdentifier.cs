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
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Opc.Ua.Security.Certificates;

namespace Opc.Ua
{
    /// <summary>
    /// The identifier for an X509 certificate.
    /// </summary>
    public partial class CertificateIdentifier : IFormattable
    {

        /// <summary>
        /// Formats the value of the current instance using the specified format.
        /// </summary>
        /// <param name="format">The <see cref="T:System.String"/> specifying the format to use.
        /// -or-
        /// null to use the default format defined for the type of the <see cref="T:System.IFormattable"/> implementation.</param>
        /// <param name="formatProvider">The <see cref="T:System.IFormatProvider"/> to use to format the value.
        /// -or-
        /// null to obtain the numeric format information from the current locale setting of the operating system.</param>
        /// <returns>
        /// A <see cref="T:System.String"/> containing the value of the current instance in the specified format.
        /// </returns>
        public string ToString(string format, IFormatProvider formatProvider)
        {
            if (!string.IsNullOrEmpty(format))
            {
                throw new FormatException();
            }

            return ToString();
        }



        /// <summary>
        /// Returns a <see cref="T:System.String"/> that represents the current <see cref="T:System.Object"/>.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.String"/> that represents the current <see cref="T:System.Object"/>.
        /// </returns>
        public override string ToString()
        {
            if (m_certificate != null)
            {
                return GetDisplayName(m_certificate);
            }

            if (m_subjectName != null)
            {
                return m_subjectName;
            }

            return m_thumbprint;
        }

        /// <summary>
        /// Returns true if the objects are equal.
        /// </summary>
        public override bool Equals(object obj)
        {
            if (Object.ReferenceEquals(this, obj))
            {
                return true;
            }


            if (!(obj is CertificateIdentifier id))
            {
                return false;
            }

            if (m_certificate != null && id.m_certificate != null)
            {
                return m_certificate.Thumbprint == id.m_certificate.Thumbprint;
            }

            if (Thumbprint == id.Thumbprint)
            {
                return true;
            }

            if (m_storeLocation != id.m_storeLocation)
            {
                return false;
            }

            if (m_storeName != id.m_storeName)
            {
                return false;
            }

            if (SubjectName != id.SubjectName)
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Returns a suitable hash code.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }



        /// <summary>
        /// Gets or sets the validation options.
        /// </summary>
        /// <value>
        /// The validation options that can be used to suppress certificate validation errors.
        /// </value>
        public CertificateValidationOptions ValidationOptions
        {
            get => m_validationOptions;
            set => m_validationOptions = value;
        }

        /// <summary>
        /// Gets or sets the actual certificate.
        /// </summary>
        /// <value>The X509 certificate used by this instance.</value>
        public X509Certificate2 Certificate
        {
            get => m_certificate;
            set => m_certificate = value;
        }



        /// <summary>
        /// Finds a certificate in a store.
        /// </summary>
        public Task<X509Certificate2> Find()
        {
            return Find(false);
        }

        /// <summary>
        /// Loads the private key for the certificate with an optional password.
        /// </summary>
        public async Task<X509Certificate2> LoadPrivateKeyEx(ICertificatePasswordProvider passwordProvider)
        {
            if (StoreType != CertificateStoreType.X509Store)
            {
                using (ICertificateStore store = CertificateStoreIdentifier.CreateStore(StoreType))
                {
                    if (store.SupportsLoadPrivateKey)
                    {
                        store.Open(StorePath, false);
                        string password = passwordProvider?.GetPassword(this);
                        m_certificate = await store.LoadPrivateKey(Thumbprint, SubjectName, password).ConfigureAwait(false);
                        return m_certificate;
                    }
                }
            }
            return await Find(true).ConfigureAwait(false);
        }

        /// <summary>
        /// Finds a certificate in a store.
        /// </summary>
        /// <param name="needPrivateKey">if set to <c>true</c> the returned certificate must contain the private key.</param>
        /// <returns>An instance of the <see cref="X509Certificate2"/> that is embedded by this instance or find it in 
        /// the selected store pointed out by the <see cref="StorePath"/> using selected <see cref="SubjectName"/>.</returns>
        public async Task<X509Certificate2> Find(bool needPrivateKey)
        {
            X509Certificate2 certificate = null;

            // check if the entire certificate has been specified.
            if (m_certificate != null && (!needPrivateKey || m_certificate.HasPrivateKey))
            {
                certificate = m_certificate;
            }
            else
            {
                // open store.
                using (ICertificateStore store = CertificateStoreIdentifier.CreateStore(StoreType))
                {
                    store.Open(StorePath, false);

                    X509Certificate2Collection collection = await store.Enumerate().ConfigureAwait(false);

                    certificate = Find(collection, m_thumbprint, m_subjectName, needPrivateKey);

                    if (certificate != null)
                    {
                        if (needPrivateKey && store.SupportsLoadPrivateKey)
                        {
                            var message = new StringBuilder();
                            message.AppendLine("Loaded a certificate with private key from store {0}.");
                            message.AppendLine("Ensure to call LoadPrivateKeyEx with password provider before calling Find(true).");
                            Utils.LogWarning(message.ToString(), StoreType);
                        }

                        m_certificate = certificate;
                    }
                }
            }

            // use the single instance in the certificate cache.
            if (needPrivateKey)
            {
                certificate = m_certificate = CertificateFactory.Load(certificate, true);
            }

            return certificate;
        }

        /// <summary>
        /// Returns a display name for a certificate.
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <returns>
        /// A string containg FriendlyName of the <see cref="X509Certificate2"/> or created using Subject of 
        /// the <see cref="X509Certificate2"/>.
        /// </returns>
        private static string GetDisplayName(X509Certificate2 certificate)
        {
            if (!string.IsNullOrEmpty(certificate.FriendlyName))
            {
                return certificate.FriendlyName;
            }

            string name = certificate.Subject;

            // find the common name delimiter.
            int index = name.IndexOf("CN", StringComparison.Ordinal);

            if (index == -1)
            {
                return name;
            }

            var buffer = new StringBuilder(name.Length);

            // skip characters until finding the '=' character
            for (int ii = index + 2; ii < name.Length; ii++)
            {
                if (name[ii] == '=')
                {
                    index = ii + 1;
                    break;
                }
            }

            // skip whitespace.
            for (int ii = index; ii < name.Length; ii++)
            {
                if (!char.IsWhiteSpace(name[ii]))
                {
                    index = ii;
                    break;
                }
            }

            // read the common until finding a ','.
            for (int ii = index; ii < name.Length; ii++)
            {
                if (name[ii] == ',')
                {
                    break;
                }

                buffer.Append(name[ii]);
            }

            return buffer.ToString();
        }

        /// <summary>
        /// Finds a certificate in the specified collection.
        /// </summary>
        /// <param name="collection">The collection.</param>
        /// <param name="thumbprint">The thumbprint of the certificate.</param>
        /// <param name="subjectName">Subject name of the certificate.</param>
        /// <param name="needPrivateKey">if set to <c>true</c> [need private key].</param>
        /// <returns></returns>
        public static X509Certificate2 Find(X509Certificate2Collection collection, string thumbprint, string subjectName, bool needPrivateKey)
        {
            // find by thumbprint.
            if (!string.IsNullOrEmpty(thumbprint))
            {
                collection = collection.Find(X509FindType.FindByThumbprint, thumbprint, false);

                foreach (X509Certificate2 certificate in collection)
                {
                    if (!needPrivateKey || certificate.HasPrivateKey)
                    {
                        if (string.IsNullOrEmpty(subjectName))
                        {
                            return certificate;
                        }

                        List<string> subjectName2 = X509Utils.ParseDistinguishedName(subjectName);

                        if (X509Utils.CompareDistinguishedName(certificate, subjectName2))
                        {
                            return certificate;
                        }
                    }
                }

                return null;
            }
            // find by subject name.
            if (!string.IsNullOrEmpty(subjectName))
            {
                List<string> subjectName2 = X509Utils.ParseDistinguishedName(subjectName);

                foreach (X509Certificate2 certificate in collection)
                {
                    if (X509Utils.CompareDistinguishedName(certificate, subjectName2))
                    {
                        if ((!needPrivateKey || certificate.HasPrivateKey) && X509Utils.GetRSAPublicKeySize(certificate) >= 0)
                        {
                            return certificate;
                        }
                    }
                }

                collection = collection.Find(X509FindType.FindBySubjectName, subjectName, false);

                foreach (X509Certificate2 certificate in collection)
                {
                    if ((!needPrivateKey || certificate.HasPrivateKey) && X509Utils.GetRSAPublicKeySize(certificate) >= 0)
                    {
                        return certificate;
                    }
                }
            }

            // certificate not found.
            return null;
        }

        /// <summary>
        /// Returns an object to access the store containing the certificate.
        /// </summary>
        /// <remarks>
        /// Opens a store which contains public and private keys.
        /// </remarks>
        /// <returns>A disposable instance of the <see cref="ICertificateStore"/>.</returns>
        public ICertificateStore OpenStore()
        {
            ICertificateStore store = CertificateStoreIdentifier.CreateStore(StoreType);
            store.Open(StorePath, false);
            return store;
        }

    }


    /// <summary>
    /// A collection of CertificateIdentifier objects.
    /// </summary>
    public partial class CertificateIdentifierCollection : ICertificateStore
    {


        /// <summary>
        /// Frees any unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        /// <summary>
        /// An overrideable version of the Dispose.
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                // nothing to do.
            }
        }



        /// <inheritdoc/>
        /// <remarks>
        /// The certificate identifier store ignores the location.
        /// </remarks>
        public void Open(string location, bool noPrivateKeys)
        {
            // nothing to do.
        }

        /// <inheritdoc/>
        public void Close()
        {
            // nothing to do.
        }

        /// <inheritdoc/>
        public string StoreType => string.Empty;

        /// <inheritdoc/>
        public string StorePath => string.Empty;

        /// <inheritdoc/>
        public async Task<X509Certificate2Collection> Enumerate()
        {
            var collection = new X509Certificate2Collection();

            for (int ii = 0; ii < Count; ii++)
            {
                X509Certificate2 certificate = await this[ii].Find(false).ConfigureAwait(false);

                if (certificate != null)
                {
                    collection.Add(certificate);
                }
            }

            return collection;
        }

        /// <inheritdoc/>
        public async Task Add(X509Certificate2 certificate, string password = null)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            for (int ii = 0; ii < Count; ii++)
            {
                X509Certificate2 current = await this[ii].Find(false).ConfigureAwait(false);

                if (current != null && current.Thumbprint == certificate.Thumbprint)
                {
                    throw ServiceResultException.Create(
                        StatusCodes.BadEntryExists,
                        "A certificate with the specified thumbprint already exists. Subject={0}, Thumbprint={1}",
                        certificate.SubjectName,
                        certificate.Thumbprint);
                }
            }

            Add(new CertificateIdentifier(certificate));
        }

        /// <inheritdoc/>
        public async Task<bool> Delete(string thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                return false;
            }

            for (int ii = 0; ii < Count; ii++)
            {
                X509Certificate2 certificate = await this[ii].Find(false).ConfigureAwait(false);

                if (certificate != null && certificate.Thumbprint == thumbprint)
                {
                    RemoveAt(ii);
                    return true;
                }
            }

            return false;
        }

        /// <inheritdoc/>
        public async Task<X509Certificate2Collection> FindByThumbprint(string thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                return null;
            }

            for (int ii = 0; ii < Count; ii++)
            {
                X509Certificate2 certificate = await this[ii].Find(false).ConfigureAwait(false);

                if (certificate != null && certificate.Thumbprint == thumbprint)
                {
                    return new X509Certificate2Collection { certificate };
                }
            }

            return new X509Certificate2Collection();
        }

        /// <inheritdoc/>
        public bool SupportsLoadPrivateKey => false;

        /// <inheritdoc/>
        public Task<X509Certificate2> LoadPrivateKey(string thumbprint, string subjectName, string password)
        {
            return Task.FromResult<X509Certificate2>(null);
        }

        /// <inheritdoc/>
        public Task<StatusCode> IsRevoked(X509Certificate2 issuer, X509Certificate2 certificate)
        {
            return Task.FromResult((StatusCode)StatusCodes.BadNotSupported);
        }

        /// <inheritdoc/>
        public Task<X509CRLCollection> EnumerateCRLs()
        {
            return Task.FromResult(new X509CRLCollection());
        }

        /// <inheritdoc/>
        public Task AddCRL(X509CRL crl)
        {
            throw new ServiceResultException(StatusCodes.BadNotSupported);
        }

        /// <inheritdoc/>
        public Task<bool> DeleteCRL(X509CRL crl)
        {
            throw new ServiceResultException(StatusCodes.BadNotSupported);
        }

    }



    /// <summary>
    /// Options that can be used to suppress certificate validation errors.
    /// </summary>
    [Flags]
    public enum CertificateValidationOptions
    {
        /// <summary>
        /// Use the default options.
        /// </summary>
        Default = 0x0,

        /// <summary>
        /// Ignore expired certificates.
        /// </summary>
        SuppressCertificateExpired = 0x1,

        /// <summary>
        /// Ignore mismatches between the URL and the DNS names in the certificate.
        /// </summary>
        SuppressHostNameInvalid = 0x2,

        /// <summary>
        /// Ignore errors when it is not possible to check the revocation status for a certificate.
        /// </summary>
        SuppressRevocationStatusUnknown = 0x8,

        /// <summary>
        /// Attempt to check the revocation status online.
        /// </summary>
        CheckRevocationStatusOnline = 0x10,

        /// <summary>
        /// Attempt to check the revocation status offline.
        /// </summary>
        CheckRevocationStatusOffine = 0x20,

        /// <summary>
        /// Never trust the certificate.
        /// </summary>
        TreatAsInvalid = 0x40
    }

}
