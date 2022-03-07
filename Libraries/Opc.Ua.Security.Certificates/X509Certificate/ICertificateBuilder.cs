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

using System.Security.Cryptography.X509Certificates;

namespace Opc.Ua.Security.Certificates
{
    /// <summary>
    /// The certificate builder interface.
    /// </summary>
    public interface ICertificateBuilder
        : ICertificateBuilderConfig
        , ICertificateBuilderPublicKey
        , ICertificateBuilderSetIssuer
        , ICertificateBuilderParameter
        , ICertificateBuilderCreateForRSA
        , IX509Certificate
    { }

    /// <summary>
    /// The interface to set an issuer.
    /// </summary>
    public interface ICertificateBuilderIssuer
        : ICertificateBuilderPublicKey
        , ICertificateBuilderCreateForRSA
        , ICertificateBuilderParameter
        , ICertificateBuilderCreateGenerator
    { }

    /// <summary>
    /// The interface to set a public key.
    /// </summary>
    public interface ICertificateBuilderPublicKey
        : ICertificateBuilderRSAPublicKey
#if ECC_SUPPORT
        , ICertificateBuilderECDsaPublicKey
#endif
    { }

    /// <summary>
    /// The interface to set key parameters.
    /// </summary>
    public interface ICertificateBuilderParameter
        : ICertificateBuilderRSAParameter
#if ECC_SUPPORT
        , ICertificateBuilderECCParameter
#endif
    { }

    /// <summary>
    /// The interface to use a signature generator.
    /// </summary>
    public interface ICertificateBuilderCreateGenerator
        : ICertificateBuilderCreateForRSAGenerator
#if ECC_SUPPORT
        , ICertificateBuilderCreateForECDsaGenerator
#endif
    { }

    /// <summary>
    /// The interface to create a RSA based certifcate.
    /// </summary>
    public interface ICertificateBuilderCreateForRSAAny
        : ICertificateBuilderCreateForRSA
        , ICertificateBuilderCreateForRSAGenerator
    { }

#if ECC_SUPPORT
    /// <summary>
    /// The interface to create a ECDSA based certifcate.
    /// </summary>
    public interface ICertificateBuilderCreateForECDsaAny
        : ICertificateBuilderCreateForECDsa
        , ICertificateBuilderCreateForECDsaGenerator
    { }
#endif

    /// <summary>
    /// The interface to set the mandatory certificate
    /// fields for a certificate builder.
    /// </summary>
    public interface ICertificateBuilderConfig
    {

        /// <summary>
        /// Set the lifetime of the certificate in month starting now.
        /// </summary>
        /// <param name="months">The lifetime in months.</param>
        ICertificateBuilder SetLifeTime(ushort months);

        /// <summary>
        /// Add an extension to the certificate in addition to the default extensions.
        /// </summary>
        /// <remarks>
        /// By default the following X509 extensions are added to a certificate,
        /// some depending on certificate type:
        /// CA/SubCA/OPC UA application:
        ///     X509BasicConstraintsExtension
        ///     X509SubjectKeyIdentifierExtension
        ///     X509AuthorityKeyIdentifierExtension
        ///     X509KeyUsageExtension
        /// OPC UA application:
        ///     X509SubjectAltNameExtension
        ///     X509EnhancedKeyUsageExtension
        /// Adding a default extension to the list overrides the default
        /// value of the extensions.
        /// Adding an extension with a already existing Oid overrides
        /// the existing extension in the list.
        /// </remarks>
        /// <param name="extension">The extension to add</param>
        ICertificateBuilder AddExtension(X509Extension extension);
    }

    /// <summary>
    /// The interface to select an issuer for the cert builder.
    /// </summary>
    public interface ICertificateBuilderSetIssuer
    {
    }

    /// <summary>
    /// The interface to select the RSA key size parameter.
    /// </summary>
    public interface ICertificateBuilderRSAParameter
    {
        /// <summary>
        /// Set the RSA key size in bits.
        /// </summary>
        /// <param name="keySize">The size of the RSA key.</param>
        ICertificateBuilderCreateForRSAAny SetRSAKeySize(ushort keySize);
    }

#if ECC_SUPPORT
    /// <summary>
    /// The interface to select the ECCurve.
    /// </summary>
    public interface ICertificateBuilderECCParameter
    {
    }
#endif

    /// <summary>
    /// The interface to set a RSA public key for a certificate.
    /// </summary>
    public interface ICertificateBuilderRSAPublicKey
    {
    }

#if ECC_SUPPORT
    /// <summary>
    /// The interface to set a ECDSA public key for a certificate.
    /// </summary>
    public interface ICertificateBuilderECDsaPublicKey
    {
    }
#endif

    /// <summary>
    /// The interface to create a certificate using the RSA algorithm.
    /// </summary>
    public interface ICertificateBuilderCreateForRSA
    {
        /// <summary>
        /// Create the RSA certificate with signature.
        /// </summary>
        /// <returns>The signed certificate.</returns>
        X509Certificate2 CreateForRSA();
    }

    /// <summary>
    /// The interface to create a certificate using a signature generator.
    /// </summary>
    public interface ICertificateBuilderCreateForRSAGenerator
    {
    }

#if ECC_SUPPORT
    /// <summary>
    /// The interface to create a certificate using the ECDSA algorithm.
    /// </summary>
    public interface ICertificateBuilderCreateForECDsa
    {
    }

    /// <summary>
    /// The interface to create a certificate using a signature generator for ECDSA.
    /// </summary>
    public interface ICertificateBuilderCreateForECDsaGenerator
    {
    }
#endif
}
