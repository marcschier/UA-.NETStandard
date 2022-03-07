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

namespace Opc.Ua
{

    /// <summary>
    /// A list of trusted certificates.
    /// </summary>
    /// <remarks>
    /// Administrators can create a list of trusted certificates by designating all certificates 
    /// in a particular certificate store as trusted and/or by explictly specifying a list of 
    /// individual certificates.
    /// 
    /// A trust list can contain either instance certificates or certification authority certificates.
    /// If the list contains instance certificates the application will trust peers that use the
    /// instance certificate (provided the ApplicationUri and HostName match the certificate).
    /// 
    /// If the list contains certification authority certificates then the application will trust
    /// peers that have certificates issued by one of the authorities.
    /// 
    /// Any certificate could be revoked by the issuer (CAs may issue certificates for other CAs).
    /// The RevocationMode specifies whether this check should be done each time a certificate
    /// in the list are used.
    /// </remarks>
    public partial class CertificateTrustList : CertificateStoreIdentifier
    {

        /// <summary>
        /// Returns an object to access the store containing the certificate of the trustlist.
        /// </summary>
        /// <remarks>
        /// Opens a cached instance of the store which contains public keys.
        /// To take advantage of the certificate cache use <see cref="ICertificateStore.Close"/>
        /// and let the CertificateTrustList handle the dispose.
        /// Disposing the store has no functional impact but may
        /// enforce unnecessary refresh of the cached certificate store.
        /// </remarks>
        /// <returns>A disposable instance of the <see cref="ICertificateStore"/>.</returns>
        public override ICertificateStore OpenStore()
        {
            lock (m_lock)
            {
                if (m_store == null ||
                    m_store.StoreType != StoreType ||
                    m_store.StorePath != StorePath)
                {
                    m_store = CreateStore(StoreType);
                }
                m_store.Open(StorePath, true);
                return m_store;
            }
        }



        private object m_lock;
        private ICertificateStore m_store;

    }

}
