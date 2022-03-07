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
    /// Describes how to connect to an endpoint.
    /// </summary>
    public partial class EndpointConfiguration
    {

        /// <summary>
        /// Creates an instance of a configuration with reasonable default values.
        /// </summary>
        public static EndpointConfiguration Create()
        {
            var configuration = new EndpointConfiguration {
                OperationTimeout = 120000,
                UseBinaryEncoding = true,
                MaxArrayLength = ushort.MaxValue,
                MaxByteStringLength = ushort.MaxValue * 16,
                MaxMessageSize = ushort.MaxValue * 64,
                MaxStringLength = ushort.MaxValue,
                MaxBufferSize = ushort.MaxValue,
                ChannelLifetime = 120000,
                SecurityTokenLifetime = 3600000
            };

            return configuration;
        }

        /// <summary>
        /// Creates an instance of a configuration with reasonable default values.
        /// </summary>
        public static EndpointConfiguration Create(ApplicationConfiguration applicationConfiguration)
        {
            if (applicationConfiguration == null || applicationConfiguration.TransportQuotas == null)
            {
                return Create();
            }

            var configuration = new EndpointConfiguration {
                OperationTimeout = applicationConfiguration.TransportQuotas.OperationTimeout,
                UseBinaryEncoding = true,
                MaxArrayLength = applicationConfiguration.TransportQuotas.MaxArrayLength,
                MaxByteStringLength = applicationConfiguration.TransportQuotas.MaxByteStringLength,
                MaxMessageSize = applicationConfiguration.TransportQuotas.MaxMessageSize,
                MaxStringLength = applicationConfiguration.TransportQuotas.MaxStringLength,
                MaxBufferSize = applicationConfiguration.TransportQuotas.MaxBufferSize,
                ChannelLifetime = applicationConfiguration.TransportQuotas.ChannelLifetime,
                SecurityTokenLifetime = applicationConfiguration.TransportQuotas.SecurityTokenLifetime
            };

            return configuration;
        }

    }
}
