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
using System.Xml;

namespace Opc.Ua
{
    /// <summary>
    /// Describes how to connect to an endpoint.
    /// </summary>
    public partial class EndpointDescription
    {
        /// <summary>
        /// Creates an endpoint configuration from a url.
        /// </summary>
        public EndpointDescription(string url)
        {
            Initialize();

            var parsedUrl = new UriBuilder(url);

            if (parsedUrl.Scheme == Uri.UriSchemeHttps &&
                !parsedUrl.Path.EndsWith(
                    DiscoverySuffix,
                    StringComparison.OrdinalIgnoreCase))
            {
                parsedUrl.Path += DiscoverySuffix;
            }

            Server.DiscoveryUrls.Add(parsedUrl.ToString());

            EndpointUrl = url;
            Server.ApplicationUri = url;
            Server.ApplicationName = url;
            SecurityMode = MessageSecurityMode.None;
            SecurityPolicyUri = null; // SecurityPolicies.None;
        }

        /// <summary>
        /// A discovery suffix that may be appended to the discovery url of https endpoints.
        /// </summary>
        public static readonly string DiscoverySuffix = "/discovery";

        /// <summary>
        /// The proxy url to use when connecting to the endpoint.
        /// </summary>
        public Uri ProxyUrl { get; set; }
    }
}
