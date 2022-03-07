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
using System.Globalization;

namespace Opc.Ua
{
    /// <summary>
    /// Stores a list of cached enpoints.
    /// </summary>
    public partial class ConfiguredEndpointCollection
    {
        /// <summary>
        /// Initializes the object with its default endpoint configuration.
        /// </summary>
        public ConfiguredEndpointCollection(EndpointConfiguration configuration)
        {
            Initialize();

            m_defaultConfiguration = (EndpointConfiguration)configuration.MemberwiseClone();
        }

        /// <summary>
        /// Initializes the object from an application configuration.
        /// </summary>
        public ConfiguredEndpointCollection(ApplicationConfiguration configuration)
        {
            Initialize();

            m_defaultConfiguration = EndpointConfiguration.Create(configuration);

            if (configuration.ClientConfiguration != null)
            {
                m_discoveryUrls = new StringCollection(configuration.ClientConfiguration.WellKnownDiscoveryUrls);
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="Opc.Ua.ConfiguredEndpoint"/> at the specified index.
        /// </summary>
        /// <value>The <see cref="Opc.Ua.ConfiguredEndpoint"/> at the index</value>
        public ConfiguredEndpoint this[int index]
        {
            get => m_endpoints[index];

            set => throw new NotImplementedException();
        }

        /// <summary>
        /// Gets the number of elements contained in the <see cref="T:System.Collections.Generic.ICollection`1"/>.
        /// </summary>
        /// <returns>The number of elements contained in the <see cref="T:System.Collections.Generic.ICollection`1"/>.</returns>
        public int Count => m_endpoints.Count;

        /// <summary>
        /// Gets a value indicating whether the <see cref="T:System.Collections.Generic.ICollection`1"/> is read-only.
        /// </summary>
        /// <value></value>
        /// <returns>true if the <see cref="T:System.Collections.Generic.ICollection`1"/> is read-only; otherwise, false.</returns>
        public bool IsReadOnly => false;


        /// <summary>
        /// Add the endpoint description to the cache.
        /// </summary>
        public ConfiguredEndpoint Add(EndpointDescription endpoint)
        {
            return Add(endpoint, null);
        }

        /// <summary>
        /// Add the endpoint description and configuration to the cache.
        /// </summary>
        public ConfiguredEndpoint Add(EndpointDescription endpoint, EndpointConfiguration configuration)
        {
            ValidateEndpoint(endpoint);

            foreach (ConfiguredEndpoint item in m_endpoints)
            {
                if (Object.ReferenceEquals(item.Description, endpoint))
                {
                    throw new ArgumentException("Endpoint already exists in the collection.");
                }
            }

            var configuredEndpoint = new ConfiguredEndpoint(this, endpoint, configuration);
            m_endpoints.Add(configuredEndpoint);
            return configuredEndpoint;
        }


        /// <summary>
        /// A list of well known urls that can be used for discovery.
        /// </summary>
        public StringCollection DiscoveryUrls
        {
            get => m_discoveryUrls;

            set
            {
                if (value == null)
                {
                    m_discoveryUrls = new StringCollection(Utils.DiscoveryUrls);
                }
                else
                {
                    m_discoveryUrls = value;
                }
            }
        }

        /// <summary>
        /// The default configuration for new ConfiguredEndpoints.
        /// </summary>
        public EndpointConfiguration DefaultConfiguration => m_defaultConfiguration;


        /// <summary>
        /// Throws exceptions if the endpoint is not valid.
        /// </summary>
        private static void ValidateEndpoint(EndpointDescription endpoint)
        {
            if (endpoint == null)
            {
                throw new ArgumentException("Endpoint must not be null.");
            }

            if (string.IsNullOrEmpty(endpoint.EndpointUrl))
            {
                throw new ArgumentException("Endpoint must have a valid URL.");
            }

            if (endpoint.Server == null)
            {
                endpoint.Server = new ApplicationDescription {
                    ApplicationType = ApplicationType.Server
                };
            }

            if (string.IsNullOrEmpty(endpoint.Server.ApplicationUri))
            {
                endpoint.Server.ApplicationUri = endpoint.EndpointUrl;
            }
        }

    }

    /// <summary>
    /// Stores the configuration information for an endpoint.
    /// </summary>
    public partial class ConfiguredEndpoint : IFormattable
    {

        /// <summary>
        /// Creates a configured endpoint from the server description.
        /// </summary>
        public ConfiguredEndpoint(
            ApplicationDescription server,
            EndpointConfiguration configuration)
        {
            if (server == null)
            {
                throw new ArgumentNullException(nameof(server));
            }

            m_description = new EndpointDescription();
            m_updateBeforeConnect = true;

            m_description.Server = server;

            foreach (string discoveryUrl in server.DiscoveryUrls)
            {
                string baseUrl = discoveryUrl;

                if (baseUrl != null)
                {
                    if (baseUrl.EndsWith("/discovery", StringComparison.Ordinal))
                    {
                        baseUrl = baseUrl.Substring(0, baseUrl.Length - "/discovery".Length);
                    }
                }

                Uri url = Utils.ParseUri(baseUrl);

                if (url != null)
                {
                    m_description.EndpointUrl = url.ToString();
                    m_description.SecurityMode = MessageSecurityMode.SignAndEncrypt;
                    m_description.SecurityPolicyUri = SecurityPolicies.Basic256Sha256;
                    m_description.UserIdentityTokens.Add(new UserTokenPolicy(UserTokenType.Anonymous));

                    if (url.Scheme == Utils.UriSchemeHttps)
                    {
                        m_description.TransportProfileUri = Profiles.HttpsBinaryTransport;
                    }

                    if (url.Scheme == Utils.UriSchemeOpcTcp)
                    {
                        m_description.TransportProfileUri = Profiles.UaTcpTransport;
                    }

                    break;
                }
            }

            // ensure a default configuration.
            if (configuration == null)
            {
                configuration = EndpointConfiguration.Create();
            }

            Update(configuration);
        }

        /// <summary>
        /// The default constructor.
        /// </summary>
        public ConfiguredEndpoint(
            ConfiguredEndpointCollection collection,
            EndpointDescription description)
        :
            this(collection, description, null)
        {
        }

        /// <summary>
        /// The default constructor.
        /// </summary>
        public ConfiguredEndpoint(
            ConfiguredEndpointCollection collection,
            EndpointDescription description,
            EndpointConfiguration configuration)
        {
            if (description == null)
            {
                throw new ArgumentNullException(nameof(description));
            }

            m_collection = collection;
            m_description = description;
            m_updateBeforeConnect = true;

            // ensure a default configuration.
            if (configuration == null)
            {
                if (collection != null)
                {
                    configuration = collection.DefaultConfiguration;
                }
                else
                {
                    configuration = EndpointConfiguration.Create();
                }
            }

            Update(configuration);
        }


        /// <summary>
        /// Returns the string representation of the object.
        /// </summary>
        public override string ToString()
        {
            return ToString(null, null);
        }



        /// <summary>
        /// Returns the string representation of the object.
        /// </summary>
        /// <param name="format">(Unused). Always pass NULL/NOTHING</param>
        /// <param name="formatProvider">(Unused). Always pass NULL/NOTHING</param>
        /// <exception cref="FormatException">Thrown if non-null parameters are used</exception>
        public string ToString(string format, IFormatProvider formatProvider)
        {
            if (format == null)
            {
                return Utils.Format(
                    "{0} - [{1}:{2}:{3}]",
                    m_description.EndpointUrl,
                    m_description.SecurityMode,
                    SecurityPolicies.GetDisplayName(m_description.SecurityPolicyUri),
                    (m_configuration != null && m_configuration.UseBinaryEncoding) ? "Binary" : "XML");
            }

            throw new FormatException(Utils.Format("Invalid format string: '{0}'.", format));
        }

        /// <summary>
        /// Updates the endpoint description.
        /// </summary>
        public void Update(EndpointDescription description)
        {
            if (description == null)
            {
                throw new ArgumentNullException(nameof(description));
            }

            m_description = (EndpointDescription)description.MemberwiseClone();

            // normalize transport profile uri.
            if (m_description.TransportProfileUri != null)
            {
                m_description.TransportProfileUri = Profiles.NormalizeUri(m_description.TransportProfileUri);
            }

            // set the proxy url.
            if (m_collection != null && m_description.EndpointUrl != null)
            {
                if (m_description.EndpointUrl.StartsWith(Utils.UriSchemeOpcTcp, StringComparison.Ordinal))
                {
                    m_description.ProxyUrl = m_collection.TcpProxyUrl;
                }
            }
        }

        /// <summary>
        /// Updates the endpoint configuration.
        /// </summary>
        public void Update(EndpointConfiguration configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            m_configuration = (EndpointConfiguration)configuration.MemberwiseClone();

            BinaryEncodingSupport binaryEncodingSupport = m_description.EncodingSupport;

            // check if the configuration restricts the encoding if the endpoint supports both.
            if (binaryEncodingSupport == BinaryEncodingSupport.Optional)
            {
                binaryEncodingSupport = m_binaryEncodingSupport;
            }

            if (binaryEncodingSupport == BinaryEncodingSupport.None)
            {
                m_configuration.UseBinaryEncoding = false;
            }

            if (binaryEncodingSupport == BinaryEncodingSupport.Required)
            {
                m_configuration.UseBinaryEncoding = true;
            }
        }

        /// <summary>
        /// Updates an endpoint with information from the server's discovery endpoint.
        /// </summary>
        public void UpdateFromServer()
        {
            UpdateFromServer(EndpointUrl, m_description.SecurityMode, m_description.SecurityPolicyUri);
        }

        /// <summary>
        /// Updates an endpoint with information from the server's discovery endpoint.
        /// </summary>
        public void UpdateFromServer(
            Uri endpointUrl,
            MessageSecurityMode securityMode,
            string securityPolicyUri)
        {
            UpdateFromServer(endpointUrl, null, securityMode, securityPolicyUri);
        }

        /// <summary>
        /// Updates an endpoint with information from the server's discovery endpoint.
        /// </summary>
        public void UpdateFromServer(
            Uri endpointUrl,
            ITransportWaitingConnection connection,
            MessageSecurityMode securityMode,
            string securityPolicyUri)
        {
            // get the a discovery url.
            Uri discoveryUrl = GetDiscoveryUrl(endpointUrl);

            // create the discovery client.
            DiscoveryClient client;
            if (connection != null)
            {
                client = DiscoveryClient.Create(connection, m_configuration);
            }
            else
            {
                client = DiscoveryClient.Create(discoveryUrl, m_configuration);
            }

            try
            {
                // get the endpoints.
                EndpointDescriptionCollection collection = client.GetEndpoints(null);

                // find list of matching endpoints.
                EndpointDescriptionCollection matches = MatchEndpoints(
                    collection,
                    endpointUrl,
                    securityMode,
                    securityPolicyUri
                    );

                // select best match
                EndpointDescription match = SelectBestMatch(matches, discoveryUrl);

                // update the endpoint.
                Update(match);
            }
            finally
            {
                client.Close();
            }
        }

        /// <summary>
        /// Returns a discovery url that can be used to update the endpoint description.
        /// </summary>
        public Uri GetDiscoveryUrl(Uri endpointUrl)
        {
            // update the endpoint description.
            if (endpointUrl != null)
            {
                m_description.EndpointUrl = endpointUrl.ToString();
            }
            else
            {
                endpointUrl = Utils.ParseUri(m_description.EndpointUrl);
            }

            // get the know discovery URLs.
            StringCollection discoveryUrls = null;

            if (m_description.Server != null)
            {
                discoveryUrls = m_description.Server.DiscoveryUrls;
            }

            // attempt to construct a discovery url by appending 'discovery' to the endpoint.
            if (discoveryUrls == null || discoveryUrls.Count == 0)
            {
                if (endpointUrl.Scheme != Utils.UriSchemeOpcTcp)
                {
                    return new Uri(string.Format(CultureInfo.InvariantCulture, "{0}/discovery", endpointUrl));
                }
                else
                {
                    return endpointUrl;
                }
            }

            // choose the URL that uses the same protocol if one exists.
            for (int ii = 1; ii < discoveryUrls.Count; ii++)
            {
                if (discoveryUrls[ii].StartsWith(endpointUrl.Scheme, StringComparison.Ordinal))
                {
                    return Utils.ParseUri(discoveryUrls[ii]);
                }
            }

            // return the first in the list.
            return Utils.ParseUri(discoveryUrls[0]);
        }



        /// <summary>
        /// The collection that the endpoint belongs to.
        /// </summary>
        public ConfiguredEndpointCollection Collection
        {
            get => m_collection;

            internal set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                m_collection = value;
            }
        }

        /// <summary>
        /// The URL used to create a sessions.
        /// </summary>
        public Uri EndpointUrl
        {
            get
            {
                if (string.IsNullOrEmpty(m_description.EndpointUrl))
                {
                    return null;
                }

                return Utils.ParseUri(m_description.EndpointUrl);
            }

            set
            {
                if (value == null)
                {
                    m_description.EndpointUrl = null;
                }

                m_description.EndpointUrl = string.Format(CultureInfo.InvariantCulture, "{0}", value);
            }
        }

        /// <summary>
        /// The user identity to use when connecting to the endpoint.
        /// </summary>
        public UserTokenPolicy SelectedUserTokenPolicy
        {
            get
            {
                if (m_description != null && m_description.UserIdentityTokens != null)
                {
                    UserTokenPolicyCollection policies = m_description.UserIdentityTokens;

                    if (m_selectedUserTokenPolicyIndex >= 0 && policies.Count > m_selectedUserTokenPolicyIndex)
                    {
                        return policies[m_selectedUserTokenPolicyIndex];
                    }
                }

                return null;
            }

            set
            {
                if (m_description != null && m_description.UserIdentityTokens != null)
                {
                    UserTokenPolicyCollection policies = m_description.UserIdentityTokens;

                    for (int ii = 0; ii < policies.Count; ii++)
                    {
                        if (Object.ReferenceEquals(policies[ii], value))
                        {
                            m_selectedUserTokenPolicyIndex = ii;
                            break;
                        }
                    }
                }

                m_selectedUserTokenPolicyIndex = -1;
            }
        }



        private EndpointDescriptionCollection MatchEndpoints(
            EndpointDescriptionCollection collection,
            Uri endpointUrl,
            MessageSecurityMode securityMode,
            string securityPolicyUri)
        {
            if (collection == null || collection.Count == 0)
            {
                throw ServiceResultException.Create(
                    StatusCodes.BadUnknownResponse,
                    "Server does not have any endpoints defined.");
            }

            // find list of matching endpoints.
            var matches = new EndpointDescriptionCollection();

            // first pass - match on the requested security parameters.
            foreach (EndpointDescription description in collection)
            {
                // check for match on security policy.
                if (!string.IsNullOrEmpty(securityPolicyUri))
                {
                    if (securityPolicyUri != description.SecurityPolicyUri)
                    {
                        continue;
                    }
                }

                // check for match on security mode.
                if (securityMode != MessageSecurityMode.Invalid)
                {
                    if (securityMode != description.SecurityMode)
                    {
                        continue;
                    }
                }

                // add to list of matches.
                matches.Add(description);
            }

            // no matches (security parameters may have changed).
            if (matches.Count == 0)
            {
                matches = collection;
            }

            // check if list has to be narrowed down further.
            if (matches.Count > 1)
            {
                collection = matches;
                matches = new EndpointDescriptionCollection();

                // second pass - match on the url scheme.
                foreach (EndpointDescription description in collection)
                {
                    // parse the endpoint url.
                    Uri sessionUrl = Utils.ParseUri(description.EndpointUrl);

                    if (sessionUrl == null)
                    {
                        continue;
                    }

                    // check for matching protocol.
                    if (sessionUrl.Scheme != endpointUrl.Scheme)
                    {
                        continue;
                    }

                    matches.Add(description);
                }
            }

            // no matches (protocol may not be supported).
            if (matches.Count == 0)
            {
                matches = collection;
            }

            return matches;
        }

        /// <summary>
        /// Select the best match from a security description.
        /// </summary>
        private EndpointDescription SelectBestMatch(
            EndpointDescriptionCollection matches,
            Uri discoveryUrl
            )
        {
            // choose first in list by default.
            EndpointDescription match = matches[0];

            // check if list has to be narrowed down further.
            if (matches.Count > 1)
            {
                // third pass - match based on security level.
                foreach (EndpointDescription description in matches)
                {
                    if (description.SecurityLevel > match.SecurityLevel)
                    {
                        match = description;
                    }
                }
            }

            // check if the endpoint url matches the endpoint used in the request.
            if (discoveryUrl != null)
            {
                Uri matchUrl = Utils.ParseUri(match.EndpointUrl);
                if (matchUrl == null || !string.Equals(discoveryUrl.DnsSafeHost, matchUrl.DnsSafeHost, StringComparison.OrdinalIgnoreCase))
                {
                    var uri = new UriBuilder(matchUrl) {
                        Host = discoveryUrl.DnsSafeHost,
                        Port = discoveryUrl.Port
                    };
                    match.EndpointUrl = uri.ToString();

                    // need to update the discovery urls.
                    match.Server.DiscoveryUrls.Clear();
                    match.Server.DiscoveryUrls.Add(discoveryUrl.ToString());
                }
            }

            return match;
        }

    }

}
