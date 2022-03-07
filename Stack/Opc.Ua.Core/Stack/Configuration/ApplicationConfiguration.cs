/* Copyright (c) 1996-2021 The OPC Foundation. All rights reserved.
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
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Opc.Ua
{

    /// <summary>
    /// Represents the location of a configuration file.
    /// </summary>
    [DataContract(Namespace = Namespaces.OpcUaConfig)]
    public class ConfigurationLocation
    {

        /// <summary>
        /// Gets or sets the relative or absolute path to the configuration file.
        /// </summary>
        /// <value>The file path.</value>
        [DataMember(IsRequired = true, Order = 0)]
        public string FilePath
        {
            get => m_filePath;
            set => m_filePath = value;
        }



        private string m_filePath;

    }

    /// <summary>
    /// Stores the configurable configuration information for a UA application.
    /// </summary>
    public partial class ApplicationConfiguration
    {

        /// <summary>
        /// Gets the file that was used to load the configuration.
        /// </summary>
        /// <value>The source file path.</value>
        public string SourceFilePath => m_sourceFilePath;

        /// <summary>
        /// Gets or sets the certificate validator which is configured to use.
        /// </summary>
        public CertificateValidator CertificateValidator
        {
            get => m_certificateValidator;
            set => m_certificateValidator = value;
        }

        /// <summary>
        /// Returns the domain names which the server is configured to use.
        /// </summary>
        /// <returns>A list of domain names.</returns>
        public IList<string> GetServerDomainNames()
        {
            var baseAddresses = new StringCollection();

            if (ServerConfiguration != null)
            {
                if (ServerConfiguration.BaseAddresses != null)
                {
                    baseAddresses.AddRange(ServerConfiguration.BaseAddresses);
                }

                if (ServerConfiguration.AlternateBaseAddresses != null)
                {
                    baseAddresses.AddRange(ServerConfiguration.AlternateBaseAddresses);
                }
            }

            if (DiscoveryServerConfiguration != null)
            {
                if (DiscoveryServerConfiguration.BaseAddresses != null)
                {
                    baseAddresses.AddRange(DiscoveryServerConfiguration.BaseAddresses);
                }

                if (DiscoveryServerConfiguration.AlternateBaseAddresses != null)
                {
                    baseAddresses.AddRange(DiscoveryServerConfiguration.AlternateBaseAddresses);
                }
            }

            var domainNames = new List<string>();
            for (int ii = 0; ii < baseAddresses.Count; ii++)
            {
                Uri url = Utils.ParseUri(baseAddresses[ii]);

                if (url == null)
                {
                    continue;
                }

                string domainName = url.DnsSafeHost;

                if (url.HostNameType == UriHostNameType.Dns)
                {
                    domainName = Utils.ReplaceLocalhost(domainName);
                }
                else // IPv4/IPv6 address
                {
                    domainName = Utils.NormalizedIPAddress(domainName);
                }

                if (!Utils.FindStringIgnoreCase(domainNames, domainName))
                {
                    domainNames.Add(domainName);
                }
            }

            return domainNames;
        }

        /// <summary>
        /// Creates the message context from the configuration.
        /// </summary>
        /// <returns>A new instance of a ServiceMessageContext object.</returns>
        public ServiceMessageContext CreateMessageContext(bool clonedFactory = false)
        {
            var messageContext = new ServiceMessageContext();

            if (m_transportQuotas != null)
            {
                messageContext.MaxArrayLength = m_transportQuotas.MaxArrayLength;
                messageContext.MaxByteStringLength = m_transportQuotas.MaxByteStringLength;
                messageContext.MaxStringLength = m_transportQuotas.MaxStringLength;
                messageContext.MaxMessageSize = m_transportQuotas.MaxMessageSize;
            }

            messageContext.NamespaceUris = new NamespaceTable();
            messageContext.ServerUris = new StringTable();
            if (clonedFactory)
            {
                messageContext.Factory = new EncodeableFactory(EncodeableFactory.GlobalFactory);
            }
            return messageContext;
        }

        /// <summary>
        /// Creates the message context from the configuration.
        /// </summary>
        /// <value>A new instance of a ServiceMessageContext object.</value>
        [Obsolete("Warning: Behavior changed return a copy instead of a reference. Should call CreateMessageContext() instead.")]
        public IServiceMessageContext MessageContext
        {
            get
            {
                if (m_messageContext == null)
                {
                    m_messageContext = CreateMessageContext();
                }

                return m_messageContext;
            }
        }

        /// <summary>
        /// Loads and validates the application configuration from a configuration section.
        /// </summary>
        /// <param name="file">The file.</param>
        /// <param name="applicationType">Type of the application.</param>
        /// <param name="systemType">Type of the system.</param>
        /// <returns>Application configuration</returns>
        public static Task<ApplicationConfiguration> Load(FileInfo file, ApplicationType applicationType, Type systemType)
        {
            return ApplicationConfiguration.Load(file, applicationType, systemType, true);
        }

        /// <summary>
        /// Loads and validates the application configuration from a configuration section.
        /// </summary>
        /// <param name="file">The file.</param>
        /// <param name="applicationType">Type of the application.</param>
        /// <param name="systemType">Type of the system.</param>
        /// <param name="applyTraceSettings">if set to <c>true</c> apply trace settings after validation.</param>
        /// <param name="certificatePasswordProvider">The certificate password provider.</param>
        /// <returns>Application configuration</returns>
        public static async Task<ApplicationConfiguration> Load(
            FileInfo file,
            ApplicationType applicationType,
            Type systemType,
            bool applyTraceSettings,
            ICertificatePasswordProvider certificatePasswordProvider = null)
        {
            ApplicationConfiguration configuration = null;

            try
            {
                using (var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read))
                {
                    configuration = await Load(stream, applicationType, systemType, applyTraceSettings, certificatePasswordProvider).ConfigureAwait(false);
                }
            }
            catch (Exception e)
            {
                var message = new StringBuilder();
                message.AppendFormat("Configuration file could not be loaded: {0}", file.FullName);
                message.AppendLine();
                message.Append(e.Message);
                throw ServiceResultException.Create(
                    StatusCodes.BadConfigurationError, e, message.ToString());
            }

            if (configuration != null)
            {
                configuration.m_sourceFilePath = file.FullName;
            }

            return configuration;
        }

        /// <summary>
        /// Loads and validates the application configuration from a configuration section.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="applicationType">Type of the application.</param>
        /// <param name="systemType">Type of the system.</param>
        /// <param name="applyTraceSettings">if set to <c>true</c> apply trace settings after validation.</param>
        /// <param name="certificatePasswordProvider">The certificate password provider.</param>
        /// <returns>Application configuration</returns>
        public static async Task<ApplicationConfiguration> Load(
            Stream stream,
            ApplicationType applicationType,
            Type systemType,
            bool applyTraceSettings,
            ICertificatePasswordProvider certificatePasswordProvider = null)
        {
            ApplicationConfiguration configuration = null;
            systemType = systemType ?? typeof(ApplicationConfiguration);

            try
            {
                var serializer = new DataContractSerializer(systemType);
                configuration = (ApplicationConfiguration)serializer.ReadObject(stream);
            }
            catch (Exception e)
            {
                var message = new StringBuilder();
                message.AppendFormat("Configuration could not be loaded.");
                message.AppendLine();
                message.AppendFormat("Error is: {0}", e.Message);
                throw ServiceResultException.Create(
                    StatusCodes.BadConfigurationError, e, message.ToString());
            }

            if (configuration != null)
            {
                // should not be here but need to preserve old behavior.
                if (applyTraceSettings && configuration.TraceConfiguration != null)
                {
                    configuration.TraceConfiguration.ApplySettings();
                }

                configuration.SecurityConfiguration.CertificatePasswordProvider = certificatePasswordProvider;

                await configuration.Validate(applicationType).ConfigureAwait(false);
            }

            return configuration;
        }

        /// <summary>
        /// Reads the file path from the application configuration file.
        /// </summary>
	    /// <param name="sectionName">Name of configuration section for the current application's default configuration containing <see cref="ConfigurationLocation"/>.
	    /// </param>
        /// <returns>File path from the application configuration file.</returns>
        public static string GetFilePathFromAppConfig(string sectionName)
        {
            // convert to absolute file path (expands environment strings).
            string absolutePath = Utils.GetAbsoluteFilePath(sectionName + ".Config.xml", true, false, false);
            return (absolutePath != null) ? absolutePath : sectionName + ".Config.xml";
        }

        /// <summary>
        /// Ensures that the application configuration is valid.
        /// </summary>
        /// <param name="applicationType">Type of the application.</param>
        public virtual async Task Validate(ApplicationType applicationType)
        {
            if (string.IsNullOrEmpty(ApplicationName))
            {
                throw ServiceResultException.Create(StatusCodes.BadConfigurationError, "ApplicationName must be specified.");
            }

            if (SecurityConfiguration == null)
            {
                throw ServiceResultException.Create(StatusCodes.BadConfigurationError, "SecurityConfiguration must be specified.");
            }

            SecurityConfiguration.Validate();

            // load private key
            await SecurityConfiguration.ApplicationCertificate.LoadPrivateKeyEx(SecurityConfiguration.CertificatePasswordProvider).ConfigureAwait(false);

            Func<string> generateDefaultUri = () => {
                var sb = new StringBuilder();
                sb.Append("urn:");
                sb.Append(Utils.GetHostName());
                sb.Append(':');
                sb.Append(ApplicationName);
                return sb.ToString();
            };

            if (string.IsNullOrEmpty(ApplicationUri))
            {
                m_applicationUri = generateDefaultUri();
            }

            if (applicationType == ApplicationType.Client || applicationType == ApplicationType.ClientAndServer)
            {
                if (ClientConfiguration == null)
                {
                    throw ServiceResultException.Create(StatusCodes.BadConfigurationError, "ClientConfiguration must be specified.");
                }

                ClientConfiguration.Validate();
            }

            if (applicationType == ApplicationType.Server || applicationType == ApplicationType.ClientAndServer)
            {
                if (ServerConfiguration == null)
                {
                    throw ServiceResultException.Create(StatusCodes.BadConfigurationError, "ServerConfiguration must be specified.");
                }

                ServerConfiguration.Validate();
            }

            if (applicationType == ApplicationType.DiscoveryServer)
            {
                if (DiscoveryServerConfiguration == null)
                {
                    throw ServiceResultException.Create(StatusCodes.BadConfigurationError, "DiscoveryServerConfiguration must be specified.");
                }

                DiscoveryServerConfiguration.Validate();
            }

            // toggle the state of the hi-res clock.
            HiResClock.Disabled = m_disableHiResClock;

            if (HiResClock.Disabled)
            {
                if (m_serverConfiguration != null)
                {
                    if (m_serverConfiguration.PublishingResolution < 50)
                    {
                        m_serverConfiguration.PublishingResolution = 50;
                    }
                }
            }

            await m_certificateValidator.Update(SecurityConfiguration).ConfigureAwait(false);
        }

        /// <summary>
        /// Looks for an extension with the specified type and uses the DataContractSerializer to parse it.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <returns>
        /// The deserialized extension. Null if an error occurs.
        /// </returns>
        /// <remarks>
        /// The containing element must use the name and namespace uri specified by the DataContractAttribute for the type.
        /// </remarks>
        public T ParseExtension<T>()
        {
            return ParseExtension<T>(null);
        }

        /// <summary>
        /// Looks for an extension with the specified type and uses the DataContractSerializer to parse it.
        /// </summary>
        /// <typeparam name="T">The type of extension.</typeparam>
        /// <param name="elementName">Name of the element (null means use type name).</param>
        /// <returns>The extension if found. Null otherwise.</returns>
        public T ParseExtension<T>(XmlQualifiedName elementName)
        {
            return Utils.ParseExtension<T>(m_extensions, elementName);
        }

    }


    /// <summary>
    /// Specifies parameters used for tracing.
    /// </summary>
    public partial class TraceConfiguration
    {

        /// <summary>
        /// Applies the trace settings to the current process.
        /// </summary>
        public void ApplySettings()
        {
            Utils.SetTraceLog(m_outputFilePath, m_deleteOnLoad);
            Utils.SetTraceMask(m_traceMasks);

            if (m_traceMasks == 0)
            {
                Utils.SetTraceOutput(Utils.TraceOutput.Off);
            }
            else
            {
                Utils.SetTraceOutput(Utils.TraceOutput.DebugAndFile);
            }
        }

    }



    /// <summary>
    /// Specifies the configuration for a server application.
    /// </summary>
    public partial class ServerBaseConfiguration
    {

        /// <summary>
        /// Validates the configuration.
        /// </summary>
        public virtual void Validate()
        {
            if (m_securityPolicies.Count == 0)
            {
                m_securityPolicies.Add(new ServerSecurityPolicy());
            }
        }

    }



    /// <summary>
    /// Specifies the configuration for a server application.
    /// </summary>
    public partial class ServerConfiguration : ServerBaseConfiguration
    {

        /// <summary>
        /// Validates the configuration.
        /// </summary>
        public override void Validate()
        {
            base.Validate();

            if (m_userTokenPolicies.Count == 0)
            {
                m_userTokenPolicies.Add(new UserTokenPolicy());
            }
        }

    }



    /// <summary>
    /// The configuration for a client application.
    /// </summary>
    public partial class ClientConfiguration
    {

        /// <summary>
        /// Validates the configuration.
        /// </summary>
        public void Validate()
        {
            if (WellKnownDiscoveryUrls.Count == 0)
            {
                WellKnownDiscoveryUrls.AddRange(Utils.DiscoveryUrls);
            }
        }

    }

}
