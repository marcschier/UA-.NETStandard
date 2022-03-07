using System.Collections.Generic;
using System.Runtime.Serialization;

// suppress warnings until OAuth 2.0 is supported
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace Opc.Ua
{
    [DataContract(Namespace = Namespaces.OpcUaConfig)]
    public class OAuth2ServerSettings
    {
        [DataMember(Order = 1)]
        public string ApplicationUri { get; set; }

        [DataMember(Order = 2)]
        public string ResourceId { get; set; }

        [DataMember(Order = 3)]
        public StringCollection Scopes { get; set; }
    }

    [CollectionDataContract(Name = "ListOfOAuth2ServerSettings", Namespace = Namespaces.OpcUaConfig, ItemName = "OAuth2ServerSettings")]
    public partial class OAuth2ServerSettingsCollection : List<OAuth2ServerSettings>
    {
    }

    [DataContract(Namespace = Namespaces.OpcUaConfig)]
    public class OAuth2Credential
    {

        /// <summary>
        /// The default constructor.
        /// </summary>
        public OAuth2Credential()
        {
            Initialize();
        }

        /// <summary>
        /// Initializes the object during deserialization.
        /// </summary>
        [OnDeserializing()]
        private void Initialize(StreamingContext context)
        {
            Initialize();
        }

        /// <summary>
        /// Sets private members to default values.
        /// </summary>
        private void Initialize()
        {
        }



        [DataMember(Order = 1)]
        public string AuthorityUrl { get; set; }

        [DataMember(Order = 2)]
        public string GrantType { get; set; }

        [DataMember(Order = 3)]
        public string ClientId { get; set; }

        [DataMember(Order = 4)]
        public string ClientSecret { get; set; }

        [DataMember(Order = 5)]
        public string RedirectUrl { get; set; }

        [DataMember(Order = 6)]
        public string TokenEndpoint { get; set; }

        [DataMember(Order = 7)]
        public string AuthorizationEndpoint { get; set; }

        [DataMember(Order = 8)]
        public OAuth2ServerSettingsCollection Servers { get; set; }


        public OAuth2ServerSettings SelectedServer { get; set; }
    }

    [CollectionDataContract(Name = "ListOfOAuth2Credential", Namespace = Namespaces.OpcUaConfig, ItemName = "OAuth2Credential")]
    public partial class OAuth2CredentialCollection : List<OAuth2Credential>
    {
    }
}
