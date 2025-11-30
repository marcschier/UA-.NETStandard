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
    public static class EndpointDescriptionExtensions
    {
        extension(EndpointDescription endpointDescription)
        {
            /// <summary>
            /// The encodings supported by the configuration.
            /// </summary>
            public BinaryEncodingSupport EncodingSupport
            {
                get
                {
                    if (!string.IsNullOrEmpty(endpointDescription.EndpointUrl) &&
                        endpointDescription.EndpointUrl.StartsWith(
                            Utils.UriSchemeOpcTcp,
                            StringComparison.Ordinal))
                    {
                        return BinaryEncodingSupport.Required;
                    }

                    endpointDescription.TransportProfileUri =
                        Profiles.NormalizeUri(endpointDescription.TransportProfileUri);
                    return endpointDescription.TransportProfileUri == Profiles.HttpsBinaryTransport ?
                        BinaryEncodingSupport.Required : BinaryEncodingSupport.None;
                }
            }

            /// <summary>
            /// Finds the user token policy with the specified id and securtyPolicyUri
            /// </summary>
            public UserTokenPolicy FindUserTokenPolicy(string policyId, string tokenSecurityPolicyUri)
            {
                UserTokenPolicy sameEncryptionAlgorithm = null;
                UserTokenPolicy unspecifiedSecPolicy = null;
                // The specified security policies take precedence
                foreach (UserTokenPolicy policy in endpointDescription.UserIdentityTokens)
                {
                    if (policy.PolicyId == policyId)
                    {
                        if (policy.SecurityPolicyUri == tokenSecurityPolicyUri)
                        {
                            return policy;
                        }
                        else if ((
                                policy.SecurityPolicyUri != null &&
                                tokenSecurityPolicyUri != null &&
                                EccUtils.IsEccPolicy(policy.SecurityPolicyUri) &&
                                EccUtils.IsEccPolicy(tokenSecurityPolicyUri)
                            ) ||
                            (
                                !EccUtils.IsEccPolicy(policy.SecurityPolicyUri) &&
                                !EccUtils.IsEccPolicy(tokenSecurityPolicyUri)))
                        {
                            sameEncryptionAlgorithm ??= policy;
                        }
                        else if (policy.SecurityPolicyUri == null)
                        {
                            unspecifiedSecPolicy = policy;
                        }
                    }
                }
                // The first token with the same encryption algorithm (RSA/ECC) follows
                if (sameEncryptionAlgorithm != null)
                {
                    return sameEncryptionAlgorithm;
                }
                // The first token with unspecified security policy follows / no policy
                return unspecifiedSecPolicy;
            }

            /// <summary>
            /// Finds a token policy that matches the user identity specified.
            /// </summary>
            public UserTokenPolicy FindUserTokenPolicy(
                UserTokenType tokenType,
                XmlQualifiedName issuedTokenType,
                string tokenSecurityPolicyUri)
            {
                if (issuedTokenType == null)
                {
                    return endpointDescription.FindUserTokenPolicy(
                        tokenType,
                        (string)null,
                        tokenSecurityPolicyUri);
                }

                return endpointDescription.FindUserTokenPolicy(
                    tokenType,
                    issuedTokenType.Namespace,
                    tokenSecurityPolicyUri);
            }

            /// <summary>
            /// Finds a token policy that matches the user identity specified.
            /// </summary>
            public UserTokenPolicy FindUserTokenPolicy(
                UserTokenType tokenType,
                string issuedTokenType,
                string tokenSecurityPolicyUri)
            {
                // construct issuer type.
                string issuedTokenTypeText = issuedTokenType;

                UserTokenPolicy sameEncryptionAlgorithm = null;
                UserTokenPolicy unspecifiedSecPolicy = null;
                // The specified security policies take precedence
                foreach (UserTokenPolicy policy in endpointDescription.UserIdentityTokens)
                {
                    if ((policy.TokenType == tokenType) &&
                        (issuedTokenTypeText == policy.IssuedTokenType))
                    {
                        if ((policy.SecurityPolicyUri == tokenSecurityPolicyUri) ||
                            (tokenType == UserTokenType.Anonymous))
                        {
                            return policy;
                        }
                        else if ((
                                policy.SecurityPolicyUri != null &&
                                tokenSecurityPolicyUri != null &&
                                EccUtils.IsEccPolicy(policy.SecurityPolicyUri) &&
                                EccUtils.IsEccPolicy(tokenSecurityPolicyUri)
                            ) ||
                            (
                                !EccUtils.IsEccPolicy(policy.SecurityPolicyUri) &&
                                !EccUtils.IsEccPolicy(tokenSecurityPolicyUri)))
                        {
                            sameEncryptionAlgorithm ??= policy;
                        }
                        else if (policy.SecurityPolicyUri == null)
                        {
                            if (sameEncryptionAlgorithm == null)
                            {
                                unspecifiedSecPolicy = policy;
                            }
                        }
                    }
                }
                // The first token with the same encryption algorithm (RSA/ECC) follows
                if (sameEncryptionAlgorithm != null)
                {
                    return sameEncryptionAlgorithm;
                }
                // The first token with unspecified security policy follows / no policy
                return unspecifiedSecPolicy;
            }
        }
    }
}
