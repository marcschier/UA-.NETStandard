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

namespace Opc.Ua
{
    /// <summary>
    /// Describes how to connect to an endpoint.
    /// </summary>
    public partial class EndpointConfiguration
    {
        /// <summary>
        /// The maximum nesting level accepted while encoding or decoding objects.
        /// </summary>
        public int MaxEncodingNestingLevels
        {
            get =>
                m_maxEncodingNestingLevels <= 0
                    ? DefaultEncodingLimits.MaxEncodingNestingLevels
                    : m_maxEncodingNestingLevels;
            set => m_maxEncodingNestingLevels = value;
        }

        /// <summary>
        /// The number of times the decoder can recover from an error
        /// caused by an encoded ExtensionObject before throwing a decoder error.
        /// </summary>
        public int MaxDecoderRecoveries { get; set; }

        private int m_maxEncodingNestingLevels;
    }
}
