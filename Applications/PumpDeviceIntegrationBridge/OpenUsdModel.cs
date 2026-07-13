/* ========================================================================
 * Copyright (c) 2005-2025 The OPC Foundation, Inc. All rights reserved.
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

namespace PumpDeviceIntegrationBridge
{
    /// <summary>
    /// The small slice of the OPC UA - OpenUSD Bindings companion model the client
    /// needs. A connector is a client: it does not need the server-side generated
    /// NodeState model, only the namespace URI, the well-known type NodeIds, and the
    /// meaning of the <c>RenderTargetKind</c> enumeration (values mirror
    /// <c>Opc.Ua.OpenUsdBinding.NodeSet2.xml</c>, DataType i=3002).
    /// </summary>
    internal static class OpenUsdModel
    {
        public const string NamespaceUri = "http://opcfoundation.org/UA/OpenUSD/";
        public const uint RepresentationTypeId = 1003;
        public const uint LiveBindingTypeId = 1004;
    }

    /// <summary>How a bound value drives the target USD attribute (NodeSet i=3002).</summary>
    public enum OpenUsdRenderTargetKind
    {
        Translation = 0,
        Rotation = 1,
        Scale = 2,
        Transform = 3,
        Visibility = 4,
        DisplayColor = 5,
        EmissiveColor = 6,
        Opacity = 7,
        Custom = 8
    }
}
