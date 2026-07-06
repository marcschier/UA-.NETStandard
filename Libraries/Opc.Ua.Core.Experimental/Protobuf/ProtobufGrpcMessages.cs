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

namespace Opc.Ua.Core.Experimental
{
    /// <summary>
    /// Carries the fields of an OPC UA Read request for the experimental gRPC mapping.
    /// </summary>
    public sealed class GrpcReadRequestMessage
    {
        /// <summary>
        /// Gets or sets the OPC UA request header carried by the gRPC Read request.
        /// </summary>
        public RequestHeader? RequestHeader { get; set; }

        /// <summary>
        /// Gets or sets the maximum age, in milliseconds, accepted for returned values.
        /// </summary>
        public double MaxAge { get; set; }

        /// <summary>
        /// Gets or sets the timestamp selection encoded for the Read request.
        /// </summary>
        public uint TimestampsToReturn { get; set; }

        /// <summary>
        /// Gets or sets the nodes and attributes requested by the gRPC Read call.
        /// </summary>
        public ArrayOf<GrpcReadValueId> NodesToRead { get; set; }
    }

    /// <summary>
    /// Carries the fields of an OPC UA Read response for the experimental gRPC mapping.
    /// </summary>
    public sealed class GrpcReadResponseMessage
    {
        /// <summary>
        /// Gets or sets the OPC UA response header carried by the gRPC Read response.
        /// </summary>
        public ResponseHeader? ResponseHeader { get; set; }

        /// <summary>
        /// Gets or sets the data values returned for the requested nodes.
        /// </summary>
        public ArrayOf<DataValue> Results { get; set; }

        /// <summary>
        /// Gets or sets per-operation diagnostics returned by the Read service.
        /// </summary>
        public ArrayOf<DiagnosticInfo?> DiagnosticInfos { get; set; }
    }

    /// <summary>
    /// Identifies one node, attribute, and optional index range requested by the experimental gRPC Read message.
    /// </summary>
    public sealed class GrpcReadValueId
    {
        /// <summary>
        /// Creates an Arrow struct slot for an OPC UA NodeId.
        /// </summary>
        public NodeId NodeId { get; set; }

        /// <summary>
        /// Gets or sets the OPC UA attribute id requested for the node.
        /// </summary>
        public uint AttributeId { get; set; }

        /// <summary>
        /// Gets or sets the optional numeric range used to read an array slice.
        /// </summary>
        public string? IndexRange { get; set; }
    }

    /// <summary>
    /// Carries OPC UA status details for the experimental gRPC status mapping.
    /// </summary>
    public sealed class GrpcOpcUaStatusDetail
    {
        /// <summary>
        /// Gets or sets the OPC UA status code represented in the gRPC status detail.
        /// </summary>
        public StatusCode StatusCode { get; set; }

        /// <summary>
        /// Gets or sets the symbolic status identifier represented in the gRPC status detail.
        /// </summary>
        public string? SymbolicId { get; set; }

        /// <summary>
        /// Gets or sets the OPC UA diagnostic information represented in the gRPC status detail.
        /// </summary>
        public DiagnosticInfo? DiagnosticInfo { get; set; }
    }
}
