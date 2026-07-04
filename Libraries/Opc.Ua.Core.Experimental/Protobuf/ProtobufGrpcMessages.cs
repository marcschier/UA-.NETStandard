namespace Opc.Ua.Core.Experimental
{
    public sealed class GrpcReadRequestMessage
    {
        public RequestHeader? RequestHeader { get; set; }
        public double MaxAge { get; set; }
        public uint TimestampsToReturn { get; set; }
        public ArrayOf<GrpcReadValueId> NodesToRead { get; set; }
    }

    public sealed class GrpcReadResponseMessage
    {
        public ResponseHeader? ResponseHeader { get; set; }
        public ArrayOf<DataValue> Results { get; set; }
        public ArrayOf<DiagnosticInfo?> DiagnosticInfos { get; set; }
    }

    public sealed class GrpcReadValueId
    {
        public NodeId NodeId { get; set; }
        public uint AttributeId { get; set; }
        public string? IndexRange { get; set; }
    }

    public sealed class GrpcOpcUaStatusDetail
    {
        public StatusCode StatusCode { get; set; }
        public string? SymbolicId { get; set; }
        public DiagnosticInfo? DiagnosticInfo { get; set; }
    }
}
