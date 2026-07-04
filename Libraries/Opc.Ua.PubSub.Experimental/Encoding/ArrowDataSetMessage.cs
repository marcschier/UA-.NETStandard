using Opc.Ua.PubSub.Encoding;

namespace Opc.Ua.PubSub.Experimental;

/// <summary>
/// PubSub DataSetMessage row in an Arrow IPC RecordBatch. The first
/// adapter version supports RawData field columns for the built-in
/// scalar and one-dimensional array types listed by the Part 14 Arrow
/// draft; unsupported field built-in types fail with NotSupportedException.
/// </summary>
public sealed record ArrowDataSetMessage : PubSubDataSetMessage
{
    public DataSetFieldContentMask FieldContentMask { get; init; }
        = DataSetFieldContentMask.RawData;
}
