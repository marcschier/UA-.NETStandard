using Opc.Ua.PubSub.Encoding;

namespace Opc.Ua.PubSub.Experimental;

public sealed record AvroDataSetMessage : PubSubDataSetMessage
{
    public DataSetFieldContentMask FieldContentMask { get; init; }
        = DataSetFieldContentMask.None;
}
