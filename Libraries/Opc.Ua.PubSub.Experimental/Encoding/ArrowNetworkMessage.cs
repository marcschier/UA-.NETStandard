using Opc.Ua.PubSub.Encoding;

namespace Opc.Ua.PubSub.Experimental;

/// <summary>
/// Apache Arrow IPC-stream PubSub NetworkMessage. The stream schema
/// describes one DataSet; each RecordBatch row is one DataSetMessage
/// sample and each DataSet field is a typed Arrow column.
/// </summary>
public sealed record ArrowNetworkMessage : PubSubNetworkMessage
{
    public const string PubSubMqttArrowTransport = "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-arrow";

    public Uuid DataSetClassId { get; init; }

    public string SchemaId { get; init; } = string.Empty;

    public override string TransportProfileUri => PubSubMqttArrowTransport;
}
