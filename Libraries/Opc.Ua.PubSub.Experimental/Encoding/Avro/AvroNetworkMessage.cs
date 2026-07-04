using Opc.Ua.PubSub.Encoding;

namespace Opc.Ua.PubSub.Experimental;

public sealed record AvroNetworkMessage : PubSubNetworkMessage
{
    public const string PubSubMqttAvroTransport = "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-avro";

    public Uuid DataSetClassId { get; init; }

    public string SchemaId { get; init; } = string.Empty;

    public override string TransportProfileUri => PubSubMqttAvroTransport;
}
