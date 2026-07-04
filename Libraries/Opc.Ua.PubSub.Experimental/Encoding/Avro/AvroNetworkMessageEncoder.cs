using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Core.Experimental;
using Opc.Ua.PubSub.Encoding;

namespace Opc.Ua.PubSub.Experimental;

public sealed class AvroNetworkMessageEncoder : INetworkMessageEncoder
{
    private const string Magic = "OPC-UA-PubSub-Avro";
    private const ushort Version = 1;

    public string TransportProfileUri => AvroNetworkMessage.PubSubMqttAvroTransport;

    public int EstimatedHeaderOverhead => 128;

    public async ValueTask<ReadOnlyMemory<byte>> EncodeAsync(
        PubSubNetworkMessage networkMessage,
        PubSubNetworkMessageContext context,
        CancellationToken cancellationToken = default)
    {
        if (networkMessage is null)
        {
            throw new ArgumentNullException(nameof(networkMessage));
        }
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }
        cancellationToken.ThrowIfCancellationRequested();

        if (networkMessage is not AvroNetworkMessage message)
        {
            throw new ArgumentException(
                "Network message type is not supported by the Avro encoder.",
                nameof(networkMessage));
        }

        using MemoryStream stream = new();
        using AvroEncoder encoder = new(stream, context.MessageContext, leaveOpen: true);
        encoder.WriteString(null, Magic);
        encoder.WriteUInt16(null, Version);
        WritePublisherId(encoder, message.PublisherId);
        WriteNullableUInt16(encoder, message.WriterGroupId);
        encoder.WriteGuid(null, message.DataSetClassId);
        encoder.WriteString(null, string.IsNullOrEmpty(message.SchemaId) ? null : message.SchemaId);
        encoder.WriteInt32(null, message.DataSetMessages.Count);

        for (int i = 0; i < message.DataSetMessages.Count; i++)
        {
            if (message.DataSetMessages[i] is not AvroDataSetMessage dataSetMessage)
            {
                throw new ArgumentException(
                    "DataSetMessage entries must be AvroDataSetMessage instances.",
                    nameof(networkMessage));
            }
            WriteDataSetMessage(encoder, message, dataSetMessage, context);
        }
        encoder.Close();
        await Task.CompletedTask.ConfigureAwait(false);
        return stream.ToArray();
    }

    private static void WriteDataSetMessage(
        AvroEncoder encoder,
        AvroNetworkMessage envelope,
        AvroDataSetMessage message,
        PubSubNetworkMessageContext context)
    {
        encoder.WriteUInt16(null, message.DataSetWriterId);
        encoder.WriteEnumerated(null, message.MessageType);
        encoder.WriteUInt32(null, message.MetaDataVersion.MajorVersion);
        encoder.WriteUInt32(null, message.MetaDataVersion.MinorVersion);
        encoder.WriteUInt32(null, message.SequenceNumber);
        encoder.WriteStatusCode(null, message.Status);
        encoder.WriteDateTime(null, message.Timestamp);
        encoder.WriteInt64(null, (long)(uint)message.FieldContentMask);

        if (message.MessageType == PubSubDataSetMessageType.KeepAlive)
        {
            encoder.WriteInt32(null, 0);
            return;
        }

        DataSetMetaDataType? metaData = ExperimentalMessageEncoding.ResolveMetaData(
            envelope,
            message,
            context,
            envelope.DataSetClassId);
        encoder.WriteInt32(null, message.Fields.Count);
        for (int i = 0; i < message.Fields.Count; i++)
        {
            DataSetField field = message.Fields[i];
            string fieldName = ExperimentalMessageEncoding.ResolveFieldName(field, metaData, i);
            PubSubFieldEncoding fieldEncoding = SelectFieldEncoding(field, message.FieldContentMask);
            encoder.WriteString(null, fieldName);
            encoder.WriteInt32(null, field.FieldIndex >= 0 ? field.FieldIndex : i);
            encoder.WriteEnumerated(null, fieldEncoding);
            WriteFieldValue(encoder, field, fieldEncoding, message.FieldContentMask, metaData, fieldName, i);
        }
    }

    private static PubSubFieldEncoding SelectFieldEncoding(
        DataSetField field,
        DataSetFieldContentMask fieldContentMask)
    {
        if (field.Encoding == PubSubFieldEncoding.DataValue
            || HasDataValueMembers(fieldContentMask))
        {
            return PubSubFieldEncoding.DataValue;
        }
        return field.Encoding == PubSubFieldEncoding.RawData
            ? PubSubFieldEncoding.RawData
            : PubSubFieldEncoding.Variant;
    }

    private static bool HasDataValueMembers(DataSetFieldContentMask mask)
    {
        const DataSetFieldContentMask dataValueBits = DataSetFieldContentMask.StatusCode
            | DataSetFieldContentMask.SourceTimestamp
            | DataSetFieldContentMask.SourcePicoSeconds
            | DataSetFieldContentMask.ServerTimestamp
            | DataSetFieldContentMask.ServerPicoSeconds;
        return (mask & dataValueBits) != 0;
    }

    private static void WriteFieldValue(
        AvroEncoder encoder,
        DataSetField field,
        PubSubFieldEncoding fieldEncoding,
        DataSetFieldContentMask fieldContentMask,
        DataSetMetaDataType? metaData,
        string fieldName,
        int index)
    {
        using MemoryStream stream = new();
        using AvroEncoder valueEncoder = new(stream, encoder.Context, leaveOpen: true);
        switch (fieldEncoding)
        {
            case PubSubFieldEncoding.RawData:
                TypeInfo? typeInfo = ExperimentalMessageEncoding.ResolveFieldType(metaData, fieldName, index);
                if (typeInfo is null)
                {
                    throw new ArgumentException(
                        $"RawData Avro field '{fieldName}' requires DataSetMetaData.");
                }
                valueEncoder.WriteVariantValue(null, field.Value);
                break;
            case PubSubFieldEncoding.DataValue:
                valueEncoder.WriteDataValue(
                    null,
                    ExperimentalMessageEncoding.BuildDataValue(field, fieldContentMask));
                break;
            case PubSubFieldEncoding.Variant:
            default:
                valueEncoder.WriteVariant(null, field.Value);
                break;
        }
        valueEncoder.Close();
        encoder.WriteByteString(null, ByteString.From(stream.ToArray()));
    }

    private static void WriteNullableUInt16(AvroEncoder encoder, ushort? value)
    {
        encoder.WriteBoolean(null, value.HasValue);
        if (value.HasValue)
        {
            encoder.WriteUInt16(null, value.Value);
        }
    }

    private static void WritePublisherId(AvroEncoder encoder, PublisherId publisherId)
    {
        encoder.WriteEnumerated(null, publisherId.Type);
        switch (publisherId.Type)
        {
            case PublisherIdType.Byte:
                publisherId.TryGetByte(out byte b);
                encoder.WriteByte(null, b);
                break;
            case PublisherIdType.UInt16:
                publisherId.TryGetUInt16(out ushort u16);
                encoder.WriteUInt16(null, u16);
                break;
            case PublisherIdType.UInt32:
                publisherId.TryGetUInt32(out uint u32);
                encoder.WriteUInt32(null, u32);
                break;
            case PublisherIdType.UInt64:
                publisherId.TryGetUInt64(out ulong u64);
                encoder.WriteUInt64(null, u64);
                break;
            case PublisherIdType.String:
                publisherId.TryGetString(out string? s);
                encoder.WriteString(null, s ?? string.Empty);
                break;
            case PublisherIdType.Guid:
                publisherId.TryGetGuid(out Guid g);
                encoder.WriteGuid(null, new Uuid(g));
                break;
        }
    }
}
