#pragma warning disable CA1861, CS0618
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Apache.Arrow;
using Apache.Arrow.Ipc;
using Apache.Arrow.Types;
using NUnit.Framework;
using Opc.Ua.PubSub.Diagnostics;
using Opc.Ua.PubSub.Encoding;
using Opc.Ua.PubSub.MetaData;

namespace Opc.Ua.PubSub.Experimental.Tests;

[TestFixture]
public sealed class ArrowPubSubRoundTripTests
{
    [Test]
    public async Task EncoderProducesTypedColumnarBatchAndDecoderRoundTripsRows()
    {
        PublisherId publisherId = PublisherId.FromString("publisher-arrow");
        Uuid dataSetClassId = new(new Guid("95669f76-285a-41c6-ac2b-27793a3eac10"));
        DataSetMetaDataType metaData = CreateMetaData();
        PubSubNetworkMessageContext context = CreateContext(
            publisherId,
            writerGroupId: 9,
            dataSetClassId,
            metaData,
            dataSetWriterId: 501);

        ArrowNetworkMessage message = new()
        {
            PublisherId = publisherId,
            WriterGroupId = 9,
            DataSetClassId = dataSetClassId,
            SchemaId = "arrow-schema-1",
            MetaData = metaData,
            DataSetMessages =
            [
                CreateSample(501, 100, 21.5, "pump-a", [1.0, 2.0], true, metaData),
                CreateSample(501, 101, 22.25, null, [], false, metaData),
                CreateSample(501, 102, 23.75, "pump-c", [3.5, 4.5, 5.5], true, metaData)
            ]
        };

        ArrowNetworkMessageEncoder encoder = new();
        ReadOnlyMemory<byte> frame = await encoder.EncodeAsync(message, context);

        using (ArrowStreamReader reader = new(new MemoryStream(frame.ToArray(), writable: false)))
        using (RecordBatch? batch = reader.ReadNextRecordBatch())
        {
            Assert.That(batch, Is.Not.Null);
            Assert.That(batch!.Length, Is.EqualTo(message.DataSetMessages.Count));
            Assert.That(batch.Schema.GetFieldByIndex(5).Name, Is.EqualTo("Temperature"));
            Assert.That(batch.Schema.GetFieldByIndex(5).DataType, Is.TypeOf<DoubleType>());
            Assert.That(batch.Schema.GetFieldByIndex(7).DataType, Is.TypeOf<ListType>());
            for (int i = 5; i < batch.ColumnCount; i++)
            {
                Assert.That(batch.Schema.GetFieldByIndex(i).DataType, Is.Not.TypeOf<BinaryType>());
            }
        }

        ArrowNetworkMessageDecoder decoder = new();
        PubSubNetworkMessage? decoded = await decoder.TryDecodeAsync(frame, context);

        Assert.That(decoded, Is.TypeOf<ArrowNetworkMessage>());
        ArrowNetworkMessage decodedMessage = (ArrowNetworkMessage)decoded!;
        Assert.That(decodedMessage.PublisherId, Is.EqualTo(message.PublisherId));
        Assert.That(decodedMessage.WriterGroupId, Is.EqualTo(message.WriterGroupId));
        Assert.That(decodedMessage.DataSetMessages.Count, Is.EqualTo(3));

        for (int i = 0; i < decodedMessage.DataSetMessages.Count; i++)
        {
            ArrowDataSetMessage actual = (ArrowDataSetMessage)decodedMessage.DataSetMessages[i];
            ArrowDataSetMessage expected = (ArrowDataSetMessage)message.DataSetMessages[i];
            Assert.That(actual.DataSetWriterId, Is.EqualTo(expected.DataSetWriterId));
            Assert.That(actual.SequenceNumber, Is.EqualTo(expected.SequenceNumber));
            Assert.That(actual.Status, Is.EqualTo(expected.Status));
            Assert.That(actual.Timestamp, Is.EqualTo(expected.Timestamp));
            Assert.That(actual.MessageType, Is.EqualTo(PubSubDataSetMessageType.KeyFrame));
        }

        ArrowDataSetMessage first = (ArrowDataSetMessage)decodedMessage.DataSetMessages[0];
        Assert.That(first.Fields[0].Value.TryGetValue(out double temperature), Is.True);
        Assert.That(temperature, Is.EqualTo(21.5));
        Assert.That(first.Fields[1].Value.TryGetValue(out string label), Is.True);
        Assert.That(label, Is.EqualTo("pump-a"));
        Assert.That(first.Fields[2].Value.TryGetValue(out ArrayOf<double> samples), Is.True);
        Assert.That(samples.ToArray(), Is.EqualTo(new[] { 1.0, 2.0 }));
        Assert.That(first.Fields[3].Value.TryGetValue(out bool enabled), Is.True);
        Assert.That(enabled, Is.True);

        ArrowDataSetMessage second = (ArrowDataSetMessage)decodedMessage.DataSetMessages[1];
        Assert.That(second.Fields[1].Value.IsNull, Is.True);
        Assert.That(second.Fields[2].Value.TryGetValue(out ArrayOf<double> emptySamples), Is.True);
        Assert.That(emptySamples.Count, Is.Zero);
    }

    private static ArrowDataSetMessage CreateSample(
        ushort writerId,
        uint sequenceNumber,
        double temperature,
        string? label,
        double[] samples,
        bool enabled,
        DataSetMetaDataType metaData)
    {
        return new ArrowDataSetMessage
        {
            DataSetWriterId = writerId,
            SequenceNumber = sequenceNumber,
            Status = (StatusCode)StatusCodes.Good,
            Timestamp = new DateTimeUtc(new DateTime(2026, 7, 4, 9, 30, 0, DateTimeKind.Utc).AddSeconds(sequenceNumber)),
            MessageType = PubSubDataSetMessageType.KeyFrame,
            MetaDataVersion = metaData.ConfigurationVersion,
            FieldContentMask = DataSetFieldContentMask.RawData,
            Fields =
            [
                new DataSetField { Name = "Temperature", Value = new Variant(temperature), Encoding = PubSubFieldEncoding.RawData },
                new DataSetField { Name = "Label", Value = label is null ? Variant.Null : new Variant(label), Encoding = PubSubFieldEncoding.RawData },
                new DataSetField { Name = "Samples", Value = new Variant(new ArrayOf<double>(samples.AsMemory())), Encoding = PubSubFieldEncoding.RawData },
                new DataSetField { Name = "Enabled", Value = new Variant(enabled), Encoding = PubSubFieldEncoding.RawData }
            ]
        };
    }

    private static PubSubNetworkMessageContext CreateContext(
        PublisherId publisherId,
        ushort writerGroupId,
        Uuid dataSetClassId,
        DataSetMetaDataType metaData,
        ushort dataSetWriterId)
    {
        DataSetMetaDataRegistry registry = new();
        DataSetMetaDataKey key = new(
            publisherId,
            writerGroupId,
            dataSetWriterId,
            dataSetClassId,
            metaData.ConfigurationVersion.MajorVersion);
        registry.Register(in key, metaData);

        return new PubSubNetworkMessageContext(
            ServiceMessageContext.CreateEmpty(null!),
            registry,
            new PubSubDiagnostics(PubSubDiagnosticsLevel.High),
            TimeProvider.System);
    }

    private static DataSetMetaDataType CreateMetaData()
    {
        return new DataSetMetaDataType
        {
            Name = "ArrowDataSet",
            ConfigurationVersion = new ConfigurationVersionDataType { MajorVersion = 1, MinorVersion = 0 },
            Fields =
            [
                new FieldMetaData { Name = "Temperature", BuiltInType = (byte)BuiltInType.Double, ValueRank = ValueRanks.Scalar },
                new FieldMetaData { Name = "Label", BuiltInType = (byte)BuiltInType.String, ValueRank = ValueRanks.Scalar },
                new FieldMetaData { Name = "Samples", BuiltInType = (byte)BuiltInType.Double, ValueRank = ValueRanks.OneDimension },
                new FieldMetaData { Name = "Enabled", BuiltInType = (byte)BuiltInType.Boolean, ValueRank = ValueRanks.Scalar }
            ]
        };
    }
}
