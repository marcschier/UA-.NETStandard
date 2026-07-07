/* ========================================================================
 * Copyright (c) 2005-2026 The OPC Foundation, Inc. All rights reserved.
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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using NUnit.Framework;
using Opc.Ua;
using Opc.Ua.PubSub.Diagnostics;
using Opc.Ua.PubSub.Encoding;
using Opc.Ua.PubSub.MetaData;
using PubSubJsonDataSetMessage = Opc.Ua.PubSub.Encoding.Json.JsonDataSetMessage;
using PubSubJsonDecoder = Opc.Ua.PubSub.Encoding.Json.JsonDecoder;
using PubSubJsonEncoder = Opc.Ua.PubSub.Encoding.Json.JsonEncoder;
using PubSubJsonEncodingMode = Opc.Ua.PubSub.Encoding.Json.JsonEncodingMode;
using PubSubJsonNetworkMessage = Opc.Ua.PubSub.Encoding.Json.JsonNetworkMessage;
using UadpDataSetMessage = Opc.Ua.PubSub.Encoding.Uadp.UadpDataSetMessage;
using UadpDecoder = Opc.Ua.PubSub.Encoding.Uadp.UadpDecoder;
using UadpEncoder = Opc.Ua.PubSub.Encoding.Uadp.UadpEncoder;
using UadpNetworkMessage = Opc.Ua.PubSub.Encoding.Uadp.UadpNetworkMessage;

namespace Opc.Ua.PubSub.Encoding.Tests
{
    /// <summary>
    /// Prints lightweight Part 14 PubSub network-message comparison measurements for row and columnar batches.
    /// </summary>
    [TestFixture]
    [Category("EncoderComparison")]
    public sealed class Part14PubSubEncoderComparisonTests
    {
        private const int WarmupIterations = 3;
        private const ushort WriterGroupId = 1;
        private const ushort DataSetWriterIdBase = 100;
        private static readonly PublisherId PublisherId = PublisherId.FromUInt16(1234);
        private static readonly Uuid DataSetClassId = new(new Guid("95669f76-285a-41c6-ac2b-27793a3eac10"));

        [Test]
        public void MeasurePart14PubSubEncoderComparisons()
        {
            EncoderSpec[] encoders =
            [
                new("UADP", new UadpEncoder(), new UadpDecoder(), CreateUadpMessages),
                new("JSON", new PubSubJsonEncoder(PubSubJsonEncodingMode.Compact), new PubSubJsonDecoder(), CreateJsonMessages),
                new("Avro", new AvroNetworkMessageEncoder(), new AvroNetworkMessageDecoder(), CreateAvroMessages),
                new(
                    "Arrow (stream)",
                    new ArrowNetworkMessageEncoder { Framing = ArrowIpcFraming.Stream },
                    new ArrowNetworkMessageDecoder(),
                    CreateArrowMessages)
            ];

            Scenario[] scenarios =
            [
                new("Single DataSet sample", 1, 500),
                new("Batch DataSet samples (10)", 10, 300),
                new("Batch DataSet samples (100)", 100, 60),
                new("Batch DataSet samples (1000)", 1000, 10)
            ];

            foreach (Scenario scenario in scenarios)
            {
                PubSubNetworkMessageContext context = CreateContext(scenario.Samples);
                Measurement[] measurements = encoders.Select(encoder => Measure(scenario, encoder, context)).ToArray();
                WriteTable(scenario.Name, measurements);
            }
        }

        [Test]
        public void MeasureArrowIpcFramingBreakdown()
        {
            int[] sampleCounts = [1, 10, 100, 1000];
            int[] iterations = [500, 300, 60, 10];
            TestContext.Progress.WriteLine(string.Empty);
            TestContext.Progress.WriteLine("Part 14: Arrow IPC framing — stream vs bare batch");
            TestContext.Progress.WriteLine(
                "Samples   Framing   Payload(B)   B/sample   Encode(ns/op)   Decode(ns/op)   Alloc(B/op)");
            TestContext.Progress.WriteLine(
                "-------   -------   ----------   --------   -------------   -------------   -----------");
            for (int s = 0; s < sampleCounts.Length; s++)
            {
                PubSubNetworkMessageContext context = CreateContext(sampleCounts[s]);
                ArrowFramingMeasurement stream =
                    MeasureArrowFraming(ArrowIpcFraming.Stream, sampleCounts[s], iterations[s], context);
                ArrowFramingMeasurement batch =
                    MeasureArrowFraming(ArrowIpcFraming.Batch, sampleCounts[s], iterations[s], context);
                WriteArrowFramingRow(sampleCounts[s], "stream", stream);
                WriteArrowFramingRow(sampleCounts[s], "batch", batch);
            }
        }

        private static ArrowFramingMeasurement MeasureArrowFraming(
            ArrowIpcFraming framing,
            int samples,
            int iterations,
            PubSubNetworkMessageContext context)
        {
            ArrowNetworkMessage message = CreateArrowMessage(samples);
            ArrowNetworkMessageEncoder encoder = new() { Framing = framing };
            ArrowNetworkMessageDecoder decoder = new();

            ReadOnlyMemory<byte> payload = EncodeArrow(encoder, message, context);
            if (framing == ArrowIpcFraming.Batch)
            {
                decoder.CacheSchema(message.SchemaId!, encoder.LastSchemaMessage);
            }
            _ = DecodeArrow(decoder, framing, payload, message.SchemaId!, context);
            for (int ii = 0; ii < WarmupIterations; ii++)
            {
                _ = EncodeArrow(encoder, message, context);
                _ = DecodeArrow(decoder, framing, payload, message.SchemaId!, context);
            }

            long beforeAlloc = GC.GetAllocatedBytesForCurrentThread();
            long encodeStart = Stopwatch.GetTimestamp();
            for (int ii = 0; ii < iterations; ii++)
            {
                _ = EncodeArrow(encoder, message, context);
            }
            long encodeStop = Stopwatch.GetTimestamp();
            long afterAlloc = GC.GetAllocatedBytesForCurrentThread();

            long decodeStart = Stopwatch.GetTimestamp();
            for (int ii = 0; ii < iterations; ii++)
            {
                _ = DecodeArrow(decoder, framing, payload, message.SchemaId!, context);
            }
            long decodeStop = Stopwatch.GetTimestamp();

            return new ArrowFramingMeasurement(
                payload.Length,
                payload.Length / (double)samples,
                ToNanoseconds(encodeStop - encodeStart, iterations),
                ToNanoseconds(decodeStop - decodeStart, iterations),
                (afterAlloc - beforeAlloc) / iterations);
        }

        private static ReadOnlyMemory<byte> EncodeArrow(
            ArrowNetworkMessageEncoder encoder,
            ArrowNetworkMessage message,
            PubSubNetworkMessageContext context)
        {
            ValueTask<ReadOnlyMemory<byte>> operation = encoder.EncodeAsync(message, context);
            return operation.IsCompletedSuccessfully
                ? operation.Result
                : operation.AsTask().GetAwaiter().GetResult();
        }

        private static PubSubNetworkMessage? DecodeArrow(
            ArrowNetworkMessageDecoder decoder,
            ArrowIpcFraming framing,
            ReadOnlyMemory<byte> payload,
            string schemaId,
            PubSubNetworkMessageContext context)
        {
            ValueTask<PubSubNetworkMessage?> operation = framing == ArrowIpcFraming.Batch
                ? decoder.TryDecodeBatchAsync(payload, schemaId, context)
                : decoder.TryDecodeAsync(payload, context);
            return operation.IsCompletedSuccessfully
                ? operation.Result
                : operation.AsTask().GetAwaiter().GetResult();
        }

        private static void WriteArrowFramingRow(int samples, string framing, ArrowFramingMeasurement measurement)
        {
            TestContext.Progress.WriteLine(string.Format(
                CultureInfo.InvariantCulture,
                "{0,7}   {1,-7}   {2,10}   {3,8:N1}   {4,13:N0}   {5,13:N0}   {6,11:N0}",
                samples,
                framing,
                measurement.PayloadBytes,
                measurement.BytesPerSample,
                measurement.EncodeNanoseconds,
                measurement.DecodeNanoseconds,
                measurement.AllocatedBytes));
        }

        private sealed record ArrowFramingMeasurement(
            int PayloadBytes,
            double BytesPerSample,
            double EncodeNanoseconds,
            double DecodeNanoseconds,
            long AllocatedBytes);

        private static Measurement Measure(
            Scenario scenario,
            EncoderSpec encoder,
            PubSubNetworkMessageContext context)
        {
            try
            {
                PubSubNetworkMessage[] messages = encoder.CreateMessages(scenario.Samples);
                ReadOnlyMemory<byte>[] payload = Encode(encoder, messages, context);
                _ = Decode(encoder, payload, context);
                for (int ii = 0; ii < WarmupIterations; ii++)
                {
                    _ = Encode(encoder, messages, context);
                    _ = Decode(encoder, payload, context);
                }

                long beforeAlloc = GC.GetAllocatedBytesForCurrentThread();
                long encodeStart = Stopwatch.GetTimestamp();
                for (int ii = 0; ii < scenario.Iterations; ii++)
                {
                    _ = Encode(encoder, messages, context);
                }
                long encodeStop = Stopwatch.GetTimestamp();
                long afterAlloc = GC.GetAllocatedBytesForCurrentThread();

                long decodeStart = Stopwatch.GetTimestamp();
                for (int ii = 0; ii < scenario.Iterations; ii++)
                {
                    _ = Decode(encoder, payload, context);
                }
                long decodeStop = Stopwatch.GetTimestamp();
                int payloadBytes = payload.Sum(frame => frame.Length);

                return new Measurement(
                    encoder.Name,
                    payloadBytes,
                    payloadBytes / (double)scenario.Samples,
                    ToNanoseconds(encodeStop - encodeStart, scenario.Iterations),
                    ToNanoseconds(decodeStop - decodeStart, scenario.Iterations),
                    (afterAlloc - beforeAlloc) / scenario.Iterations,
                    null);
            }
            catch (NotSupportedException ex)
            {
                return Measurement.NotAvailable(encoder.Name, ex.Message);
            }
            catch (InvalidOperationException ex)
            {
                return Measurement.NotAvailable(encoder.Name, ex.Message);
            }
            catch (ServiceResultException ex)
            {
                return Measurement.NotAvailable(encoder.Name, ex.Message);
            }
            catch (Exception ex)
            {
                return Measurement.NotAvailable(encoder.Name, ex.GetType().Name + ": " + ex.Message);
            }
        }

        private static ReadOnlyMemory<byte>[] Encode(
            EncoderSpec encoder,
            PubSubNetworkMessage[] messages,
            PubSubNetworkMessageContext context)
        {
            ReadOnlyMemory<byte>[] payloads = new ReadOnlyMemory<byte>[messages.Length];
            for (int ii = 0; ii < messages.Length; ii++)
            {
                ValueTask<ReadOnlyMemory<byte>> operation = encoder.Encoder.EncodeAsync(messages[ii], context);
                payloads[ii] = operation.IsCompletedSuccessfully
                    ? operation.Result
                    : operation.AsTask().GetAwaiter().GetResult();
            }
            return payloads;
        }

        private static PubSubNetworkMessage? Decode(
            EncoderSpec encoder,
            ReadOnlyMemory<byte>[] payload,
            PubSubNetworkMessageContext context)
        {
            PubSubNetworkMessage? last = null;
            for (int ii = 0; ii < payload.Length; ii++)
            {
                ValueTask<PubSubNetworkMessage?> operation = encoder.Decoder.TryDecodeAsync(payload[ii], context);
                last = operation.IsCompletedSuccessfully
                    ? operation.Result
                    : operation.AsTask().GetAwaiter().GetResult();
            }
            return last;
        }

        private static PubSubNetworkMessage[] CreateUadpMessages(int samples)
        {
            DataSetMetaDataType metaData = CreateMetaData();
            PubSubNetworkMessage[] messages = new PubSubNetworkMessage[samples];
            for (int ii = 0; ii < samples; ii++)
            {
                messages[ii] = CreateUadpMessage(ii, metaData);
            }
            return messages;
        }

        private static UadpNetworkMessage CreateUadpMessage(int sample, DataSetMetaDataType metaData)
        {
            return new UadpNetworkMessage
            {
                ContentMask =
                    UadpNetworkMessageContentMask.PublisherId |
                    UadpNetworkMessageContentMask.GroupHeader |
                    UadpNetworkMessageContentMask.WriterGroupId |
                    UadpNetworkMessageContentMask.PayloadHeader |
                    UadpNetworkMessageContentMask.DataSetClassId,
                PublisherId = PublisherId,
                WriterGroupId = WriterGroupId,
                DataSetClassId = DataSetClassId,
                DataSetMessages =
                [
                    new UadpDataSetMessage
                    {
                        DataSetWriterId = GetWriterId(sample),
                        MessageType = PubSubDataSetMessageType.KeyFrame,
                        MetaDataVersion = metaData.ConfigurationVersion,
                        FieldEncoding = PubSubFieldEncoding.RawData,
                        Fields = CreateFields(sample)
                    }
                ]
            };
        }

        private static PubSubNetworkMessage[] CreateJsonMessages(int samples)
        {
            return [CreateJsonMessage(samples)];
        }

        private static PubSubJsonNetworkMessage CreateJsonMessage(int samples)
        {
            PubSubDataSetMessage[] messages = new PubSubDataSetMessage[samples];
            for (int ii = 0; ii < messages.Length; ii++)
            {
                messages[ii] = new PubSubJsonDataSetMessage
                {
                    DataSetWriterId = GetWriterId(ii),
                    SequenceNumber = (uint)ii,
                    MessageType = PubSubDataSetMessageType.KeyFrame,
                    MetaDataVersion = CreateMetaData().ConfigurationVersion,
                    Fields = CreateFields(ii)
                };
            }

            return new PubSubJsonNetworkMessage
            {
                MessageId = "comparison-json",
                PublisherId = PublisherId,
                DataSetClassId = DataSetClassId,
                DataSetMessages = messages
            };
        }

        private static PubSubNetworkMessage[] CreateAvroMessages(int samples)
        {
            return [CreateAvroMessage(samples)];
        }

        private static AvroNetworkMessage CreateAvroMessage(int samples)
        {
            DataSetMetaDataType metaData = CreateMetaData();
            PubSubDataSetMessage[] messages = new PubSubDataSetMessage[samples];
            for (int ii = 0; ii < messages.Length; ii++)
            {
                messages[ii] = new AvroDataSetMessage
                {
                    DataSetWriterId = GetWriterId(ii),
                    SequenceNumber = (uint)ii,
                    Timestamp = CreateTimestamp(ii),
                    Status = (StatusCode)StatusCodes.Good,
                    MessageType = PubSubDataSetMessageType.KeyFrame,
                    MetaDataVersion = metaData.ConfigurationVersion,
                    Fields = CreateFields(ii)
                };
            }

            return new AvroNetworkMessage
            {
                PublisherId = PublisherId,
                WriterGroupId = WriterGroupId,
                DataSetClassId = DataSetClassId,
                SchemaId = "comparison-avro",
                MetaData = metaData,
                DataSetMessages = messages
            };
        }

        private static PubSubNetworkMessage[] CreateArrowMessages(int samples)
        {
            return [CreateArrowMessage(samples)];
        }

        private static ArrowNetworkMessage CreateArrowMessage(int samples)
        {
            DataSetMetaDataType metaData = CreateMetaData();
            PubSubDataSetMessage[] messages = new PubSubDataSetMessage[samples];
            for (int ii = 0; ii < messages.Length; ii++)
            {
                messages[ii] = new ArrowDataSetMessage
                {
                    DataSetWriterId = GetWriterId(ii),
                    SequenceNumber = (uint)ii,
                    Timestamp = CreateTimestamp(ii),
                    Status = (StatusCode)StatusCodes.Good,
                    MessageType = PubSubDataSetMessageType.KeyFrame,
                    MetaDataVersion = metaData.ConfigurationVersion,
                    FieldContentMask = DataSetFieldContentMask.RawData,
                    Fields = CreateFields(ii)
                };
            }

            return new ArrowNetworkMessage
            {
                PublisherId = PublisherId,
                WriterGroupId = WriterGroupId,
                DataSetClassId = DataSetClassId,
                SchemaId = "comparison-arrow",
                MetaData = metaData,
                DataSetMessages = messages
            };
        }

        private static DataSetField[] CreateFields(int sample)
        {
            return
            [
                Field("Enabled", new Variant(sample % 2 == 0)),
                Field("Pressure", new Variant(sample * 10)),
                Field("Temperature", new Variant(20.0d + sample * 0.125d)),
                Field("Label", new Variant("pump-" + (sample % 16).ToString(CultureInfo.InvariantCulture))),
                Field("Counter", new Variant((uint)sample)),
                Field("Ratio", new Variant((float)(sample / 10.0f))),
                Field("Total", new Variant((long)sample * 1000000L)),
                Field("Quality", new Variant((ushort)(sample % 1024))),
                Field("Offset", new Variant((sbyte)(sample % 100 - 50))),
                Field("Code", new Variant((byte)(sample % 255)))
            ];
        }

        private static DataSetField Field(string name, Variant value)
        {
            return new DataSetField
            {
                Name = name,
                Value = value,
                Encoding = PubSubFieldEncoding.RawData
            };
        }

        private static PubSubNetworkMessageContext CreateContext(int samples)
        {
            DataSetMetaDataRegistry registry = new();
            DataSetMetaDataType metaData = CreateMetaData();
            for (int ii = 0; ii < samples; ii++)
            {
                DataSetMetaDataKey key = new(
                    PublisherId,
                    WriterGroupId,
                    GetWriterId(ii),
                    DataSetClassId,
                    metaData.ConfigurationVersion.MajorVersion);
                registry.Register(in key, metaData);
            }

            return new PubSubNetworkMessageContext(
                ServiceMessageContext.CreateEmpty(null!),
                registry,
                new PubSubDiagnostics(PubSubDiagnosticsLevel.Low),
                TimeProvider.System);
        }

        private static DataSetMetaDataType CreateMetaData()
        {
            return new DataSetMetaDataType
            {
                Name = "EncoderComparisonDataSet",
                ConfigurationVersion = new ConfigurationVersionDataType { MajorVersion = 1, MinorVersion = 0 },
                Fields =
                [
                    Meta("Enabled", BuiltInType.Boolean),
                    Meta("Pressure", BuiltInType.Int32),
                    Meta("Temperature", BuiltInType.Double),
                    Meta("Label", BuiltInType.String),
                    Meta("Counter", BuiltInType.UInt32),
                    Meta("Ratio", BuiltInType.Float),
                    Meta("Total", BuiltInType.Int64),
                    Meta("Quality", BuiltInType.UInt16),
                    Meta("Offset", BuiltInType.SByte),
                    Meta("Code", BuiltInType.Byte)
                ]
            };
        }

        private static FieldMetaData Meta(string name, BuiltInType builtInType)
        {
            return new FieldMetaData
            {
                Name = name,
                BuiltInType = (byte)builtInType,
                ValueRank = ValueRanks.Scalar
            };
        }

        private static ushort GetWriterId(int sample)
        {
            return checked((ushort)(DataSetWriterIdBase + sample));
        }

        private static DateTimeUtc CreateTimestamp(int sample)
        {
            return new DateTimeUtc(new DateTime(2026, 7, 6, 12, 0, 0, DateTimeKind.Utc).AddMilliseconds(sample));
        }

        private static double ToNanoseconds(long elapsedTicks, int iterations)
        {
            return elapsedTicks * 1_000_000_000.0d / Stopwatch.Frequency / iterations;
        }

        private static void WriteTable(string scenario, IReadOnlyList<Measurement> measurements)
        {
            TestContext.Progress.WriteLine(string.Empty);
            TestContext.Progress.WriteLine("Part 14: " + scenario);
            TestContext.Progress.WriteLine("Encoder     Payload(B)   B/sample   Encode(ns/op)   Decode(ns/op)   Alloc(B/op)   Notes");
            TestContext.Progress.WriteLine("----------  -----------  ---------  -------------  -------------  -----------   -----");
            foreach (Measurement item in measurements)
            {
                TestContext.Progress.WriteLine(item.ToRow());
            }
        }

        private sealed record Scenario(string Name, int Samples, int Iterations);

        private sealed record EncoderSpec(
            string Name,
            INetworkMessageEncoder Encoder,
            INetworkMessageDecoder Decoder,
            Func<int, PubSubNetworkMessage[]> CreateMessages);

        private sealed record Measurement(
            string Encoder,
            int? PayloadBytes,
            double? BytesPerSample,
            double? EncodeNanoseconds,
            double? DecodeNanoseconds,
            long? AllocatedBytes,
            string? Notes)
        {
            public static Measurement NotAvailable(string encoder, string notes)
            {
                return new Measurement(encoder, null, null, null, null, null, "n/a: " + notes);
            }

            public string ToRow()
            {
                return string.Format(
                    CultureInfo.InvariantCulture,
                    "{0,-10}  {1,11}  {2,9}  {3,13}  {4,13}  {5,11}   {6}",
                    Encoder,
                    Format(PayloadBytes),
                    Format(BytesPerSample),
                    Format(EncodeNanoseconds),
                    Format(DecodeNanoseconds),
                    Format(AllocatedBytes),
                    Notes ?? string.Empty);
            }

            private static string Format(int? value)
            {
                return value.HasValue ? value.Value.ToString("N0", CultureInfo.InvariantCulture) : "n/a";
            }

            private static string Format(long? value)
            {
                return value.HasValue ? value.Value.ToString("N0", CultureInfo.InvariantCulture) : "n/a";
            }

            private static string Format(double? value)
            {
                return value.HasValue ? value.Value.ToString("N1", CultureInfo.InvariantCulture) : "n/a";
            }
        }
    }
}
