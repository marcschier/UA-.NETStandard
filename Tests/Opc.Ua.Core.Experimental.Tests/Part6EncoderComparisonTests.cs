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
using System.IO;
using System.Linq;
using System.Text;
using NUnit.Framework;
using CoreJsonDecoder = Opc.Ua.JsonDecoder;
using CoreJsonEncoder = Opc.Ua.JsonEncoder;

namespace Opc.Ua.Core.Tests
{
    /// <summary>
    /// Prints lightweight Part 6 encoder comparison measurements for payload size, CPU, and allocation trends.
    /// </summary>
    [TestFixture]
    [Category("EncoderComparison")]
    public sealed class Part6EncoderComparisonTests
    {
        private const int WarmupIterations = 5;
        private static readonly IServiceMessageContext Context = ServiceMessageContext.CreateEmpty(null!);
        private static readonly Guid SampleGuid = new("00112233-4455-6677-8899-aabbccddeeff");
        private static readonly DateTime SampleDateTime = new(2026, 7, 6, 12, 34, 56, DateTimeKind.Utc);

        [Test]
        public void MeasurePart6EncoderComparisons()
        {
            EncoderSpec[] encoders =
            [
                new("Binary", CreateBinaryEncoder, CreateBinaryDecoder),
                new("JSON", CreateJsonEncoder, CreateJsonDecoder),
                new("Avro", CreateAvroEncoder, CreateAvroDecoder),
                new("Protobuf", CreateProtobufEncoder, CreateProtobufDecoder),
                new("Arrow", CreateArrowEncoder, CreateArrowDecoder)
            ];

            Scenario[] scenarios =
            [
                new("Scalars-mixed", 1000, WriteScalarsMixed, ReadScalarsMixed),
                new("DoubleArray-1000", 200, WriteDoubleArray1000, ReadDoubleArray1000),
                new("Int32Matrix-50x50", 100, WriteInt32Matrix50By50, ReadInt32Matrix50By50),
                new("Variants-100", 200, WriteVariants100, ReadVariants100)
            ];

            foreach (Scenario scenario in scenarios)
            {
                Measurement[] measurements = encoders.Select(encoder => Measure(scenario, encoder)).ToArray();
                WriteTable(scenario.Name, measurements);
            }
        }

        private static Measurement Measure(Scenario scenario, EncoderSpec encoder)
        {
            try
            {
                byte[] payload = Encode(encoder, scenario.Write);
                _ = Decode(encoder, scenario.Read, payload);
                for (int ii = 0; ii < WarmupIterations; ii++)
                {
                    _ = Encode(encoder, scenario.Write);
                    _ = Decode(encoder, scenario.Read, payload);
                }

                long beforeAlloc = GC.GetAllocatedBytesForCurrentThread();
                long encodeStart = Stopwatch.GetTimestamp();
                for (int ii = 0; ii < scenario.Iterations; ii++)
                {
                    _ = Encode(encoder, scenario.Write);
                }
                long encodeStop = Stopwatch.GetTimestamp();
                long afterAlloc = GC.GetAllocatedBytesForCurrentThread();

                long decodeStart = Stopwatch.GetTimestamp();
                for (int ii = 0; ii < scenario.Iterations; ii++)
                {
                    _ = Decode(encoder, scenario.Read, payload);
                }
                long decodeStop = Stopwatch.GetTimestamp();

                return new Measurement(
                    encoder.Name,
                    payload.Length,
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

        private static byte[] Encode(EncoderSpec encoder, Action<IEncoder> write)
        {
            using MemoryStream stream = new();
            using IEncoder instance = encoder.CreateEncoder(stream);
            write(instance);
            instance.Close();
            return stream.ToArray();
        }

        private static object? Decode(EncoderSpec encoder, Action<IDecoder> read, byte[] payload)
        {
            using IDecoder decoder = encoder.CreateDecoder(payload);
            read(decoder);
            return null;
        }

        private static BinaryEncoder CreateBinaryEncoder(Stream stream)
        {
            return new BinaryEncoder(stream, Context, true);
        }

        private static BinaryDecoder CreateBinaryDecoder(byte[] payload)
        {
            return new BinaryDecoder(payload, Context);
        }

        private static CoreJsonEncoder CreateJsonEncoder(Stream stream)
        {
            return new CoreJsonEncoder(stream, Context, JsonEncoderOptions.Compact);
        }

        private static CoreJsonDecoder CreateJsonDecoder(byte[] payload)
        {
            return new CoreJsonDecoder(new MemoryStream(payload, writable: false), Context);
        }

        private static AvroEncoder CreateAvroEncoder(Stream stream)
        {
            return new AvroEncoder(stream, Context, true);
        }

        private static AvroDecoder CreateAvroDecoder(byte[] payload)
        {
            return new AvroDecoder(payload, Context);
        }

        private static ProtobufEncoder CreateProtobufEncoder(Stream stream)
        {
            return new ProtobufEncoder(stream, Context, true);
        }

        private static ProtobufDecoder CreateProtobufDecoder(byte[] payload)
        {
            return new ProtobufDecoder(payload, Context);
        }

        private static ArrowEncoder CreateArrowEncoder(Stream stream)
        {
            return new ArrowEncoder(stream, Context, true);
        }

        private static ArrowDecoder CreateArrowDecoder(byte[] payload)
        {
            return new ArrowDecoder(payload, Context);
        }

        private static void WriteScalarsMixed(IEncoder encoder)
        {
            encoder.WriteBoolean("Bool", true);
            encoder.WriteSByte("SByte", -12);
            encoder.WriteInt16("Int16", -1234);
            encoder.WriteInt32("Int32", -123456);
            encoder.WriteInt64("Int64", -1234567890123L);
            encoder.WriteUInt32("UInt32", 123456U);
            encoder.WriteFloat("Float", 123.456f);
            encoder.WriteDouble("Double", -9876.54321d);
            encoder.WriteDateTime("DateTime", SampleDateTime);
            encoder.WriteString("String", "The quick brown fox jumps over the lazy dog.");
            encoder.WriteNodeId("NodeId", NodeId.Parse("ns=2;s=Pump/Temperature"));
            encoder.WriteGuid("Guid", new Uuid(SampleGuid));
            encoder.WriteStatusCode("StatusCode", StatusCodes.GoodClamped);
        }

        private static void ReadScalarsMixed(IDecoder decoder)
        {
            _ = decoder.ReadBoolean("Bool");
            _ = decoder.ReadSByte("SByte");
            _ = decoder.ReadInt16("Int16");
            _ = decoder.ReadInt32("Int32");
            _ = decoder.ReadInt64("Int64");
            _ = decoder.ReadUInt32("UInt32");
            _ = decoder.ReadFloat("Float");
            _ = decoder.ReadDouble("Double");
            _ = decoder.ReadDateTime("DateTime");
            _ = decoder.ReadString("String");
            _ = decoder.ReadNodeId("NodeId");
            _ = decoder.ReadGuid("Guid");
            _ = decoder.ReadStatusCode("StatusCode");
        }

        private static void WriteDoubleArray1000(IEncoder encoder)
        {
            encoder.WriteDoubleArray("Doubles", new ArrayOf<double>(CreateDoubleValues(1000)));
        }

        private static void ReadDoubleArray1000(IDecoder decoder)
        {
            _ = decoder.ReadDoubleArray("Doubles");
        }

        private static void WriteInt32Matrix50By50(IEncoder encoder)
        {
            encoder.WriteVariant("Int32Matrix", new Variant(new ArrayOf<int>(CreateInt32Values(2500)).ToMatrix(50, 50)));
        }

        private static void ReadInt32Matrix50By50(IDecoder decoder)
        {
            _ = decoder.ReadVariant("Int32Matrix");
        }

        private static void WriteVariants100(IEncoder encoder)
        {
            for (int ii = 0; ii < 100; ii++)
            {
                encoder.WriteVariant("Variant" + ii.ToString(CultureInfo.InvariantCulture), CreateVariant(ii));
            }
        }

        private static void ReadVariants100(IDecoder decoder)
        {
            for (int ii = 0; ii < 100; ii++)
            {
                _ = decoder.ReadVariant("Variant" + ii.ToString(CultureInfo.InvariantCulture));
            }
        }

        private static Variant CreateVariant(int index)
        {
            return (index % 8) switch
            {
                0 => new Variant(index % 2 == 0),
                1 => new Variant((int)(index * 1000)),
                2 => new Variant((double)index / 3.0d),
                3 => new Variant("value-" + index.ToString(CultureInfo.InvariantCulture)),
                4 => new Variant(new DateTime(2026, 7, 6, 0, 0, 0, DateTimeKind.Utc).AddSeconds(index)),
                5 => new Variant(new NodeId((uint)index, 2)),
                6 => new Variant(new Uuid(SampleGuid)),
                _ => new Variant((StatusCode)StatusCodes.UncertainSubNormal)
            };
        }

        private static double[] CreateDoubleValues(int count)
        {
            double[] values = new double[count];
            for (int ii = 0; ii < values.Length; ii++)
            {
                values[ii] = Math.Sin(ii * 0.01d) * 1000.0d;
            }
            return values;
        }

        private static int[] CreateInt32Values(int count)
        {
            int[] values = new int[count];
            for (int ii = 0; ii < values.Length; ii++)
            {
                values[ii] = ii - 1250;
            }
            return values;
        }

        private static double ToNanoseconds(long elapsedTicks, int iterations)
        {
            return elapsedTicks * 1_000_000_000.0d / Stopwatch.Frequency / iterations;
        }

        private static void WriteTable(string scenario, IReadOnlyList<Measurement> measurements)
        {
            TestContext.Progress.WriteLine(string.Empty);
            TestContext.Progress.WriteLine("Part 6: " + scenario);
            TestContext.Progress.WriteLine("Encoder     Payload(B)   Encode(ns/op)   Decode(ns/op)   Alloc(B/op)   Notes");
            TestContext.Progress.WriteLine("----------  -----------  -------------  -------------  -----------   -----");
            foreach (Measurement item in measurements)
            {
                TestContext.Progress.WriteLine(item.ToRow());
            }
        }

        private sealed record Scenario(
            string Name,
            int Iterations,
            Action<IEncoder> Write,
            Action<IDecoder> Read);

        private sealed record EncoderSpec(
            string Name,
            Func<Stream, IEncoder> CreateEncoder,
            Func<byte[], IDecoder> CreateDecoder);

        private sealed record Measurement(
            string Encoder,
            int? PayloadBytes,
            double? EncodeNanoseconds,
            double? DecodeNanoseconds,
            long? AllocatedBytes,
            string? Notes)
        {
            public static Measurement NotAvailable(string encoder, string notes)
            {
                return new Measurement(encoder, null, null, null, null, "n/a: " + notes);
            }

            public string ToRow()
            {
                return string.Format(
                    CultureInfo.InvariantCulture,
                    "{0,-10}  {1,11}  {2,13}  {3,13}  {4,11}   {5}",
                    Encoder,
                    Format(PayloadBytes),
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
                return value.HasValue ? value.Value.ToString("N0", CultureInfo.InvariantCulture) : "n/a";
            }
        }
    }
}
