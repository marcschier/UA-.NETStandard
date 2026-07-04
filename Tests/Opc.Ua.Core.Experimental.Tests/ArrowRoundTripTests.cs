using System;
#pragma warning disable RCS0056, RCS1078, CA1861
using System.IO;
using Apache.Arrow.Ipc;
using Apache.Arrow.Types;
using NUnit.Framework;
using Opc.Ua;
using Opc.Ua.Core.Experimental;

namespace Opc.Ua.Core.Experimental.Tests
{
    [TestFixture]
    public sealed class ArrowRoundTripTests
    {
        private static IServiceMessageContext Context => ServiceMessageContext.CreateEmpty(null!);

        [Test]
        public void ArrowBuiltInsRoundTripWithFloatBits()
        {
            Assert.That(RoundTrip(e => e.WriteBoolean(null, true), d => d.ReadBoolean(null)), Is.True);
            Assert.That(RoundTrip(e => e.WriteSByte(null, sbyte.MinValue), d => d.ReadSByte(null)), Is.EqualTo(sbyte.MinValue));
            Assert.That(RoundTrip(e => e.WriteUInt64(null, ulong.MaxValue), d => d.ReadUInt64(null)), Is.EqualTo(ulong.MaxValue));
            Assert.That(BitConverter.SingleToInt32Bits(RoundTrip(e => e.WriteFloat(null, -0.0f), d => d.ReadFloat(null))), Is.EqualTo(BitConverter.SingleToInt32Bits(-0.0f)));
            Assert.That(float.IsNaN(RoundTrip(e => e.WriteFloat(null, float.NaN), d => d.ReadFloat(null))), Is.True);
            Assert.That(RoundTrip(e => e.WriteDouble(null, double.PositiveInfinity), d => d.ReadDouble(null)), Is.EqualTo(double.PositiveInfinity));
            Assert.That(RoundTrip(e => e.WriteDateTime(null, DateTimeUtc.MaxValue), d => d.ReadDateTime(null)), Is.EqualTo(DateTimeUtc.MaxValue));
            Assert.That(RoundTrip(e => e.WriteString(null, null), d => d.ReadString(null)), Is.Null);
            Assert.That(RoundTrip(e => e.WriteByteString(null, ByteString.From(1, 2, 3)), d => d.ReadByteString(null)), Is.EqualTo(ByteString.From(1, 2, 3)));
        }

        [Test]
        public void ArrowNodeIdKindsRoundTrip()
        {
            RoundTripEqual(new NodeId(123u, 2));
            RoundTripEqual(new NodeId("name", 3));
            RoundTripEqual(new NodeId(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"), 4));
            RoundTripEqual(new NodeId(ByteString.From(0xaa, 0xbb), 5));
        }

        [Test]
        public void ArrowArraysVariantMatrixDataValueExtensionObjectAndDiagnosticsRoundTrip()
        {
            var strings = new ArrayOf<string>(new string?[] { "a", null, string.Empty }!);
            Assert.That(RoundTrip(e => e.WriteStringArray(null, strings), d => d.ReadStringArray(null)), Is.EqualTo(strings));

            Variant matrix = new Variant(new ArrayOf<int>(new[] { 1, 2, 3, 4 }).ToMatrix(2, 2));
            Assert.That(RoundTrip(e => e.WriteVariant(null, matrix), d => d.ReadVariant(null)), Is.EqualTo(matrix));

            var value = new DataValue(new Variant("payload"), new StatusCode(0x80340000), new DateTimeUtc(123456789L), new DateTimeUtc(987654321L), 10, 20);
            Assert.That(RoundTrip(e => e.WriteDataValue(null, value), d => d.ReadDataValue(null)), Is.EqualTo(value));

            var extension = new ExtensionObject(new ExpandedNodeId(new NodeId(1u, 2)), ByteString.From(9, 8, 7));
            Assert.That(RoundTrip(e => e.WriteExtensionObject(null, extension), d => d.ReadExtensionObject(null)), Is.EqualTo(extension));

            var diagnostic = new DiagnosticInfo { SymbolicId = 1, AdditionalInfo = "info", InnerStatusCode = new StatusCode(0x80010000), InnerDiagnosticInfo = new DiagnosticInfo { SymbolicId = 2 } };
            Assert.That(RoundTrip(e => e.WriteDiagnosticInfo(null, diagnostic), d => d.ReadDiagnosticInfo(null)), Is.EqualTo(diagnostic));
        }

        [Test]
        public void ArrowUnionAndOptionalPresenceSignalsRoundTrip()
        {
            byte[] bytes = Encode(e =>
            {
                e.WriteSwitchField(2, out _);
                e.WriteEncodingMask(0b101);
                e.WriteInt32("presentZero", 0);
                e.WriteString("presentNull", null);
            });

            using var decoder = new ArrowDecoder(bytes, Context);
            Assert.That(decoder.ReadSwitchField(Array.Empty<string>(), out _), Is.EqualTo(2));
            Assert.That(decoder.ReadEncodingMask(Array.Empty<string>()), Is.EqualTo(0b101));
            Assert.That(decoder.HasField("presentZero"), Is.True);
            Assert.That(decoder.HasField("absent"), Is.False);
            Assert.That(decoder.ReadInt32("presentZero"), Is.Zero);
            Assert.That(decoder.ReadString("presentNull"), Is.Null);
        }

        [Test]
        public void ArrowSchemaUsesTypedColumns()
        {
            AssertArrowType(e => e.WriteInt32(null, 42), typeof(Int32Type));
            AssertArrowType(e => e.WriteGuid(null, new Uuid(Guid.NewGuid())), typeof(FixedSizeBinaryType));
            AssertArrowType(e => e.WriteNodeId(null, new NodeId(123u, 2)), typeof(StructType));
            AssertArrowType(e => e.WriteStringArray(null, new ArrayOf<string>(new[] { "a", "b" })), typeof(ListType));
            AssertArrowType(e => e.WriteVariant(null, new Variant(123)), typeof(UnionType));
        }

        private static void RoundTripEqual(NodeId value)
        {
            Assert.That(RoundTrip(e => e.WriteNodeId(null, value), d => d.ReadNodeId(null)), Is.EqualTo(value));
        }

        private static T RoundTrip<T>(Action<ArrowEncoder> write, Func<ArrowDecoder, T> read)
        {
            byte[] bytes = Encode(write);
            using var decoder = new ArrowDecoder(bytes, Context);
            return read(decoder);
        }

        private static byte[] Encode(Action<ArrowEncoder> write)
        {
            using var stream = new MemoryStream();
            using (var encoder = new ArrowEncoder(stream, Context, leaveOpen: true))
            {
                write(encoder);
                encoder.Close();
            }
            return stream.ToArray();
        }

        private static void AssertArrowType(Action<ArrowEncoder> write, Type expectedType)
        {
            using var reader = new ArrowStreamReader(Encode(write));
            using var batch = reader.ReadNextRecordBatch();

            Assert.That(batch, Is.Not.Null);
            Assert.That(batch!.ColumnCount, Is.EqualTo(1));
            Assert.That(batch.Schema.GetFieldByIndex(0).DataType, Is.TypeOf(expectedType));
            Assert.That(batch.Schema.GetFieldByIndex(0).DataType, Is.Not.TypeOf<BinaryType>());
        }
    }
}
