#pragma warning disable RCS0056, NUnit2005, CS0618, CS8620
using System;
using System.IO;
using NUnit.Framework;

namespace Opc.Ua.Core.Experimental.Tests
{
    [TestFixture]
    public sealed class ProtobufRoundTripTests
    {
        private static readonly IServiceMessageContext Context = ServiceMessageContext.CreateEmpty(null!);

        [Test]
        public void BuiltInsRoundTripEdges()
        {
            byte[] bytes = Encode(e =>
            {
                e.WriteBoolean("b", true);
                e.WriteSByte("sb", sbyte.MinValue);
                e.WriteByte("by", byte.MaxValue);
                e.WriteInt16("i16", short.MinValue);
                e.WriteUInt16("u16", ushort.MaxValue);
                e.WriteInt32("i32", int.MinValue);
                e.WriteUInt32("u32", uint.MaxValue);
                e.WriteInt64("i64", long.MinValue);
                e.WriteUInt64("u64", ulong.MaxValue);
                e.WriteFloat("f", -0.0f);
                e.WriteDouble("d", double.NaN);
                e.WriteString("sn", null);
                e.WriteString("se", string.Empty);
                e.WriteDateTime("dt0", DateTimeUtc.MinValue);
                e.WriteDateTime("dt1", DateTimeUtc.MaxValue);
                e.WriteGuid("g", new Uuid(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff")));
                e.WriteByteString("bs", ByteString.From(new byte[] { 0, 1, 255 }));
            });

            var d = new ProtobufDecoder(bytes, Context);
            Assert.That(d.ReadBoolean("b"), Is.True);
            Assert.That(d.ReadSByte("sb"), Is.EqualTo(sbyte.MinValue));
            Assert.That(d.ReadByte("by"), Is.EqualTo(byte.MaxValue));
            Assert.That(d.ReadInt16("i16"), Is.EqualTo(short.MinValue));
            Assert.That(d.ReadUInt16("u16"), Is.EqualTo(ushort.MaxValue));
            Assert.That(d.ReadInt32("i32"), Is.EqualTo(int.MinValue));
            Assert.That(d.ReadUInt32("u32"), Is.EqualTo(uint.MaxValue));
            Assert.That(d.ReadInt64("i64"), Is.EqualTo(long.MinValue));
            Assert.That(d.ReadUInt64("u64"), Is.EqualTo(ulong.MaxValue));
            Assert.That(BitConverter.SingleToUInt32Bits(d.ReadFloat("f")), Is.EqualTo(BitConverter.SingleToUInt32Bits(-0.0f)));
            Assert.That(BitConverter.DoubleToUInt64Bits(d.ReadDouble("d")), Is.EqualTo(BitConverter.DoubleToUInt64Bits(double.NaN)));
            Assert.That(d.ReadString("sn"), Is.Null);
            Assert.That(d.ReadString("se"), Is.EqualTo(string.Empty));
            Assert.That(d.ReadDateTime("dt0"), Is.EqualTo(DateTimeUtc.MinValue));
            Assert.That(d.ReadDateTime("dt1"), Is.EqualTo(DateTimeUtc.MaxValue));
            Assert.That((Guid)d.ReadGuid("g"), Is.EqualTo(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff")));
            Assert.That(d.ReadByteString("bs").Span.ToArray(), Is.EqualTo(new byte[] { 0, 1, 255 }));
        }

        [Test]
        public void NodeIdIdentifierKindsRoundTrip()
        {
            NodeId[] values =
            [
                new NodeId(123u, 2),
                new NodeId("name", 3),
                new NodeId(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"), 4),
                new NodeId(ByteString.From(new byte[] { 9, 8, 7 }), 5)
            ];
            byte[] bytes = Encode(e =>
            {
                for (int ii = 0; ii < values.Length; ii++)
                {
                    e.WriteNodeId("n" + ii, values[ii]);
                }
            });
            var d = new ProtobufDecoder(bytes, Context);
            for (int ii = 0; ii < values.Length; ii++)
            {
                Assert.That(d.ReadNodeId("n" + ii), Is.EqualTo(values[ii]));
            }
        }

        [Test]
        public void NullableArraysAndCompositeValuesRoundTrip()
        {
            var numbers = new ArrayOf<ulong>(new ulong[] { 0, 1, ulong.MaxValue });
            var value = new DataValue(new Variant(42), StatusCodes.BadUnexpectedError);
            var info = new DiagnosticInfo { SymbolicId = 1, AdditionalInfo = "detail", InnerStatusCode = StatusCodes.BadInternalError };
            var xo = new ExtensionObject(new ExpandedNodeId(new NodeId(5001u, 2)), ByteString.From(new byte[] { 1, 2, 3 }));

            byte[] bytes = Encode(e =>
            {
                e.WriteUInt64Array("ua", numbers);
                e.WriteDataValue("dv", value);
                e.WriteDiagnosticInfo("di", info);
                e.WriteExtensionObject("eo", xo);
            });

            var d = new ProtobufDecoder(bytes, Context);
            Assert.That(d.ReadUInt64Array("ua").Span.ToArray(), Is.EqualTo(numbers.Span.ToArray()));
            Assert.That(d.ReadDataValue("dv"), Is.EqualTo(value));
            Assert.That(d.ReadDiagnosticInfo("di")!.AdditionalInfo, Is.EqualTo("detail"));
            Assert.That(d.ReadExtensionObject("eo").TypeId, Is.EqualTo(xo.TypeId));
        }

        [Test]
        public void OptionalScalarPresenceDistinguishesAbsentFromPresentZero()
        {
            var absent = new OptionalScalars { Id = 7 };
            var zero = new OptionalScalars { Id = 7, HasCount = true, Count = 0 };

            OptionalScalars absentRoundTrip = RoundTrip(absent);
            OptionalScalars zeroRoundTrip = RoundTrip(zero);

            Assert.That(absentRoundTrip.HasCount, Is.False);
            Assert.That(zeroRoundTrip.HasCount, Is.True);
            Assert.That(zeroRoundTrip.Count, Is.Zero);
        }

        [Test]
        public void VariantScalarRoundTrip()
        {
            Variant value = new Variant(ulong.MaxValue);
            byte[] bytes = Encode(e => e.WriteVariant("v", value));
            var decoded = new ProtobufDecoder(bytes, Context).ReadVariant("v");
            Assert.That(decoded.GetUInt64(), Is.EqualTo(ulong.MaxValue));
        }

        private static T RoundTrip<T>(T value) where T : IEncodeable, new()
        {
            byte[] bytes = Encode(value.Encode);
            var decoded = new T();
            decoded.Decode(new ProtobufDecoder(bytes, Context));
            return decoded;
        }

        private static byte[] Encode(Action<ProtobufEncoder> encode)
        {
            using var stream = new MemoryStream();
            using var encoder = new ProtobufEncoder(stream, Context);
            encode(encoder);
            encoder.Close();
            return stream.ToArray();
        }

        private sealed class OptionalScalars : IEncodeable
        {
            public int Id { get; set; }
            public bool HasFlag { get; set; }
            public bool Flag { get; set; }
            public bool HasCount { get; set; }
            public int Count { get; set; }
            public bool HasRatio { get; set; }
            public double Ratio { get; set; }
            public ExpandedNodeId TypeId => new NodeId(9001u, 1);
            public ExpandedNodeId BinaryEncodingId => new NodeId(9002u, 1);
            public ExpandedNodeId XmlEncodingId => new NodeId(9003u, 1);
            public object Clone() => MemberwiseClone();
            public bool IsEqual(IEncodeable? encodeable) => encodeable is OptionalScalars other && Equals(other);
            public void Encode(IEncoder encoder)
            {
                encoder.WriteInt32("id", Id);
                if (HasFlag) { encoder.WriteBoolean("flag", Flag); }
                if (HasCount) { encoder.WriteInt32("count", Count); }
                if (HasRatio) { encoder.WriteDouble("ratio", Ratio); }
            }
            public void Decode(IDecoder decoder)
            {
                Id = decoder.ReadInt32("id");
                uint mask = decoder.ReadEncodingMask(["count"]);
                HasCount = (mask & 1u) != 0;
                if (HasFlag) { Flag = decoder.ReadBoolean("flag"); }
                if (HasCount) { Count = decoder.ReadInt32("count"); }
                if (HasRatio) { Ratio = decoder.ReadDouble("ratio"); }
            }
        }
    }
}


