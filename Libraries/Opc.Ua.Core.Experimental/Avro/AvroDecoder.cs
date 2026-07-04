#pragma warning disable RCS0056, RCS1007, CA2263, CS8600, CS8604, CS8620
using System;
using System.Collections.Generic;
using System.IO;
using Opc.Ua;
using Opc.Ua.Types;

namespace Opc.Ua.Core.Experimental
{
    public sealed partial class AvroDecoder : IDecoder
    {
        private readonly Stream m_stream;
        private readonly AvroBinaryReader m_reader;
        private readonly bool m_leaveOpen;
        public AvroDecoder(byte[] buffer, IServiceMessageContext context) : this(new MemoryStream(buffer, false), context, false) { }
        public AvroDecoder(Stream stream, IServiceMessageContext context, bool leaveOpen = true)
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
            m_stream = stream ?? throw new ArgumentNullException(nameof(stream));
            m_leaveOpen = leaveOpen;
            m_reader = new AvroBinaryReader(m_stream);
        }
        public EncodingType EncodingType => AvroEncoder.AvroEncodingType;
        public IServiceMessageContext Context { get; }
        public void Dispose() => Close();
        public void Close() { if (!m_leaveOpen) m_stream.Dispose(); }
        public void SetMappingTables(NamespaceTable namespaceUris, StringTable serverUris) { }
        public void PushNamespace(string namespaceUri) { }
        public void PopNamespace() { }
        public T DecodeMessage<T>() where T : IEncodeable
        {
            var value = (T)(Activator.CreateInstance(typeof(T))
                ?? throw new NotSupportedException($"Cannot create {typeof(T).FullName}."));
            value.Decode(this);
            return value;
        }

        public bool ReadBoolean(string? fieldName) => m_reader.ReadBoolean();
        public sbyte ReadSByte(string? fieldName) => checked((sbyte)m_reader.ReadInt());
        public byte ReadByte(string? fieldName) => checked((byte)m_reader.ReadInt());
        public short ReadInt16(string? fieldName) => checked((short)m_reader.ReadInt());
        public ushort ReadUInt16(string? fieldName) => checked((ushort)m_reader.ReadInt());
        public int ReadInt32(string? fieldName) => m_reader.ReadInt();
        public uint ReadUInt32(string? fieldName) => unchecked((uint)m_reader.ReadInt());
        public long ReadInt64(string? fieldName) => m_reader.ReadLong();
        public ulong ReadUInt64(string? fieldName) => unchecked((ulong)m_reader.ReadLong());
        public float ReadFloat(string? fieldName) => m_reader.ReadFloat();
        public double ReadDouble(string? fieldName) => m_reader.ReadDouble();
        public string? ReadString(string? fieldName) => ReadNullable(() => m_reader.ReadString());
        public DateTimeUtc ReadDateTime(string? fieldName) => new DateTimeUtc(m_reader.ReadLong());
        public Uuid ReadGuid(string? fieldName) => new Uuid(m_reader.ReadFixed(16));
        public ByteString ReadByteString(string? fieldName) { byte[]? bytes = ReadNullable(() => m_reader.ReadBytes()); return bytes == null ? default : ByteString.From(bytes); }
        public XmlElement ReadXmlElement(string? fieldName) => XmlElement.From(ReadString(fieldName));
        public NodeId ReadNodeId(string? fieldName)
        {
            ushort ns = ReadUInt16(null);
            var type = (IdType)ReadInt32(null);
            return type switch
            {
                IdType.Numeric => new NodeId(ReadUInt32(null), ns),
                IdType.String => new NodeId(ReadString(null) ?? string.Empty, ns),
                IdType.Guid => new NodeId(ReadGuid(null).Guid, ns),
                IdType.Opaque => new NodeId(ReadByteString(null), ns),
                _ => throw new NotSupportedException($"Unsupported NodeId identifier type {type}.")
            };
        }
        public ExpandedNodeId ReadExpandedNodeId(string? fieldName) => new ExpandedNodeId(ReadNodeId(null), ReadString(null), ReadUInt32(null));
        public StatusCode ReadStatusCode(string? fieldName) => new StatusCode(ReadUInt32(null));
        public QualifiedName ReadQualifiedName(string? fieldName)
        {
            ushort namespaceIndex = ReadUInt16(null);
            string? name = ReadString(null);
            return new QualifiedName(name, namespaceIndex);
        }
        public LocalizedText ReadLocalizedText(string? fieldName)
        {
            long branch = m_reader.ReadLong();
            if (branch == 0) return LocalizedText.Null;
            ExpectBranch(branch, 1);
            return new LocalizedText(ReadString(null), ReadString(null));
        }
        public DiagnosticInfo? ReadDiagnosticInfo(string? fieldName)
        {
            long branch = m_reader.ReadLong();
            if (branch == 0) return null;
            ExpectBranch(branch, 1);
            var d = new DiagnosticInfo();
            d.SymbolicId = ReadNullableValue(() => ReadInt32(null), -1);
            d.NamespaceUri = ReadNullableValue(() => ReadInt32(null), -1);
            d.Locale = ReadNullableValue(() => ReadInt32(null), -1);
            d.LocalizedText = ReadNullableValue(() => ReadInt32(null), -1);
            d.AdditionalInfo = ReadString(null);
            d.InnerStatusCode = ReadNullableValue(() => ReadStatusCode(null), StatusCodes.Good);
            d.InnerDiagnosticInfo = ReadDiagnosticInfo(null);
            return d;
        }
        public DataValue ReadDataValue(string? fieldName)
        {
            Variant value = ReadNullableValue(() => ReadVariant(null), Variant.Null);
            StatusCode status = ReadNullableValue(() => ReadStatusCode(null), StatusCodes.Good);
            DateTimeUtc sourceTs = ReadNullableValue(() => ReadDateTime(null), DateTimeUtc.MinValue);
            ushort sourcePs = ReadNullableValue(() => ReadUInt16(null), (ushort)0);
            DateTimeUtc serverTs = ReadNullableValue(() => ReadDateTime(null), DateTimeUtc.MinValue);
            ushort serverPs = ReadNullableValue(() => ReadUInt16(null), (ushort)0);
            if (value.IsNull && status.Equals(StatusCodes.Good, StatusCodeComparison.AllBits) && sourceTs.IsNull && serverTs.IsNull && sourcePs == 0 && serverPs == 0)
            {
                return DataValue.Null;
            }
            return new DataValue(value, status, sourceTs, serverTs, sourcePs, serverPs);
        }
        public ExtensionObject ReadExtensionObject(string? fieldName)
        {
            ExpandedNodeId typeId = ReadExpandedNodeId(null);
            long branch = m_reader.ReadLong();
            if (branch == 0) return new ExtensionObject(typeId);
            if (branch == 1)
            {
                if (!Context.Factory.TryGetEncodeableType(typeId, out IEncodeableType? activator))
                {
                    throw new NotSupportedException($"Cannot decode Avro ExtensionObject body for unregistered type {typeId}.");
                }
                IEncodeable body = activator.CreateInstance();
                body.Decode(this);
                return new ExtensionObject(typeId, body);
            }
            if (branch == 2) return new ExtensionObject(typeId, ByteString.From(m_reader.ReadBytes()));
            if (branch == 3) return new ExtensionObject(typeId, XmlElement.From(m_reader.ReadString()));
            throw new FormatException($"Invalid ExtensionObject Avro body branch {branch}.");
        }

        public T ReadEncodeable<T>(string? fieldName, ExpandedNodeId encodeableTypeId) where T : IEncodeable
        {
            if (!Context.Factory.TryGetEncodeableType(encodeableTypeId, out IEncodeableType? activator)) throw new NotSupportedException($"Cannot decode type {encodeableTypeId}.");
            var value = (T)activator.CreateInstance(); value.Decode(this); return value;
        }
        public T ReadEncodeable<T>(string? fieldName) where T : IEncodeable, new() { var value = new T(); value.Decode(this); return value; }
        public T ReadEncodeableAsExtensionObject<T>(string? fieldName) where T : IEncodeable { ExtensionObject eo = ReadExtensionObject(fieldName); return eo.TryGetValue(out T? value) ? value! : default!; }
        public T ReadEnumerated<T>(string? fieldName) where T : struct, Enum => EnumHelper.Int32ToEnum<T>(ReadInt32(fieldName));
        public EnumValue ReadEnumerated(string? fieldName) => EnumValue.From(ReadInt32(fieldName));
        public uint ReadSwitchField(IList<string> switches, out string? fieldName) { fieldName = null; return ReadUInt32("switch"); }
        public uint ReadEncodingMask(IList<string> masks) => ReadUInt32("encodingMask");
        public bool HasField(string fieldName) => true;

        private T? ReadNullable<T>(Func<T> read) where T : class { long b = m_reader.ReadLong(); if (b == 0) return null; ExpectBranch(b, 1); return read(); }
        private T ReadNullableValue<T>(Func<T> read, T defaultValue) { long b = m_reader.ReadLong(); if (b == 0) return defaultValue; ExpectBranch(b, 1); return read(); }
        private static void ExpectBranch(long actual, long expected) { if (actual != expected) throw new FormatException($"Unexpected Avro union branch {actual}; expected {expected}."); }
        private ArrayOf<T> ReadArray<T>(Func<T> read)
        {
            long branch = m_reader.ReadLong();
            if (branch == 0) return default;
            ExpectBranch(branch, 1);
            var values = new List<T>();
            while (true)
            {
                long count = m_reader.ReadLong();
                if (count == 0) break;
                if (count < 0) { _ = m_reader.ReadLong(); count = -count; }
                for (long i = 0; i < count; i++) values.Add(read());
            }
            return values.ToArray();
        }
        private MatrixOf<T> ReadMatrix<T>(Func<ArrayOf<T>> readArray)
        {
            long branch = m_reader.ReadLong();
            if (branch == 0) return default;
            ExpectBranch(branch, 1);
            int[] dims = ReadInt32Array(null).ToArray() ?? Array.Empty<int>();
            return readArray().ToMatrix(dims);
        }

        public ArrayOf<bool> ReadBooleanArray(string? fieldName) => ReadArray(() => ReadBoolean(null));
        public ArrayOf<sbyte> ReadSByteArray(string? fieldName) => ReadArray(() => ReadSByte(null));
        public ArrayOf<byte> ReadByteArray(string? fieldName) => ReadArray(() => ReadByte(null));
        public ArrayOf<short> ReadInt16Array(string? fieldName) => ReadArray(() => ReadInt16(null));
        public ArrayOf<ushort> ReadUInt16Array(string? fieldName) => ReadArray(() => ReadUInt16(null));
        public ArrayOf<int> ReadInt32Array(string? fieldName) => ReadArray(() => ReadInt32(null));
        public ArrayOf<uint> ReadUInt32Array(string? fieldName) => ReadArray(() => ReadUInt32(null));
        public ArrayOf<long> ReadInt64Array(string? fieldName) => ReadArray(() => ReadInt64(null));
        public ArrayOf<ulong> ReadUInt64Array(string? fieldName) => ReadArray(() => ReadUInt64(null));
        public ArrayOf<float> ReadFloatArray(string? fieldName) => ReadArray(() => ReadFloat(null));
        public ArrayOf<double> ReadDoubleArray(string? fieldName) => ReadArray(() => ReadDouble(null));
        public ArrayOf<string?> ReadStringArray(string? fieldName) => ReadArray(() => ReadString(null));
        public ArrayOf<DateTimeUtc> ReadDateTimeArray(string? fieldName) => ReadArray(() => ReadDateTime(null));
        public ArrayOf<Uuid> ReadGuidArray(string? fieldName) => ReadArray(() => ReadGuid(null));
        public ArrayOf<ByteString> ReadByteStringArray(string? fieldName) => ReadArray(() => ReadByteString(null));
        public ArrayOf<XmlElement> ReadXmlElementArray(string? fieldName) => ReadArray(() => ReadXmlElement(null));
        public ArrayOf<NodeId> ReadNodeIdArray(string? fieldName) => ReadArray(() => ReadNodeId(null));
        public ArrayOf<ExpandedNodeId> ReadExpandedNodeIdArray(string? fieldName) => ReadArray(() => ReadExpandedNodeId(null));
        public ArrayOf<StatusCode> ReadStatusCodeArray(string? fieldName) => ReadArray(() => ReadStatusCode(null));
        public ArrayOf<DiagnosticInfo?> ReadDiagnosticInfoArray(string? fieldName) => ReadArray(() => ReadDiagnosticInfo(null));
        public ArrayOf<QualifiedName> ReadQualifiedNameArray(string? fieldName) => ReadArray(() => ReadQualifiedName(null));
        public ArrayOf<LocalizedText> ReadLocalizedTextArray(string? fieldName) => ReadArray(() => ReadLocalizedText(null));
        public ArrayOf<Variant> ReadVariantArray(string? fieldName) => ReadArray(() => ReadVariant(null));
        public ArrayOf<DataValue> ReadDataValueArray(string? fieldName) => ReadArray(() => ReadDataValue(null));
        public ArrayOf<ExtensionObject> ReadExtensionObjectArray(string? fieldName) => ReadArray(() => ReadExtensionObject(null));
        public ArrayOf<T> ReadEncodeableArray<T>(string? fieldName) where T : IEncodeable, new() => ReadArray(() => ReadEncodeable<T>(null));
        public ArrayOf<T> ReadEncodeableArray<T>(string? fieldName, ExpandedNodeId encodeableTypeId) where T : IEncodeable => ReadArray(() => ReadEncodeable<T>(null, encodeableTypeId));
        public ArrayOf<T> ReadEncodeableArrayAsExtensionObjects<T>(string? fieldName) where T : IEncodeable => ReadArray(() => ReadEncodeableAsExtensionObject<T>(null));
        public MatrixOf<T> ReadEncodeableMatrix<T>(string? fieldName, ExpandedNodeId encodeableTypeId) where T : IEncodeable => ReadMatrix(() => ReadEncodeableArray<T>(null, encodeableTypeId));
        public MatrixOf<T> ReadEncodeableMatrix<T>(string? fieldName) where T : IEncodeable, new() => ReadMatrix(() => ReadEncodeableArray<T>(null));
        public ArrayOf<T> ReadEnumeratedArray<T>(string? fieldName) where T : struct, Enum => ReadArray(() => ReadEnumerated<T>(null));
        public ArrayOf<EnumValue> ReadEnumeratedArray(string? fieldName) => ReadArray(() => ReadEnumerated(null));
    }
}



