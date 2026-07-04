using System;
#pragma warning disable RCS0056, RCS1007, RCS1078, CA1816, CA2000, CS0618
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Apache.Arrow;
using Apache.Arrow.Arrays;
using Apache.Arrow.Ipc;
using Apache.Arrow.Memory;
using Apache.Arrow.Types;

namespace Opc.Ua.Core.Experimental
{
    public sealed class ArrowEncoder : IEncoder
    {
        internal const string ValueName = "value";
        internal const string SwitchName = "__switch";
        internal const string MaskName = "__encodingMask";
        private readonly Stream _stream;
        private readonly bool _ownsStream;
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);
        private bool _closed;

        public ArrowEncoder(IServiceMessageContext context) : this(new MemoryStream(), context, false) { }
        public ArrowEncoder(Stream stream, IServiceMessageContext context, bool leaveOpen = true)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            Context = context ?? throw new ArgumentNullException(nameof(context));
            _ownsStream = !leaveOpen;
        }

        public EncodingType EncodingType => EncodingType.Binary;
        public bool CanOmitFields => false;
        public IServiceMessageContext Context { get; }
        public void Dispose() { if (!_closed) { Close(); } if (_ownsStream) { _stream.Dispose(); } }
        public void PushNamespace(string namespaceUri) { }
        public void PopNamespace() { }
        public void SetMappingTables(NamespaceTable namespaceUris, StringTable serverUris) { }

        public int Close()
        {
            if (_closed) { throw new ObjectDisposedException(nameof(ArrowEncoder)); }
            long start = _stream.CanSeek ? _stream.Position : 0;
            var schema = new Apache.Arrow.Schema.Builder().Metadata("opcua-arrow", "1");
            var arrays = new List<IArrowArray>();
            foreach (var item in _slots)
            {
                schema.Field(item.Value.Field(item.Key));
                arrays.Add(item.Value.Array);
            }
            Apache.Arrow.Schema built = schema.Build();
            using var batch = new RecordBatch(built, arrays, 1);
            using var writer = new ArrowStreamWriter(_stream, built, leaveOpen: true);
            writer.WriteStart();
            writer.WriteRecordBatch(batch);
            writer.WriteEnd();
            _closed = true;
            return _stream.CanSeek ? checked((int)(_stream.Position - start)) : 0;
        }

        public string? CloseAndReturnText() => Convert.ToBase64String(CloseAndReturnBuffer());
        public byte[] CloseAndReturnBuffer()
        {
            Close();
            if (_stream is MemoryStream ms) { return ms.ToArray(); }
            throw new NotSupportedException("ArrowEncoder can only return bytes when backed by a MemoryStream.");
        }

        private void Put(string? name, Slot slot) => _slots[name ?? ValueName] = slot;
        private static NotSupportedException Unsupported(string member) => new($"OPC UA Arrow reference encoder does not yet support {member}.");

        public void EncodeMessage<T>(T message) where T : IEncodeable, new() => WriteEncodeable(ValueName, message);
        public void EncodeMessage<T>(T message, ExpandedNodeId encodeableTypeId) where T : IEncodeable => WriteEncodeable(ValueName, message, encodeableTypeId);
        public void WriteBoolean(string? fieldName, bool value) => Put(fieldName, A.Bool(value));
        public void WriteSByte(string? fieldName, sbyte value) => Put(fieldName, A.I8(value));
        public void WriteByte(string? fieldName, byte value) => Put(fieldName, A.U8(value));
        public void WriteInt16(string? fieldName, short value) => Put(fieldName, A.I16(value));
        public void WriteUInt16(string? fieldName, ushort value) => Put(fieldName, A.U16(value));
        public void WriteInt32(string? fieldName, int value) => Put(fieldName, A.I32(value));
        public void WriteUInt32(string? fieldName, uint value) => Put(fieldName, A.U32(value));
        public void WriteInt64(string? fieldName, long value) => Put(fieldName, A.I64(value));
        public void WriteUInt64(string? fieldName, ulong value) => Put(fieldName, A.U64(value));
        public void WriteFloat(string? fieldName, float value) => Put(fieldName, A.F32(value));
        public void WriteDouble(string? fieldName, double value) => Put(fieldName, A.F64(value));
        public void WriteString(string? fieldName, string? value) => Put(fieldName, A.Str(value));
        public void WriteDateTime(string? fieldName, DateTimeUtc value) => Put(fieldName, A.DateTime(value));
        public void WriteGuid(string? fieldName, Uuid value) => Put(fieldName, A.Guid(value));
        public void WriteByteString(string? fieldName, ByteString value) => Put(fieldName, A.Bytes(value));
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
        public void WriteByteString(string? fieldName, ReadOnlySpan<byte> value) => WriteByteString(fieldName, ByteString.From(value));
#endif
        public void WriteXmlElement(string? fieldName, XmlElement value) => Put(fieldName, A.Str(value.OuterXml));
        public void WriteNodeId(string? fieldName, NodeId value) => Put(fieldName, A.NodeId(value));
        public void WriteExpandedNodeId(string? fieldName, ExpandedNodeId value) => Put(fieldName, A.ExpandedNodeId(value));
        public void WriteStatusCode(string? fieldName, StatusCode value) => Put(fieldName, A.Status(value));
        public void WriteDiagnosticInfo(string? fieldName, DiagnosticInfo? value) => Put(fieldName, A.Diagnostic(value));
        public void WriteQualifiedName(string? fieldName, QualifiedName value) => Put(fieldName, A.QualifiedName(value));
        public void WriteLocalizedText(string? fieldName, LocalizedText value) => Put(fieldName, A.LocalizedText(value));
        public void WriteVariant(string? fieldName, in Variant value) { Variant v = value; Put(fieldName, A.Variant(v)); }
        public void WriteDataValue(string? fieldName, in DataValue value) { DataValue v = value; Put(fieldName, A.DataValue(v)); }
        public void WriteExtensionObject(string? fieldName, ExtensionObject value) => Put(fieldName, A.Extension(value));
        public void WriteEncodeable<T>(string? fieldName, T value) where T : IEncodeable, new() => throw Unsupported(nameof(WriteEncodeable));
        public void WriteEncodeable<T>(string? fieldName, T value, ExpandedNodeId encodeableTypeId) where T : IEncodeable => throw Unsupported(nameof(WriteEncodeable));
        public void WriteEncodeableAsExtensionObject<T>(string? fieldName, T value) where T : IEncodeable => WriteExtensionObject(fieldName, new ExtensionObject(value));
        public void WriteEnumerated<T>(string? fieldName, T value) where T : struct, Enum => WriteInt32(fieldName, Convert.ToInt32(value, CultureInfo.InvariantCulture));
        public void WriteEnumerated(string? fieldName, EnumValue value) => WriteInt32(fieldName, value.Value);
        public void WriteBooleanArray(string? fieldName, ArrayOf<bool> values) => Put(fieldName, A.List(values, A.BoolMany));
        public void WriteSByteArray(string? fieldName, ArrayOf<sbyte> values) => Put(fieldName, A.List(values, A.I8Many));
        public void WriteByteArray(string? fieldName, ArrayOf<byte> values) => Put(fieldName, A.List(values, A.U8Many));
        public void WriteInt16Array(string? fieldName, ArrayOf<short> values) => Put(fieldName, A.List(values, A.I16Many));
        public void WriteUInt16Array(string? fieldName, ArrayOf<ushort> values) => Put(fieldName, A.List(values, A.U16Many));
        public void WriteInt32Array(string? fieldName, ArrayOf<int> values) => Put(fieldName, A.List(values, A.I32Many));
        public void WriteUInt32Array(string? fieldName, ArrayOf<uint> values) => Put(fieldName, A.List(values, A.U32Many));
        public void WriteInt64Array(string? fieldName, ArrayOf<long> values) => Put(fieldName, A.List(values, A.I64Many));
        public void WriteUInt64Array(string? fieldName, ArrayOf<ulong> values) => Put(fieldName, A.List(values, A.U64Many));
        public void WriteFloatArray(string? fieldName, ArrayOf<float> values) => Put(fieldName, A.List(values, A.F32Many));
        public void WriteDoubleArray(string? fieldName, ArrayOf<double> values) => Put(fieldName, A.List(values, A.F64Many));
        public void WriteStringArray(string? fieldName, ArrayOf<string> values) => Put(fieldName, A.List(values, A.StrMany));
        public void WriteDateTimeArray(string? fieldName, ArrayOf<DateTimeUtc> values) => Put(fieldName, A.List(values, A.DateTimeMany));
        public void WriteGuidArray(string? fieldName, ArrayOf<Uuid> values) => Put(fieldName, A.List(values, A.GuidMany));
        public void WriteByteStringArray(string? fieldName, ArrayOf<ByteString> values) => Put(fieldName, A.List(values, A.BytesMany));
        public void WriteXmlElementArray(string? fieldName, ArrayOf<XmlElement> values) => Put(fieldName, A.List(values.ConvertAll<string>(x => x.OuterXml!), A.StrMany));
        public void WriteNodeIdArray(string? fieldName, ArrayOf<NodeId> values) => Put(fieldName, A.ListStruct(values, A.NodeId));
        public void WriteExpandedNodeIdArray(string? fieldName, ArrayOf<ExpandedNodeId> values) => Put(fieldName, A.ListStruct(values, A.ExpandedNodeId));
        public void WriteStatusCodeArray(string? fieldName, ArrayOf<StatusCode> values) => Put(fieldName, A.List(values.ConvertAll(x => x.Code), A.U32Many));
        public void WriteDiagnosticInfoArray(string? fieldName, ArrayOf<DiagnosticInfo> values) => Put(fieldName, A.ListStruct(values, A.Diagnostic));
        public void WriteQualifiedNameArray(string? fieldName, ArrayOf<QualifiedName> values) => Put(fieldName, A.ListStruct(values, A.QualifiedName));
        public void WriteLocalizedTextArray(string? fieldName, ArrayOf<LocalizedText> values) => Put(fieldName, A.ListStruct(values, A.LocalizedText));
        public void WriteVariantArray(string? fieldName, ArrayOf<Variant> values) => Put(fieldName, A.ListStruct(values, A.Variant));
        public void WriteDataValueArray(string? fieldName, ArrayOf<DataValue> values) => Put(fieldName, A.ListStruct(values, A.DataValue));
        public void WriteExtensionObjectArray(string? fieldName, ArrayOf<ExtensionObject> values) => Put(fieldName, A.ListStruct(values, A.Extension));
        public void WriteEncodeableArray<T>(string? fieldName, ArrayOf<T> values) where T : IEncodeable, new() => throw Unsupported(nameof(WriteEncodeableArray));
        public void WriteEncodeableArray<T>(string? fieldName, ArrayOf<T> values, ExpandedNodeId encodeableTypeId) where T : IEncodeable => throw Unsupported(nameof(WriteEncodeableArray));
        public void WriteEncodeableArrayAsExtensionObjects<T>(string? fieldName, ArrayOf<T> values) where T : IEncodeable => WriteExtensionObjectArray(fieldName, values.ConvertAll(x => new ExtensionObject(x)));
        public void WriteEnumeratedArray<T>(string? fieldName, ArrayOf<T> values) where T : struct, Enum => WriteInt32Array(fieldName, values.ConvertAll(x => Convert.ToInt32(x, CultureInfo.InvariantCulture)));
        public void WriteEnumeratedArray(string? fieldName, ArrayOf<EnumValue> values) => WriteInt32Array(fieldName, values.ConvertAll(x => x.Value));
        public void WriteVariantValue(string? fieldName, in Variant value) { Variant v = value; Put(fieldName, A.Variant(v)); }
        public void WriteEncodeableMatrix<T>(string? fieldName, MatrixOf<T> values) where T : IEncodeable, new() => throw Unsupported(nameof(WriteEncodeableMatrix));
        public void WriteEncodeableMatrix<T>(string? fieldName, MatrixOf<T> values, ExpandedNodeId encodeableTypeId) where T : IEncodeable => throw Unsupported(nameof(WriteEncodeableMatrix));
        public void WriteSwitchField(uint switchField, out string? fieldName) { fieldName = null; WriteUInt32(SwitchName, switchField); }
        public void WriteEncodingMask(uint encodingMask) => WriteUInt32(MaskName, encodingMask);
    }

    public sealed class ArrowDecoder : IDecoder
    {
        private readonly RecordBatch _batch;
        private readonly Dictionary<string, int> _columns = new(StringComparer.Ordinal);
        private bool _closed;

        public ArrowDecoder(byte[] buffer, IServiceMessageContext context) : this(new MemoryStream(buffer, false), context) { }
        public ArrowDecoder(ReadOnlyMemory<byte> buffer, IServiceMessageContext context) : this(buffer.ToArray(), context) { }
        public ArrowDecoder(Stream stream, IServiceMessageContext context)
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
            using var reader = new ArrowStreamReader(stream ?? throw new ArgumentNullException(nameof(stream)), leaveOpen: true);
            _batch = reader.ReadNextRecordBatch() ?? throw new FormatException("Arrow stream contains no record batch.");
            for (int ii = 0; ii < _batch.Schema.FieldsList.Count; ii++) { _columns[_batch.Schema.GetFieldByIndex(ii).Name] = ii; }
        }

        public EncodingType EncodingType => EncodingType.Binary;
        public IServiceMessageContext Context { get; }
        public void Dispose() => Close();
        public void Close() { if (!_closed) { _batch.Dispose(); _closed = true; } }
        public void SetMappingTables(NamespaceTable namespaceUris, StringTable serverUris) { }
        public void PushNamespace(string namespaceUri) { }
        public void PopNamespace() { }
        private (Field Field, IArrowArray Array) Col(string? name)
        {
            if (_closed) { throw new ObjectDisposedException(nameof(ArrowDecoder)); }
            string key = name ?? ArrowEncoder.ValueName;
            if (!_columns.TryGetValue(key, out int index)) { throw new FormatException($"Arrow field '{key}' is not present."); }
            return (_batch.Schema.GetFieldByIndex(index), _batch.Column(index));
        }
        public T DecodeMessage<T>() where T : IEncodeable => throw new NotSupportedException("Arrow message decode is not supported yet.");
        public bool ReadBoolean(string? fieldName) => ((BooleanArray)Col(fieldName).Array).GetBoolean(0);
        public sbyte ReadSByte(string? fieldName) => ((Int8Array)Col(fieldName).Array).GetValue(0) ?? default;
        public byte ReadByte(string? fieldName) => ((UInt8Array)Col(fieldName).Array).GetValue(0) ?? default;
        public short ReadInt16(string? fieldName) => ((Int16Array)Col(fieldName).Array).GetValue(0) ?? default;
        public ushort ReadUInt16(string? fieldName) => ((UInt16Array)Col(fieldName).Array).GetValue(0) ?? default;
        public int ReadInt32(string? fieldName) => ((Int32Array)Col(fieldName).Array).GetValue(0) ?? default;
        public uint ReadUInt32(string? fieldName) => ((UInt32Array)Col(fieldName).Array).GetValue(0) ?? default;
        public long ReadInt64(string? fieldName) => ((Int64Array)Col(fieldName).Array).GetValue(0) ?? default;
        public ulong ReadUInt64(string? fieldName) => ((UInt64Array)Col(fieldName).Array).GetValue(0) ?? default;
        public float ReadFloat(string? fieldName) => ((FloatArray)Col(fieldName).Array).GetValue(0) ?? default;
        public double ReadDouble(string? fieldName) => ((DoubleArray)Col(fieldName).Array).GetValue(0) ?? default;
        public string? ReadString(string? fieldName) { var a = (StringArray)Col(fieldName).Array; return a.IsNull(0) ? null : a.GetString(0); }
        public DateTimeUtc ReadDateTime(string? fieldName) { var a = (Int64Array)Col(fieldName).Array; return a.IsNull(0) ? default : new DateTimeUtc(a.GetValue(0) ?? 0); }
        public Uuid ReadGuid(string? fieldName) => A.ReadGuid(Col(fieldName).Array, 0);
        public ByteString ReadByteString(string? fieldName) => A.ReadBytes(Col(fieldName).Array, 0);
        public XmlElement ReadXmlElement(string? fieldName) { string? xml = ReadString(fieldName); return xml == null ? default! : (XmlElement)xml; }
        public NodeId ReadNodeId(string? fieldName) => A.ReadNodeId(Col(fieldName).Array, 0);
        public ExpandedNodeId ReadExpandedNodeId(string? fieldName) => A.ReadExpandedNodeId(Col(fieldName).Array, 0);
        public StatusCode ReadStatusCode(string? fieldName) => new StatusCode(ReadUInt32(fieldName));
        public DiagnosticInfo? ReadDiagnosticInfo(string? fieldName) => A.ReadDiagnostic(Col(fieldName).Array, 0);
        public QualifiedName ReadQualifiedName(string? fieldName) => A.ReadQualifiedName(Col(fieldName).Array, 0);
        public LocalizedText ReadLocalizedText(string? fieldName) => A.ReadLocalizedText(Col(fieldName).Array, 0);
        public Variant ReadVariant(string? fieldName) => A.ReadVariant(Col(fieldName).Array, 0);
        public DataValue ReadDataValue(string? fieldName) => A.ReadDataValue(Col(fieldName).Array, 0);
        public ExtensionObject ReadExtensionObject(string? fieldName) => A.ReadExtension(Col(fieldName).Array, 0);
        public T ReadEncodeable<T>(string? fieldName, ExpandedNodeId encodeableTypeId) where T : IEncodeable => throw new NotSupportedException("Arrow encodeable decode by type id is not supported yet.");
        public T ReadEncodeable<T>(string? fieldName) where T : IEncodeable, new() => throw new NotSupportedException("Arrow encodeable decode is not supported yet.");
        public T ReadEncodeableAsExtensionObject<T>(string? fieldName) where T : IEncodeable => throw new NotSupportedException("Arrow abstract encodeable decode is not supported yet.");
        public T ReadEnumerated<T>(string? fieldName) where T : struct, Enum => (T)Enum.ToObject(typeof(T), ReadInt32(fieldName));
        public EnumValue ReadEnumerated(string? fieldName) => new EnumValue(ReadInt32(fieldName));
        public ArrayOf<bool> ReadBooleanArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadBoolMany);
        public ArrayOf<sbyte> ReadSByteArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadI8Many);
        public ArrayOf<byte> ReadByteArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadU8Many);
        public ArrayOf<short> ReadInt16Array(string? fieldName) => A.ReadList(Col(fieldName), A.ReadI16Many);
        public ArrayOf<ushort> ReadUInt16Array(string? fieldName) => A.ReadList(Col(fieldName), A.ReadU16Many);
        public ArrayOf<int> ReadInt32Array(string? fieldName) => A.ReadList(Col(fieldName), A.ReadI32Many);
        public ArrayOf<uint> ReadUInt32Array(string? fieldName) => A.ReadList(Col(fieldName), A.ReadU32Many);
        public ArrayOf<long> ReadInt64Array(string? fieldName) => A.ReadList(Col(fieldName), A.ReadI64Many);
        public ArrayOf<ulong> ReadUInt64Array(string? fieldName) => A.ReadList(Col(fieldName), A.ReadU64Many);
        public ArrayOf<float> ReadFloatArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadF32Many);
        public ArrayOf<double> ReadDoubleArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadF64Many);
        public ArrayOf<string?> ReadStringArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadStrMany);
        public ArrayOf<DateTimeUtc> ReadDateTimeArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadDateTimeMany);
        public ArrayOf<Uuid> ReadGuidArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadGuidMany);
        public ArrayOf<ByteString> ReadByteStringArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadBytesMany);
        public ArrayOf<XmlElement> ReadXmlElementArray(string? fieldName) => ReadStringArray(fieldName).ConvertAll(x => x == null ? default! : (XmlElement)x);
        public ArrayOf<NodeId> ReadNodeIdArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadNodeIdMany);
        public ArrayOf<ExpandedNodeId> ReadExpandedNodeIdArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadExpandedNodeIdMany);
        public ArrayOf<StatusCode> ReadStatusCodeArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadStatusMany);
        public ArrayOf<DiagnosticInfo?> ReadDiagnosticInfoArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadDiagnosticMany);
        public ArrayOf<QualifiedName> ReadQualifiedNameArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadQualifiedNameMany);
        public ArrayOf<LocalizedText> ReadLocalizedTextArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadLocalizedTextMany);
        public ArrayOf<Variant> ReadVariantArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadVariantMany);
        public ArrayOf<DataValue> ReadDataValueArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadDataValueMany);
        public ArrayOf<ExtensionObject> ReadExtensionObjectArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadExtensionMany);
        public ArrayOf<T> ReadEncodeableArray<T>(string? fieldName) where T : IEncodeable, new() => throw new NotSupportedException("Arrow encodeable arrays are not supported yet.");
        public ArrayOf<T> ReadEncodeableArray<T>(string? fieldName, ExpandedNodeId encodeableTypeId) where T : IEncodeable => throw new NotSupportedException("Arrow encodeable arrays are not supported yet.");
        public ArrayOf<T> ReadEncodeableArrayAsExtensionObjects<T>(string? fieldName) where T : IEncodeable => throw new NotSupportedException("Arrow abstract encodeable arrays are not supported yet.");
        public MatrixOf<T> ReadEncodeableMatrix<T>(string? fieldName, ExpandedNodeId encodeableTypeId) where T : IEncodeable => throw new NotSupportedException("Arrow encodeable matrices are not supported yet.");
        public MatrixOf<T> ReadEncodeableMatrix<T>(string? fieldName) where T : IEncodeable, new() => throw new NotSupportedException("Arrow encodeable matrices are not supported yet.");
        public ArrayOf<T> ReadEnumeratedArray<T>(string? fieldName) where T : struct, Enum => ReadInt32Array(fieldName).ConvertAll(x => (T)Enum.ToObject(typeof(T), x));
        public ArrayOf<EnumValue> ReadEnumeratedArray(string? fieldName) => ReadInt32Array(fieldName).ConvertAll(x => new EnumValue(x));
        public Variant ReadVariantValue(string? fieldName, TypeInfo typeInfo) => ReadVariant(fieldName);
        public uint ReadSwitchField(IList<string> switches, out string? fieldName) { fieldName = null; return ReadUInt32(ArrowEncoder.SwitchName); }
        public uint ReadEncodingMask(IList<string> masks) => HasField(ArrowEncoder.MaskName) ? ReadUInt32(ArrowEncoder.MaskName) : 0;
        public bool HasField(string fieldName) => _columns.ContainsKey(fieldName);
    }

    internal sealed record Slot(Field Template, IArrowArray Array)
    {
        public Field Field(string name) => new(name, Template.DataType, Template.IsNullable, Template.Metadata);
    }

    internal static class A
    {
        private static readonly MemoryAllocator Alloc = MemoryAllocator.Default.Value;
        private static Field F(string n, IArrowType t, bool nullable = true) => new(n, t, nullable, null);
        private static ArrowBuffer B<T>(params T[] values) where T : struct { var b = new ArrowBuffer.Builder<T>(values.Length); b.Append(values.AsSpan()); return b.Build(Alloc); }
        private static ArrowBuffer V(int length, bool valid) { var b = new ArrowBuffer.BitmapBuilder(length); b.AppendRange(valid, length); return b.Build(Alloc); }
        public static Slot Bool(bool v) { var b = new BooleanArray.Builder(); b.Append(v); return new(F("", BooleanType.Default, false), b.Build(Alloc)); }
        public static Slot I8(sbyte v) { var b = new Int8Array.Builder(); b.Append(v); return new(F("", Int8Type.Default, false), b.Build(Alloc)); }
        public static Slot U8(byte v) { var b = new UInt8Array.Builder(); b.Append(v); return new(F("", UInt8Type.Default, false), b.Build(Alloc)); }
        public static Slot I16(short v) { var b = new Int16Array.Builder(); b.Append(v); return new(F("", Int16Type.Default, false), b.Build(Alloc)); }
        public static Slot U16(ushort v) { var b = new UInt16Array.Builder(); b.Append(v); return new(F("", UInt16Type.Default, false), b.Build(Alloc)); }
        public static Slot I32(int v) { var b = new Int32Array.Builder(); b.Append(v); return new(F("", Int32Type.Default, false), b.Build(Alloc)); }
        public static Slot U32(uint v) { var b = new UInt32Array.Builder(); b.Append(v); return new(F("", UInt32Type.Default, false), b.Build(Alloc)); }
        public static Slot I64(long v) { var b = new Int64Array.Builder(); b.Append(v); return new(F("", Int64Type.Default, false), b.Build(Alloc)); }
        public static Slot U64(ulong v) { var b = new UInt64Array.Builder(); b.Append(v); return new(F("", UInt64Type.Default, false), b.Build(Alloc)); }
        public static Slot F32(float v) { var b = new FloatArray.Builder(); b.Append(v); return new(F("", FloatType.Default, false), b.Build(Alloc)); }
        public static Slot F64(double v) { var b = new DoubleArray.Builder(); b.Append(v); return new(F("", DoubleType.Default, false), b.Build(Alloc)); }
        public static Slot Str(string? v) { var b = new StringArray.Builder(); if (v == null) { b.AppendNull(); } else { b.Append(v); } return new(F("", StringType.Default), b.Build(Alloc)); }
        public static Slot DateTime(DateTimeUtc v) { var b = new Int64Array.Builder(); if (v.IsNull) { b.AppendNull(); } else { b.Append(v.Value); } return new(F("", Int64Type.Default), b.Build(Alloc)); }
        public static Slot Status(StatusCode v) { var b = new UInt32Array.Builder(); b.Append(v.Code); return new(F("", UInt32Type.Default, false), b.Build(Alloc)); }
        public static Slot Bytes(ByteString v) { var b = new BinaryArray.Builder(); if (v.IsNull) { b.AppendNull(); } else { b.Append(v.Span); } return new(F("", BinaryType.Default), b.Build(Alloc)); }
        public static Slot Guid(Uuid v) => GuidMany(new[] { v });
        public static Slot GuidMany(ReadOnlyMemory<Uuid> v) { var bytes = new List<byte>(); foreach (var x in v.Span) { bytes.AddRange(x.Guid.ToByteArray()); }         var a = new FixedSizeBinaryArray(new ArrayData(new FixedSizeBinaryType(16), v.Length, 0, 0, new[] { V(v.Length, true), B(bytes.ToArray()) }, System.Array.Empty<ArrayData>())); return new(F("", new FixedSizeBinaryType(16)), a); }
        public static Slot NodeId(NodeId v)
        {
            byte t = v.IsNull ? (byte)0 : (byte)v.IdType; uint n = !v.IsNull && v.IdType == IdType.Numeric ? (uint)v.Identifier : 0;
            string? s = !v.IsNull && v.IdType == IdType.String ? (string)v.Identifier : null;
            Uuid g = !v.IsNull && v.IdType == IdType.Guid ? new Uuid((Guid)v.Identifier) : default;
            ByteString o = !v.IsNull && v.IdType == IdType.Opaque ? (ByteString)v.Identifier : default;
            return Struct(new() { U16(v.NamespaceIndex), U8(t), U32(n), Str(s), Guid(g), Bytes(o) }, new() { "namespace", "id_type", "numeric", "string", "guid", "opaque" }, !v.IsNull);
        }
        public static Slot ExpandedNodeId(ExpandedNodeId v) => Struct(new() { NodeId(new NodeId(v.Identifier, v.NamespaceIndex)), Str(v.NamespaceUri), U32(v.ServerIndex) }, new() { "node_id", "namespace_uri", "server_index" }, !v.IsNull);
        public static Slot QualifiedName(QualifiedName v) => Struct(new() { U16(v.NamespaceIndex), Str(v.Name) }, new() { "namespace", "name" }, !v.IsNull);
        public static Slot LocalizedText(LocalizedText v) => Struct(new() { Str(v.Locale), Str(v.Text) }, new() { "locale", "text" }, !v.IsNull);
        public static Slot DataValue(DataValue v) => Struct(new() { Variant(v.WrappedValue), Status(v.StatusCode), DateTime(v.SourceTimestamp), U16(v.SourcePicoseconds), DateTime(v.ServerTimestamp), U16(v.ServerPicoseconds) }, new() { "value", "status", "source_timestamp", "source_picoseconds", "server_timestamp", "server_picoseconds" }, !v.IsNull);
        public static Slot Diagnostic(DiagnosticInfo? v) => v == null ?
            Struct(new() { I32(-1), I32(-1), I32(-1), I32(-1), Str(null), Status(StatusCodes.Good), Null() }, new() { "symbolic_id", "namespace_uri", "locale", "localized_text", "additional_info", "inner_status_code", "inner_diagnostic_info" }, false) :
            Struct(new() { I32(v.SymbolicId), I32(v.NamespaceUri), I32(v.Locale), I32(v.LocalizedText), Str(v.AdditionalInfo), Status(v.InnerStatusCode), Diagnostic(v.InnerDiagnosticInfo) }, new() { "symbolic_id", "namespace_uri", "locale", "localized_text", "additional_info", "inner_status_code", "inner_diagnostic_info" });
        public static Slot Extension(ExtensionObject v)
        {
            ByteString body = default; if (v.TryGetAsBinary(out ByteString b)) { body = b; }
            return Struct(new() { ExpandedNodeId(v.TypeId), Union(v.IsNull ? 0 : 1, new() { Null(), Bytes(body) }, new() { "null", "binary" }) }, new() { "type_id", "body" }, !v.IsNull);
        }
        public static Slot Null() { var b = new NullArray.Builder(); b.AppendNull(); return new(F("", NullType.Default), b.Build(Alloc)); }
        public static Slot Struct(List<Slot> children, List<string> names, bool valid = true)
        {
            var fields = children.Select((c, i) => c.Field(names[i])).ToList(); var t = new StructType(fields);
            return new(F("", t), new StructArray(t, 1, children.Select(c => c.Array), V(1, valid), valid ? 0 : 1, 0));
        }
        public static Slot Union(int selected, List<Slot> children, List<string> names)
        {
            var fields = children.Select((c, i) => c.Field(names[i])).ToList();
            // The dense-union type-ids buffer stores `selected`, so the declared union type-ids
            // must contain it or external Arrow readers (pyarrow/ADBC) cannot map a slot to its
            // child. When `selected` is a child index (e.g. the ExtensionObject body union) the
            // natural [0,1,..] mapping is correct; when it is an OPC BuiltInType code (Variant
            // union, whose value is always child 1) declare [0, selected].
            IEnumerable<int> typeIds = selected < fields.Count ? Enumerable.Range(0, fields.Count) : new[] { 0, selected };
            var t = new UnionType(fields, typeIds, UnionMode.Dense);
            return new(F("", t), new DenseUnionArray(t, 1, children.Select(c => c.Array), B((byte)selected), B(0), 0, 0));
        }
        public static Slot Variant(Variant v)
        {
            if (v.IsNull) { return Union(0, new() { Null() }, new() { "null" }); }
            if (v.TypeInfo.IsMatrix && v.TypeInfo.BuiltInType == BuiltInType.Int32)
            {
                return Union(21, new() { Null(), Matrix(v.GetInt32Matrix(), I32Many) }, new() { "null", "matrix_int32" });
            }
            object? x = v.Value;
            return x switch
            {
                int i => Union(6, new() { Null(), I32(i) }, new() { "null", "int32" }),
                string s => Union(12, new() { Null(), Str(s) }, new() { "null", "string" }),
                ExtensionObject e => Union(17, new() { Null(), Extension(e) }, new() { "null", "extensionobject" }),
                DataValue d => Union(18, new() { Null(), DataValue(d) }, new() { "null", "datavalue" }),
                MatrixOf<int> m => Union(21, new() { Null(), Matrix(m, I32Many) }, new() { "null", "matrix_int32" }),
                _ => throw new NotSupportedException($"Arrow Variant branch '{v.TypeInfo}' is not supported yet.")
            };
        }
        public static Slot Matrix<T>(MatrixOf<T> values, Func<ReadOnlyMemory<T>, Slot> elem) => Struct(new() { List(new ArrayOf<int>(values.Dimensions), I32Many), List(new ArrayOf<T>(values.Memory), elem) }, new() { "dimensions", "values" }, !values.IsNull);
        public static Slot List<T>(ArrayOf<T> values, Func<ReadOnlyMemory<T>, Slot> elem)
        {
            Slot child = elem(values.IsNull ? ReadOnlyMemory<T>.Empty : values.Memory); var t = new ListType(child.Field("item"));
            return new(F("", t), new ListArray(t, 1, B(0, values.IsNull ? 0 : values.Count), child.Array, V(1, !values.IsNull), values.IsNull ? 1 : 0, 0));
        }
        public static Slot ListStruct<T>(ArrayOf<T> values, Func<T, Slot> elem) => values.Count == 1 ? List(values, s => elem(s.Span[0])) : throw new NotSupportedException("Struct lists currently support one element.");
        public static Slot BoolMany(ReadOnlyMemory<bool> v) { var b = new BooleanArray.Builder(); foreach (bool x in v.Span) { b.Append(x); } return new(F("", BooleanType.Default), b.Build(Alloc)); }
        public static Slot I8Many(ReadOnlyMemory<sbyte> v) { var b = new Int8Array.Builder(); foreach (sbyte x in v.Span) { b.Append(x); } return new(F("", Int8Type.Default), b.Build(Alloc)); }
        public static Slot U8Many(ReadOnlyMemory<byte> v) { var b = new UInt8Array.Builder(); foreach (byte x in v.Span) { b.Append(x); } return new(F("", UInt8Type.Default), b.Build(Alloc)); }
        public static Slot I16Many(ReadOnlyMemory<short> v) { var b = new Int16Array.Builder(); foreach (short x in v.Span) { b.Append(x); } return new(F("", Int16Type.Default), b.Build(Alloc)); }
        public static Slot U16Many(ReadOnlyMemory<ushort> v) { var b = new UInt16Array.Builder(); foreach (ushort x in v.Span) { b.Append(x); } return new(F("", UInt16Type.Default), b.Build(Alloc)); }
        public static Slot I32Many(ReadOnlyMemory<int> v) { var b = new Int32Array.Builder(); foreach (int x in v.Span) { b.Append(x); } return new(F("", Int32Type.Default), b.Build(Alloc)); }
        public static Slot U32Many(ReadOnlyMemory<uint> v) { var b = new UInt32Array.Builder(); foreach (uint x in v.Span) { b.Append(x); } return new(F("", UInt32Type.Default), b.Build(Alloc)); }
        public static Slot I64Many(ReadOnlyMemory<long> v) { var b = new Int64Array.Builder(); foreach (long x in v.Span) { b.Append(x); } return new(F("", Int64Type.Default), b.Build(Alloc)); }
        public static Slot U64Many(ReadOnlyMemory<ulong> v) { var b = new UInt64Array.Builder(); foreach (ulong x in v.Span) { b.Append(x); } return new(F("", UInt64Type.Default), b.Build(Alloc)); }
        public static Slot F32Many(ReadOnlyMemory<float> v) { var b = new FloatArray.Builder(); foreach (float x in v.Span) { b.Append(x); } return new(F("", FloatType.Default), b.Build(Alloc)); }
        public static Slot F64Many(ReadOnlyMemory<double> v) { var b = new DoubleArray.Builder(); foreach (double x in v.Span) { b.Append(x); } return new(F("", DoubleType.Default), b.Build(Alloc)); }
        public static Slot StrMany(ReadOnlyMemory<string> v) { var b = new StringArray.Builder(); foreach (string x in v.Span) { if (x == null) { b.AppendNull(); } else { b.Append(x); } } return new(F("", StringType.Default), b.Build(Alloc)); }
        public static Slot DateTimeMany(ReadOnlyMemory<DateTimeUtc> v) { var b = new Int64Array.Builder(); foreach (DateTimeUtc x in v.Span) { if (x.IsNull) { b.AppendNull(); } else { b.Append(x.Value); } } return new(F("", Int64Type.Default), b.Build(Alloc)); }
        public static Slot BytesMany(ReadOnlyMemory<ByteString> v) { var b = new BinaryArray.Builder(); foreach (ByteString x in v.Span) { if (x.IsNull) { b.AppendNull(); } else { b.Append(x.Span); } } return new(F("", BinaryType.Default), b.Build(Alloc)); }
        public static Uuid ReadGuid(IArrowArray a, int i) => new(((FixedSizeBinaryArray)a).GetBytes(i).ToArray());
        public static ByteString ReadBytes(IArrowArray a, int i) => ((BinaryArray)a).IsNull(i) ? default : ByteString.From(((BinaryArray)a).GetBytes(i).ToArray());
        public static Opc.Ua.NodeId ReadNodeId(IArrowArray a, int i) { var s = (StructArray)a; if (s.IsNull(i)) { return Opc.Ua.NodeId.Null; } ushort ns = ((UInt16Array)s.Fields[0]).GetValue(i) ?? 0; byte t = ((UInt8Array)s.Fields[1]).GetValue(i) ?? 0; return (IdType)t switch { IdType.String => new Opc.Ua.NodeId(((StringArray)s.Fields[3]).GetString(i), ns), IdType.Guid => new Opc.Ua.NodeId(ReadGuid(s.Fields[4], i).Guid, ns), IdType.Opaque => new Opc.Ua.NodeId(ReadBytes(s.Fields[5], i), ns), _ => new Opc.Ua.NodeId(((UInt32Array)s.Fields[2]).GetValue(i) ?? 0, ns) }; }
        public static ExpandedNodeId ReadExpandedNodeId(IArrowArray a, int i) { var s = (StructArray)a; return new ExpandedNodeId(ReadNodeId(s.Fields[0], i), ((StringArray)s.Fields[1]).IsNull(i) ? null : ((StringArray)s.Fields[1]).GetString(i), ((UInt32Array)s.Fields[2]).GetValue(i) ?? 0); }
        public static QualifiedName ReadQualifiedName(IArrowArray a, int i) { var s = (StructArray)a; return new QualifiedName(((StringArray)s.Fields[1]).IsNull(i) ? null : ((StringArray)s.Fields[1]).GetString(i), ((UInt16Array)s.Fields[0]).GetValue(i) ?? 0); }
        public static LocalizedText ReadLocalizedText(IArrowArray a, int i) { var s = (StructArray)a; return new LocalizedText(((StringArray)s.Fields[0]).IsNull(i) ? null : ((StringArray)s.Fields[0]).GetString(i), ((StringArray)s.Fields[1]).IsNull(i) ? null : ((StringArray)s.Fields[1]).GetString(i)); }
        public static DataValue ReadDataValue(IArrowArray a, int i) { var s = (StructArray)a; return new DataValue(ReadVariant(s.Fields[0], i), new StatusCode(((UInt32Array)s.Fields[1]).GetValue(i) ?? 0), new DateTimeUtc(((Int64Array)s.Fields[2]).GetValue(i) ?? 0), new DateTimeUtc(((Int64Array)s.Fields[4]).GetValue(i) ?? 0), ((UInt16Array)s.Fields[3]).GetValue(i) ?? 0, ((UInt16Array)s.Fields[5]).GetValue(i) ?? 0); }
        public static DiagnosticInfo? ReadDiagnostic(IArrowArray a, int i) { var s = (StructArray)a; if (s.IsNull(i)) { return null; } return new DiagnosticInfo { SymbolicId = ((Int32Array)s.Fields[0]).GetValue(i) ?? -1, NamespaceUri = ((Int32Array)s.Fields[1]).GetValue(i) ?? -1, Locale = ((Int32Array)s.Fields[2]).GetValue(i) ?? -1, LocalizedText = ((Int32Array)s.Fields[3]).GetValue(i) ?? -1, AdditionalInfo = ((StringArray)s.Fields[4]).IsNull(i) ? null : ((StringArray)s.Fields[4]).GetString(i), InnerStatusCode = new StatusCode(((UInt32Array)s.Fields[5]).GetValue(i) ?? 0), InnerDiagnosticInfo = ReadDiagnostic(s.Fields[6], i) }; }
        public static ExtensionObject ReadExtension(IArrowArray a, int i) { var s = (StructArray)a; if (s.IsNull(i)) { return ExtensionObject.Null; } var u = (DenseUnionArray)s.Fields[1]; return u.TypeIds[i] == 1 ? new ExtensionObject(ReadExpandedNodeId(s.Fields[0], i), ReadBytes(u.Fields[1], u.ValueOffsets[i])) : new ExtensionObject(ReadExpandedNodeId(s.Fields[0], i)); }
        public static Opc.Ua.Variant ReadVariant(IArrowArray a, int i) { var u = (DenseUnionArray)a; int code = u.TypeIds[i]; int off = u.ValueOffsets[i]; return code switch { 0 => Opc.Ua.Variant.Null, 6 => new Opc.Ua.Variant(((Int32Array)u.Fields[1]).GetValue(off) ?? 0), 12 => new Opc.Ua.Variant(((StringArray)u.Fields[1]).GetString(off)), 17 => new Opc.Ua.Variant(ReadExtension(u.Fields[1], off)), 18 => new Opc.Ua.Variant(ReadDataValue(u.Fields[1], off)), 21 => new Opc.Ua.Variant(ReadMatrixInt32(u.Fields[1], off)), _ => throw new NotSupportedException($"Unknown Variant union code {code}.") }; }
        private static MatrixOf<int> ReadMatrixInt32(IArrowArray a, int i) { var s = (StructArray)a; var dims = ReadList((null!, s.Fields[0]), ReadI32Many); var vals = ReadList((null!, s.Fields[1]), ReadI32Many); return vals.ToMatrix(dims); }
        public static ArrayOf<T> ReadList<T>((Field Field, IArrowArray Array) c, Func<IArrowArray, int, int, T[]> read) { var l = (ListArray)c.Array; if (l.IsNull(0)) { return ArrayOf<T>.Null; } return new ArrayOf<T>(read(l.Values, l.ValueOffsets[0], l.ValueOffsets[1] - l.ValueOffsets[0])); }
        public static bool[] ReadBoolMany(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ((BooleanArray)a).GetBoolean(i)).ToArray();
        public static sbyte[] ReadI8Many(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ((Int8Array)a).GetValue(i) ?? 0).ToArray();
        public static byte[] ReadU8Many(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ((UInt8Array)a).GetValue(i) ?? 0).ToArray();
        public static short[] ReadI16Many(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ((Int16Array)a).GetValue(i) ?? 0).ToArray();
        public static ushort[] ReadU16Many(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ((UInt16Array)a).GetValue(i) ?? 0).ToArray();
        public static int[] ReadI32Many(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ((Int32Array)a).GetValue(i) ?? 0).ToArray();
        public static uint[] ReadU32Many(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ((UInt32Array)a).GetValue(i) ?? 0).ToArray();
        public static long[] ReadI64Many(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ((Int64Array)a).GetValue(i) ?? 0).ToArray();
        public static ulong[] ReadU64Many(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ((UInt64Array)a).GetValue(i) ?? 0).ToArray();
        public static float[] ReadF32Many(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ((FloatArray)a).GetValue(i) ?? 0).ToArray();
        public static double[] ReadF64Many(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ((DoubleArray)a).GetValue(i) ?? 0).ToArray();
        public static string?[] ReadStrMany(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ((StringArray)a).IsNull(i) ? null : ((StringArray)a).GetString(i)).ToArray();
        public static DateTimeUtc[] ReadDateTimeMany(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ((Int64Array)a).IsNull(i) ? default : new DateTimeUtc(((Int64Array)a).GetValue(i) ?? 0)).ToArray();
        public static Uuid[] ReadGuidMany(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ReadGuid(a, i)).ToArray();
        public static ByteString[] ReadBytesMany(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ReadBytes(a, i)).ToArray();
        public static NodeId[] ReadNodeIdMany(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ReadNodeId(a, i)).ToArray();
        public static ExpandedNodeId[] ReadExpandedNodeIdMany(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ReadExpandedNodeId(a, i)).ToArray();
        public static StatusCode[] ReadStatusMany(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => new StatusCode(((UInt32Array)a).GetValue(i) ?? 0)).ToArray();
        public static QualifiedName[] ReadQualifiedNameMany(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ReadQualifiedName(a, i)).ToArray();
        public static LocalizedText[] ReadLocalizedTextMany(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ReadLocalizedText(a, i)).ToArray();
        public static DiagnosticInfo?[] ReadDiagnosticMany(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ReadDiagnostic(a, i)).ToArray();
        public static Variant[] ReadVariantMany(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ReadVariant(a, i)).ToArray();
        public static DataValue[] ReadDataValueMany(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ReadDataValue(a, i)).ToArray();
        public static ExtensionObject[] ReadExtensionMany(IArrowArray a, int s, int n) => Enumerable.Range(s, n).Select(i => ReadExtension(a, i)).ToArray();
    }
}
