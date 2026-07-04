#pragma warning disable RCS0056, RCS0023, RCS1007, CA1305, CA1725, CS0618, CS0649, CS8604, CS8619
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Opc.Ua.Core.Experimental
{
    public sealed class ProtobufEncoder : IEncoder
    {
        public ProtobufEncoder(IServiceMessageContext context) : this(new MemoryStream(), context, false) { }
        public ProtobufEncoder(Stream stream, IServiceMessageContext context, bool leaveOpen = true)
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
            m_stream = stream ?? throw new ArgumentNullException(nameof(stream));
            m_leaveOpen = leaveOpen;
            m_stack.Push(new Frame(new BinaryWriter(m_stream, Encoding.UTF8, true)));
        }

        public EncodingType EncodingType => EncodingType.Json;
        public bool CanOmitFields => true;
        public IServiceMessageContext Context { get; }
        public byte[] ToArray()
        {
            if (m_stream is MemoryStream ms) { return ms.ToArray(); }
            throw new NotSupportedException("ProtobufEncoder.ToArray requires the internally managed MemoryStream.");
        }
        public int Close()
        {
            if (m_disposed) { throw new ObjectDisposedException(nameof(ProtobufEncoder)); }
            m_stack.Peek().Writer.Flush();
            int length = m_stream is MemoryStream ms ? checked((int)ms.Length) : 0;
            if (!m_leaveOpen) { m_stream.Dispose(); }
            m_disposed = true;
            return length;
        }
        public string? CloseAndReturnText() => Convert.ToHexString(ToArray()).ToLowerInvariant();
        public void Dispose() { if (!m_disposed) { Close(); } }
        public void SetMappingTables(NamespaceTable namespaceUris, StringTable serverUris) { m_namespaceMappings = namespaceUris?.CreateMapping(Context.NamespaceUris, false); m_serverMappings = serverUris?.CreateMapping(Context.ServerUris, false); }
        public void PushNamespace(string namespaceUri) { }
        public void PopNamespace() { }
        public void EncodeMessage<T>(T message) where T : IEncodeable, new() => EncodeMessage(message, message.TypeId);
        public void EncodeMessage<T>(T message, ExpandedNodeId encodeableTypeId) where T : IEncodeable { WriteNodeId("type_id", ExpandedNodeId.ToNodeId(encodeableTypeId, Context.NamespaceUris)); WriteEncodeable("body", message, encodeableTypeId); }

        public void WriteBoolean(string? fieldName, bool value) => WriteVarint(fieldName, value ? 1UL : 0UL);
        public void WriteSByte(string? fieldName, sbyte value) => WriteSignedVarint(fieldName, value);
        public void WriteByte(string? fieldName, byte value) => WriteVarint(fieldName, value);
        public void WriteInt16(string? fieldName, short value) => WriteSignedVarint(fieldName, value);
        public void WriteUInt16(string? fieldName, ushort value) => WriteVarint(fieldName, value);
        public void WriteInt32(string? fieldName, int value) => WriteSignedVarint(fieldName, value);
        public void WriteUInt32(string? fieldName, uint value) => WriteVarint(fieldName, value);
        public void WriteInt64(string? fieldName, long value) => WriteSignedVarint(fieldName, value);
        public void WriteUInt64(string? fieldName, ulong value) => WriteVarint(fieldName, value);
        public void WriteFloat(string? fieldName, float value) => WriteFixed32(fieldName, BitConverter.SingleToUInt32Bits(value));
        public void WriteDouble(string? fieldName, double value) => WriteFixed64(fieldName, BitConverter.DoubleToUInt64Bits(value));
        public void WriteString(string? fieldName, string? value) => WriteMessage(fieldName, w => { if (value != null) { Proto.WriteTag(w, 1, 2); Proto.WriteString(w, value); } });
        public void WriteDateTime(string? fieldName, DateTimeUtc value) => WriteFixed64(fieldName, unchecked((ulong)(long)value));
        public void WriteGuid(string? fieldName, Uuid value) => WriteBytes(fieldName, value.ToByteArray());
        public void WriteByteString(string? fieldName, ByteString value) => WriteMessage(fieldName, w => { if (!value.IsNull) { Proto.WriteTag(w, 1, 2); Proto.WriteBytes(w, value.Span); } });
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
        public void WriteByteString(string? fieldName, ReadOnlySpan<byte> value) => WriteBytes(fieldName, value);
#endif
        public void WriteXmlElement(string? fieldName, XmlElement value) => WriteString(fieldName, value.OuterXml);
        public void WriteStatusCode(string? fieldName, StatusCode value) => WriteFixed32(fieldName, value.Code);
        public void WriteEnumerated<T>(string? fieldName, T value) where T : struct, Enum => WriteInt32(fieldName, Convert.ToInt32(value));
        public void WriteEnumerated(string? fieldName, EnumValue value) => WriteInt32(fieldName, value.Value);
        public void WriteSwitchField(uint switchField, out string? fieldName) { fieldName = null; m_stack.Peek().UnionSwitch = switchField; }
        public void WriteEncodingMask(uint encodingMask) { m_stack.Peek().EncodingMask = encodingMask; }

        public void WriteNodeId(string? fieldName, NodeId value) => WriteMessage(fieldName, w => EncodeNodeId(w, value));
        public void WriteExpandedNodeId(string? fieldName, ExpandedNodeId value) => WriteMessage(fieldName, w => { EncodeNodeIdField(w, 1, value.InnerNodeId); if (value.NamespaceUri != null) { Proto.WriteTag(w, 2, 2); Proto.WriteString(w, value.NamespaceUri); } if (value.ServerIndex != 0) { Proto.WriteTag(w, 3, 0); Proto.WriteVarint(w, value.ServerIndex); } });
        public void WriteQualifiedName(string? fieldName, QualifiedName value) => WriteMessage(fieldName, w => { if (value.NamespaceIndex != 0) { Proto.WriteTag(w, 1, 0); Proto.WriteVarint(w, value.NamespaceIndex); } if (value.Name != null) { Proto.WriteTag(w, 2, 2); Proto.WriteString(w, value.Name); } });
        public void WriteLocalizedText(string? fieldName, LocalizedText value) => WriteMessage(fieldName, w => { if (value.Locale != null) { Proto.WriteTag(w, 1, 2); Proto.WriteString(w, value.Locale); } if (value.Text != null) { Proto.WriteTag(w, 2, 2); Proto.WriteString(w, value.Text); } });
        public void WriteDiagnosticInfo(string? fieldName, DiagnosticInfo? value) { if (value == null) return; WriteMessage(fieldName, w => EncodeDiagnosticInfo(w, value)); }
        public void WriteDataValue(string? fieldName, in DataValue value) { DataValue copy = value; WriteMessage(fieldName, w => EncodeDataValue(w, copy)); }
        public void WriteExtensionObject(string? fieldName, ExtensionObject value) => WriteMessage(fieldName, w => EncodeExtensionObject(w, value));
        public void WriteVariant(string? fieldName, in Variant value) { Variant copy = value; WriteMessage(fieldName, w => EncodeVariant(w, copy)); }
        public void WriteVariantValue(string? fieldName, in Variant value) => WriteVariant(fieldName, value);

        public void WriteEncodeable<T>(string? fieldName, T value) where T : IEncodeable, new() => WriteEncodeable(fieldName, value, value.TypeId);
        public void WriteEncodeable<T>(string? fieldName, T value, ExpandedNodeId encodeableTypeId) where T : IEncodeable { if (EqualityComparer<T>.Default.Equals(value, default!)) return; WriteMessage(fieldName, w => WithFrame(w, () => value.Encode(this))); }
        public void WriteEncodeableAsExtensionObject<T>(string? fieldName, T value) where T : IEncodeable => WriteExtensionObject(fieldName, new ExtensionObject(value));
        public void WriteEncodeableArray<T>(string? fieldName, ArrayOf<T> values) where T : IEncodeable, new() => WriteArray(fieldName, values, v => WriteMessageRaw(1, w => WithFrame(w, () => v.Encode(this))));
        public void WriteEncodeableArray<T>(string? fieldName, ArrayOf<T> values, ExpandedNodeId encodeableTypeId) where T : IEncodeable => WriteArray(fieldName, values, v => WriteMessageRaw(1, w => WithFrame(w, () => v.Encode(this))));
        public void WriteEncodeableArrayAsExtensionObjects<T>(string? fieldName, ArrayOf<T> values) where T : IEncodeable => WriteArray(fieldName, values, v => { var eo = new ExtensionObject(v); WriteMessageRaw(1, w => EncodeExtensionObject(w, eo)); });
        public void WriteEncodeableMatrix<T>(string? fieldName, MatrixOf<T> values) where T : IEncodeable, new() => WriteMatrix(fieldName, values, v => WriteMessageRaw(2, w => WithFrame(w, () => v.Encode(this))));
        public void WriteEncodeableMatrix<T>(string? fieldName, MatrixOf<T> values, ExpandedNodeId encodeableTypeId) where T : IEncodeable => WriteMatrix(fieldName, values, v => WriteMessageRaw(2, w => WithFrame(w, () => v.Encode(this))));

        public void WriteBooleanArray(string? f, ArrayOf<bool> v) => WriteArray(f, v, x => { Proto.WriteTag(Current, 1, 0); Proto.WriteVarint(Current, x ? 1UL : 0UL); });
        public void WriteSByteArray(string? f, ArrayOf<sbyte> v) => WriteArray(f, v, x => { Proto.WriteTag(Current, 1, 0); Proto.WriteSignedVarint(Current, x); });
        public void WriteByteArray(string? f, ArrayOf<byte> v) => WriteArray(f, v, x => { Proto.WriteTag(Current, 1, 0); Proto.WriteVarint(Current, x); });
        public void WriteInt16Array(string? f, ArrayOf<short> v) => WriteArray(f, v, x => { Proto.WriteTag(Current, 1, 0); Proto.WriteSignedVarint(Current, x); });
        public void WriteUInt16Array(string? f, ArrayOf<ushort> v) => WriteArray(f, v, x => { Proto.WriteTag(Current, 1, 0); Proto.WriteVarint(Current, x); });
        public void WriteInt32Array(string? f, ArrayOf<int> v) => WriteArray(f, v, x => { Proto.WriteTag(Current, 1, 0); Proto.WriteSignedVarint(Current, x); });
        public void WriteUInt32Array(string? f, ArrayOf<uint> v) => WriteArray(f, v, x => { Proto.WriteTag(Current, 1, 0); Proto.WriteVarint(Current, x); });
        public void WriteInt64Array(string? f, ArrayOf<long> v) => WriteArray(f, v, x => { Proto.WriteTag(Current, 1, 0); Proto.WriteSignedVarint(Current, x); });
        public void WriteUInt64Array(string? f, ArrayOf<ulong> v) => WriteArray(f, v, x => { Proto.WriteTag(Current, 1, 0); Proto.WriteVarint(Current, x); });
        public void WriteFloatArray(string? f, ArrayOf<float> v) => WriteArray(f, v, x => { Proto.WriteTag(Current, 1, 5); Proto.WriteFixed32(Current, BitConverter.SingleToUInt32Bits(x)); });
        public void WriteDoubleArray(string? f, ArrayOf<double> v) => WriteArray(f, v, x => { Proto.WriteTag(Current, 1, 1); Proto.WriteFixed64(Current, BitConverter.DoubleToUInt64Bits(x)); });
        public void WriteStringArray(string? f, ArrayOf<string> v) => WriteArray(f, v, x => WriteMessageRaw(1, w => { if (x != null) { Proto.WriteTag(w, 1, 2); Proto.WriteString(w, x); } }));
        public void WriteDateTimeArray(string? f, ArrayOf<DateTimeUtc> v) => WriteArray(f, v, x => { Proto.WriteTag(Current, 1, 1); Proto.WriteFixed64(Current, unchecked((ulong)(long)x)); });
        public void WriteGuidArray(string? f, ArrayOf<Uuid> v) => WriteArray(f, v, x => { Proto.WriteTag(Current, 1, 2); Proto.WriteBytes(Current, x.ToByteArray()); });
        public void WriteByteStringArray(string? f, ArrayOf<ByteString> v) => WriteArray(f, v, x => WriteMessageRaw(1, w => { if (!x.IsNull) { Proto.WriteTag(w, 1, 2); Proto.WriteBytes(w, x.Span); } }));
        public void WriteXmlElementArray(string? f, ArrayOf<XmlElement> v) => WriteArray(f, v, x => WriteMessageRaw(1, w => { if (x.OuterXml != null) { Proto.WriteTag(w, 1, 2); Proto.WriteString(w, x.OuterXml); } }));
        public void WriteNodeIdArray(string? f, ArrayOf<NodeId> v) => WriteArray(f, v, x => WriteMessageRaw(1, w => EncodeNodeId(w, x)));
        public void WriteExpandedNodeIdArray(string? f, ArrayOf<ExpandedNodeId> v) => WriteArray(f, v, x => WriteExpandedNodeId(null, x));
        public void WriteStatusCodeArray(string? f, ArrayOf<StatusCode> v) => WriteArray(f, v, x => { Proto.WriteTag(Current, 1, 5); Proto.WriteFixed32(Current, x.Code); });
        public void WriteDiagnosticInfoArray(string? f, ArrayOf<DiagnosticInfo> v) => WriteArray(f, v, x => WriteMessageRaw(1, w => { if (x != null) EncodeDiagnosticInfo(w, x); }));
        public void WriteQualifiedNameArray(string? f, ArrayOf<QualifiedName> v) => WriteArray(f, v, x => WriteMessageRaw(1, w => { if (x.NamespaceIndex != 0) { Proto.WriteTag(w,1,0); Proto.WriteVarint(w,x.NamespaceIndex); } if (x.Name != null) { Proto.WriteTag(w,2,2); Proto.WriteString(w,x.Name); } }));
        public void WriteLocalizedTextArray(string? f, ArrayOf<LocalizedText> v) => WriteArray(f, v, x => WriteMessageRaw(1, w => { if (x.Locale != null) { Proto.WriteTag(w,1,2); Proto.WriteString(w,x.Locale); } if (x.Text != null) { Proto.WriteTag(w,2,2); Proto.WriteString(w,x.Text); } }));
        public void WriteVariantArray(string? f, ArrayOf<Variant> v) => WriteArray(f, v, x => WriteMessageRaw(1, w => EncodeVariant(w, x)));
        public void WriteDataValueArray(string? f, ArrayOf<DataValue> v) => WriteArray(f, v, x => WriteMessageRaw(1, w => EncodeDataValue(w, x)));
        public void WriteExtensionObjectArray(string? f, ArrayOf<ExtensionObject> v) => WriteArray(f, v, x => WriteMessageRaw(1, w => EncodeExtensionObject(w, x)));
        public void WriteEnumeratedArray<T>(string? f, ArrayOf<T> v) where T : struct, Enum => WriteArray(f, v, x => { Proto.WriteTag(Current,1,0); Proto.WriteSignedVarint(Current, Convert.ToInt32(x)); });
        public void WriteEnumeratedArray(string? f, ArrayOf<EnumValue> v) => WriteArray(f, v, x => { Proto.WriteTag(Current,1,0); Proto.WriteSignedVarint(Current, x.Value); });

        private BinaryWriter Current => m_stack.Peek().Writer;
        private void WriteVarint(string? name, ulong value) { Proto.WriteTag(Current, m_stack.Peek().Next(name), 0); Proto.WriteVarint(Current, value); }
        private void WriteSignedVarint(string? name, long value) { Proto.WriteTag(Current, m_stack.Peek().Next(name), 0); Proto.WriteSignedVarint(Current, value); }
        private void WriteFixed32(string? name, uint value) { Proto.WriteTag(Current, m_stack.Peek().Next(name), 5); Proto.WriteFixed32(Current, value); }
        private void WriteFixed64(string? name, ulong value) { Proto.WriteTag(Current, m_stack.Peek().Next(name), 1); Proto.WriteFixed64(Current, value); }
        private void WriteBytes(string? name, ReadOnlySpan<byte> bytes) { Proto.WriteTag(Current, m_stack.Peek().Next(name), 2); Proto.WriteBytes(Current, bytes); }
        private void WriteMessage(string? name, Action<BinaryWriter> encode) => WriteMessageRaw(m_stack.Peek().Next(name), encode);
        private void WriteMessageRaw(int field, Action<BinaryWriter> encode) { using var ms = new MemoryStream(); using var bw = new BinaryWriter(ms, Encoding.UTF8, true); encode(bw); bw.Flush(); Proto.WriteTag(Current, field, 2); Proto.WriteBytes(Current, ms.ToArray()); }
        private void WithFrame(BinaryWriter writer, Action action) { m_stack.Push(new Frame(writer)); try { action(); } finally { m_stack.Pop(); } }
        private void WriteArray<T>(string? name, ArrayOf<T> values, Action<T> write) { if (values.IsNull) return; WriteMessage(name, w => WithFrame(w, () => { for (int i=0;i<values.Count;i++) write(values.Span[i]); })); }
        private void WriteMatrix<T>(string? name, MatrixOf<T> values, Action<T> write) { if (values.IsNull) return; WriteMessage(name, w => WithFrame(w, () => { foreach (int d in values.Dimensions) { Proto.WriteTag(Current,1,0); Proto.WriteSignedVarint(Current,d); } for (int i=0;i<values.Count;i++) write(values.Span[i]); })); }
        private static void EncodeNodeIdField(BinaryWriter w, int field, NodeId n) { using var ms = new MemoryStream(); using var bw = new BinaryWriter(ms, Encoding.UTF8, true); EncodeNodeId(bw,n); bw.Flush(); Proto.WriteTag(w,field,2); Proto.WriteBytes(w,ms.ToArray()); }
        private static void EncodeNodeId(BinaryWriter w, NodeId n) { if (n.NamespaceIndex != 0) { Proto.WriteTag(w,1,0); Proto.WriteVarint(w,n.NamespaceIndex); } switch (n.IdType) { case IdType.Numeric: Proto.WriteTag(w,2,0); Proto.WriteVarint(w,(uint)n.Identifier); break; case IdType.String: Proto.WriteTag(w,3,2); Proto.WriteString(w,(string)n.Identifier); break; case IdType.Guid: Proto.WriteTag(w,4,2); Proto.WriteBytes(w, ((Uuid)(Guid)n.Identifier).ToByteArray()); break; case IdType.Opaque: Proto.WriteTag(w,5,2); Proto.WriteBytes(w, ((ByteString)n.Identifier).Span); break; } }
        private void EncodeDiagnosticInfo(BinaryWriter w, DiagnosticInfo d) { if (d.SymbolicId >= 0) { Proto.WriteTag(w,1,0); Proto.WriteSignedVarint(w,d.SymbolicId); } if (d.NamespaceUri >= 0) { Proto.WriteTag(w,2,0); Proto.WriteSignedVarint(w,d.NamespaceUri); } if (d.Locale >= 0) { Proto.WriteTag(w,3,0); Proto.WriteSignedVarint(w,d.Locale); } if (d.LocalizedText >= 0) { Proto.WriteTag(w,4,0); Proto.WriteSignedVarint(w,d.LocalizedText); } if (d.AdditionalInfo != null) { Proto.WriteTag(w,5,2); Proto.WriteString(w,d.AdditionalInfo); } if (d.InnerStatusCode.Code != 0) { Proto.WriteTag(w,6,5); Proto.WriteFixed32(w,d.InnerStatusCode.Code); } if (d.InnerDiagnosticInfo != null) { using var ms = new MemoryStream(); using var bw = new BinaryWriter(ms,Encoding.UTF8,true); EncodeDiagnosticInfo(bw,d.InnerDiagnosticInfo); bw.Flush(); Proto.WriteTag(w,7,2); Proto.WriteBytes(w,ms.ToArray()); } }
        private void EncodeDataValue(BinaryWriter w, DataValue d) { if (d.IsNull) return; using var ms = new MemoryStream(); using var bw = new BinaryWriter(ms,Encoding.UTF8,true); if (!d.WrappedValue.IsNull) { EncodeVariantField(w,1,d.WrappedValue); } Proto.WriteTag(w,2,5); Proto.WriteFixed32(w,d.StatusCode.Code); Proto.WriteTag(w,3,1); Proto.WriteFixed64(w, unchecked((ulong)(long)d.SourceTimestamp)); if (d.SourcePicoseconds != 0) { Proto.WriteTag(w,4,0); Proto.WriteVarint(w,d.SourcePicoseconds); } Proto.WriteTag(w,5,1); Proto.WriteFixed64(w, unchecked((ulong)(long)d.ServerTimestamp)); if (d.ServerPicoseconds != 0) { Proto.WriteTag(w,6,0); Proto.WriteVarint(w,d.ServerPicoseconds); } }
        private void EncodeExtensionObject(BinaryWriter w, ExtensionObject e) { if (e.IsNull) return; using (var ms = new MemoryStream()) { using var bw = new BinaryWriter(ms,Encoding.UTF8,true); EncodeNodeId(bw, ExpandedNodeId.ToNodeId(e.TypeId, Context.NamespaceUris)); bw.Flush(); Proto.WriteTag(w,1,2); Proto.WriteBytes(w,ms.ToArray()); } if (e.Body is ByteString bs && !bs.IsNull) { Proto.WriteTag(w,3,2); Proto.WriteBytes(w, bs.Span); } else if (e.Body is byte[] bytes) { Proto.WriteTag(w,3,2); Proto.WriteBytes(w, bytes); } else if (e.Body is IEncodeable enc) { using var ms = new MemoryStream(); using var be = new BinaryEncoder(ms, Context, true); enc.Encode(be); be.Close(); Proto.WriteTag(w,2,2); Proto.WriteBytes(w, ms.ToArray()); } }
        private void EncodeVariantField(BinaryWriter w, int field, Variant v) { using var ms = new MemoryStream(); using var bw = new BinaryWriter(ms,Encoding.UTF8,true); EncodeVariant(bw,v); bw.Flush(); Proto.WriteTag(w,field,2); Proto.WriteBytes(w,ms.ToArray()); }
        private void EncodeVariant(BinaryWriter w, Variant v) { if (v.IsNull) return; BuiltInType t = v.TypeInfo.BuiltInType; Proto.WriteTag(w,1,0); Proto.WriteVarint(w,(uint)t); object? o = v.AsBoxedObject(Variant.BoxingBehavior.None); if (o == null) return; using var ms = new MemoryStream(); using var bw = new BinaryWriter(ms,Encoding.UTF8,true); WithFrame(bw, () => WriteObjectAsField1(t,o)); bw.Flush(); Proto.WriteTag(w, v.TypeInfo.IsMatrix ? 4 : v.TypeInfo.IsArray ? 3 : 2, 2); Proto.WriteBytes(w,ms.ToArray()); }
        private void WriteObjectAsField1(BuiltInType t, object o) { switch (t) { case BuiltInType.Boolean: WriteBoolean("v",(bool)o); break; case BuiltInType.SByte: WriteSByte("v",(sbyte)o); break; case BuiltInType.Byte: WriteByte("v",(byte)o); break; case BuiltInType.Int16: WriteInt16("v",(short)o); break; case BuiltInType.UInt16: WriteUInt16("v",(ushort)o); break; case BuiltInType.Int32: case BuiltInType.Enumeration: WriteInt32("v", Convert.ToInt32(o)); break; case BuiltInType.UInt32: WriteUInt32("v",(uint)o); break; case BuiltInType.Int64: WriteInt64("v",(long)o); break; case BuiltInType.UInt64: WriteUInt64("v",(ulong)o); break; case BuiltInType.Float: WriteFloat("v",(float)o); break; case BuiltInType.Double: WriteDouble("v",(double)o); break; case BuiltInType.String: WriteString("v",(string?)o); break; case BuiltInType.DateTime: WriteDateTime("v",(DateTimeUtc)o); break; case BuiltInType.Guid: WriteGuid("v",(Uuid)o); break; case BuiltInType.ByteString: WriteByteString("v",(ByteString)o); break; case BuiltInType.NodeId: WriteNodeId("v",(NodeId)o); break; case BuiltInType.ExpandedNodeId: WriteExpandedNodeId("v",(ExpandedNodeId)o); break; case BuiltInType.StatusCode: WriteStatusCode("v",(StatusCode)o); break; case BuiltInType.QualifiedName: WriteQualifiedName("v",(QualifiedName)o); break; case BuiltInType.LocalizedText: WriteLocalizedText("v",(LocalizedText)o); break; case BuiltInType.ExtensionObject: WriteExtensionObject("v",(ExtensionObject)o); break; case BuiltInType.DataValue: WriteDataValue("v",(DataValue)o); break; default: throw new NotSupportedException($"Variant payload type {t} is not supported by the Protobuf reference encoder."); } }
        private sealed class Frame { public Frame(BinaryWriter writer){Writer=writer;} public BinaryWriter Writer; public int NextField=1; public uint EncodingMask; public uint UnionSwitch; public int Next(string? name)=>NextField++; }
        private readonly Stack<Frame> m_stack = new(); private readonly Stream m_stream; private readonly bool m_leaveOpen; private bool m_disposed; private ushort[]? m_namespaceMappings; private ushort[]? m_serverMappings;
    }
}




