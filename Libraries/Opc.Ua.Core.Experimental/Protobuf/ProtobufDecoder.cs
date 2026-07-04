#pragma warning disable RCS0056, RCS0023, RCS1007, CA1305, CA1725, CS0618, CS0649, CS8604, CS8619
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Opc.Ua.Core.Experimental
{
    public sealed class ProtobufDecoder : IDecoder
    {
        public ProtobufDecoder(byte[] buffer, IServiceMessageContext context) : this(new ReadOnlyMemory<byte>(buffer), context) { }
        public ProtobufDecoder(ReadOnlyMemory<byte> buffer, IServiceMessageContext context)
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
            m_stack.Push(new Frame(Proto.Parse(buffer)));
        }
        public ProtobufDecoder(Stream stream, IServiceMessageContext context)
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
            using var ms = new MemoryStream(); stream.CopyTo(ms); m_stack.Push(new Frame(Proto.Parse(ms.ToArray())));
        }
        public EncodingType EncodingType => EncodingType.Json;
        public IServiceMessageContext Context { get; }
        public void Dispose() => Close();
        public void Close() { m_stack.Clear(); }
        public void SetMappingTables(NamespaceTable namespaceUris, StringTable serverUris) { m_namespaceMappings = namespaceUris?.CreateMapping(Context.NamespaceUris, true); m_serverMappings = serverUris?.CreateMapping(Context.ServerUris, true); }
        public void PushNamespace(string namespaceUri) { }
        public void PopNamespace() { }
        public T DecodeMessage<T>() where T : IEncodeable { NodeId type = ReadNodeId("type_id"); return ReadEncodeable<T>("body", type); }
        public bool HasField(string fieldName) => Current.Message.Has(Current.FieldForName(fieldName));
        // KNOWN LIMITATION (reference decoder): optional-field presence is reconstructed by probing
        // each optional field name against the wire (HasField). Because the encoder numbers protobuf
        // fields positionally and omits absent optionals, this reconstruction is only reliable when at
        // most one optional precedes a given field, or no preceding optional is absent. Structures with
        // two or more optional fields where an earlier one is absent can mis-map presence. The in-scope
        // gRPC service messages (ProtobufGrpcMessages) do not use such structures. A fully general fix
        // requires an explicit on-wire encoding mask (see WriteEncodingMask), which is out of scope for
        // this first reference and would need coordinated encoder/decoder/generated-code changes.
        public uint ReadEncodingMask(IList<string> masks) { if (masks != null) { uint mask=0; for (int i=0;i<masks.Count && i<32;i++) if (HasField(masks[i])) mask |= 1u << i; return mask; } return Current.EncodingMask; }
        public uint ReadSwitchField(IList<string> switches, out string? fieldName) { fieldName=null; if (switches != null) { for (int i=0;i<switches.Count;i++) if (HasField(switches[i])) { fieldName=switches[i]; return (uint)(i+1); } } return Current.UnionSwitch; }

        public bool ReadBoolean(string? f) => Get(f).Varint != 0;
        public sbyte ReadSByte(string? f) => unchecked((sbyte)Get(f).Varint);
        public byte ReadByte(string? f) => checked((byte)Get(f).Varint);
        public short ReadInt16(string? f) => unchecked((short)Get(f).Varint);
        public ushort ReadUInt16(string? f) => checked((ushort)Get(f).Varint);
        public int ReadInt32(string? f) => unchecked((int)Get(f).Varint);
        public uint ReadUInt32(string? f) => checked((uint)Get(f).Varint);
        public long ReadInt64(string? f) => unchecked((long)Get(f).Varint);
        public ulong ReadUInt64(string? f) => Get(f).Varint;
        public float ReadFloat(string? f) => BitConverter.UInt32BitsToSingle(Get(f).Fixed32);
        public double ReadDouble(string? f) => BitConverter.UInt64BitsToDouble(Get(f).Fixed64);
        public string? ReadString(string? f) { var fld = GetNullable(f); if (fld == null) return null; var m=Proto.Parse(fld.Value.Bytes); var v=m.First(1); return v.HasValue ? Proto.String(v.Value.Bytes) : null; }
        public DateTimeUtc ReadDateTime(string? f) => new(unchecked((long)Get(f).Fixed64));
        public Uuid ReadGuid(string? f) => new(Get(f).Bytes.ToArray());
        public ByteString ReadByteString(string? f) { var fld=GetNullable(f); if (fld==null) return default; var m=Proto.Parse(fld.Value.Bytes); var v=m.First(1); return v.HasValue ? ByteString.From(v.Value.Bytes.Span) : default; }
        public XmlElement ReadXmlElement(string? f) { string? xml=ReadString(f); if (xml == null) return default!; return (XmlElement)xml; }
        public StatusCode ReadStatusCode(string? f) => new(Get(f).Fixed32);
        public EnumValue ReadEnumerated(string? f) => new(ReadInt32(f));
        public T ReadEnumerated<T>(string? f) where T : struct, Enum => (T)Enum.ToObject(typeof(T), ReadInt32(f));

        public NodeId ReadNodeId(string? f) => DecodeNodeId(Proto.Parse(Get(f).Bytes));
        public ExpandedNodeId ReadExpandedNodeId(string? f) { var m=Proto.Parse(Get(f).Bytes); NodeId n=m.First(1) is var nf && nf.HasValue ? DecodeNodeId(Proto.Parse(nf.Value.Bytes)) : NodeId.Null; string? uri=m.First(2) is var uf && uf.HasValue ? Proto.String(uf.Value.Bytes) : null; uint si=m.First(3) is var sf && sf.HasValue ? (uint)sf.Value.Varint : 0; return new ExpandedNodeId(n, uri, si); }
        public QualifiedName ReadQualifiedName(string? f) { var m=Proto.Parse(Get(f).Bytes); ushort ns=m.First(1) is var nf && nf.HasValue ? (ushort)nf.Value.Varint : (ushort)0; string? name=m.First(2) is var sf && sf.HasValue ? Proto.String(sf.Value.Bytes) : null; return new QualifiedName(name, ns); }
        public LocalizedText ReadLocalizedText(string? f) { var m=Proto.Parse(Get(f).Bytes); string? loc=m.First(1) is var lf && lf.HasValue ? Proto.String(lf.Value.Bytes) : null; string? text=m.First(2) is var tf && tf.HasValue ? Proto.String(tf.Value.Bytes) : null; return new LocalizedText(loc, text); }
        public DiagnosticInfo? ReadDiagnosticInfo(string? f) { var fld=GetNullable(f); return fld.HasValue ? DecodeDiagnosticInfo(Proto.Parse(fld.Value.Bytes)) : null; }
        public DataValue ReadDataValue(string? f) => DecodeDataValue(Proto.Parse(Get(f).Bytes));
        public ExtensionObject ReadExtensionObject(string? f) => DecodeExtensionObject(Proto.Parse(Get(f).Bytes));
        public Variant ReadVariant(string? f) => DecodeVariant(Proto.Parse(Get(f).Bytes));
        public Variant ReadVariantValue(string? f, TypeInfo typeInfo) => ReadVariant(f);

        public T ReadEncodeable<T>(string? f, ExpandedNodeId encodeableTypeId) where T : IEncodeable
        {
            ProtoField fld=Get(f); if (!Context.Factory.TryGetEncodeableType(encodeableTypeId, out IEncodeableType? act)) throw new ServiceResultException(StatusCodes.BadDecodingError, $"Cannot decode type '{encodeableTypeId}'."); var v=(T)act.CreateInstance(); DecodeInto(v, fld.Bytes); return v;
        }
        public T ReadEncodeable<T>(string? f) where T : IEncodeable, new() { var v=new T(); DecodeInto(v, Get(f).Bytes); return v; }
        public T ReadEncodeableAsExtensionObject<T>(string? f) where T : IEncodeable { var eo=ReadExtensionObject(f); if (eo.Body is T t) return t; if (!eo.TypeId.IsNull) return ReadEncodeable<T>(f, eo.TypeId); return default!; }
        private void DecodeInto(IEncodeable v, ReadOnlyMemory<byte> bytes) { m_stack.Push(new Frame(Proto.Parse(bytes))); try { v.Decode(this); } finally { m_stack.Pop(); } }

        public ArrayOf<bool> ReadBooleanArray(string? f) => ReadArray(f, x => x.Varint != 0);
        public ArrayOf<sbyte> ReadSByteArray(string? f) => ReadArray(f, x => unchecked((sbyte)x.Varint));
        public ArrayOf<byte> ReadByteArray(string? f) => ReadArray(f, x => (byte)x.Varint);
        public ArrayOf<short> ReadInt16Array(string? f) => ReadArray(f, x => unchecked((short)x.Varint));
        public ArrayOf<ushort> ReadUInt16Array(string? f) => ReadArray(f, x => (ushort)x.Varint);
        public ArrayOf<int> ReadInt32Array(string? f) => ReadArray(f, x => unchecked((int)x.Varint));
        public ArrayOf<uint> ReadUInt32Array(string? f) => ReadArray(f, x => (uint)x.Varint);
        public ArrayOf<long> ReadInt64Array(string? f) => ReadArray(f, x => (long)x.Varint);
        public ArrayOf<ulong> ReadUInt64Array(string? f) => ReadArray(f, x => x.Varint);
        public ArrayOf<float> ReadFloatArray(string? f) => ReadArray(f, x => BitConverter.UInt32BitsToSingle(x.Fixed32));
        public ArrayOf<double> ReadDoubleArray(string? f) => ReadArray(f, x => BitConverter.UInt64BitsToDouble(x.Fixed64));
        public ArrayOf<string?> ReadStringArray(string? f) => ReadArray(f, x => { var m=Proto.Parse(x.Bytes); var v=m.First(1); return v.HasValue ? Proto.String(v.Value.Bytes) : null; });
        public ArrayOf<DateTimeUtc> ReadDateTimeArray(string? f) => ReadArray(f, x => new DateTimeUtc((long)x.Fixed64));
        public ArrayOf<Uuid> ReadGuidArray(string? f) => ReadArray(f, x => new Uuid(x.Bytes.ToArray()));
        public ArrayOf<ByteString> ReadByteStringArray(string? f) => ReadArray(f, x => { var m=Proto.Parse(x.Bytes); var v=m.First(1); return v.HasValue ? ByteString.From(v.Value.Bytes.Span) : default; });
        public ArrayOf<XmlElement> ReadXmlElementArray(string? f) => ReadArray(f, x => { var m=Proto.Parse(x.Bytes); var v=m.First(1); if (!v.HasValue) return default!; return (XmlElement)Proto.String(v.Value.Bytes); });
        public ArrayOf<NodeId> ReadNodeIdArray(string? f) => ReadArray(f, x => DecodeNodeId(Proto.Parse(x.Bytes)));
        public ArrayOf<ExpandedNodeId> ReadExpandedNodeIdArray(string? f) => ReadArray(f, x => { m_stack.Push(new Frame(new ProtoMessage { Fields = { x } })); try { return ReadExpandedNodeId(null); } finally { m_stack.Pop(); } });
        public ArrayOf<StatusCode> ReadStatusCodeArray(string? f) => ReadArray(f, x => new StatusCode(x.Fixed32));
        public ArrayOf<DiagnosticInfo?> ReadDiagnosticInfoArray(string? f) => new ArrayOf<DiagnosticInfo?>(ReadArray(f, x => (DiagnosticInfo?)DecodeDiagnosticInfo(Proto.Parse(x.Bytes))).Memory);
        public ArrayOf<QualifiedName> ReadQualifiedNameArray(string? f) => ReadArray(f, x => { var m=Proto.Parse(x.Bytes); return new QualifiedName(m.First(2) is var n && n.HasValue ? Proto.String(n.Value.Bytes) : null, m.First(1) is var ns && ns.HasValue ? (ushort)ns.Value.Varint : (ushort)0); });
        public ArrayOf<LocalizedText> ReadLocalizedTextArray(string? f) => ReadArray(f, x => { var m=Proto.Parse(x.Bytes); return new LocalizedText(m.First(1) is var l && l.HasValue ? Proto.String(l.Value.Bytes) : null, m.First(2) is var t && t.HasValue ? Proto.String(t.Value.Bytes) : null); });
        public ArrayOf<Variant> ReadVariantArray(string? f) => ReadArray(f, x => DecodeVariant(Proto.Parse(x.Bytes)));
        public ArrayOf<DataValue> ReadDataValueArray(string? f) => ReadArray(f, x => DecodeDataValue(Proto.Parse(x.Bytes)));
        public ArrayOf<ExtensionObject> ReadExtensionObjectArray(string? f) => ReadArray(f, x => DecodeExtensionObject(Proto.Parse(x.Bytes)));
        public ArrayOf<T> ReadEnumeratedArray<T>(string? f) where T : struct, Enum => ReadArray(f, x => (T)Enum.ToObject(typeof(T), (int)(long)x.Varint));
        public ArrayOf<EnumValue> ReadEnumeratedArray(string? f) => ReadArray(f, x => new EnumValue((int)(long)x.Varint));
        public ArrayOf<T> ReadEncodeableArray<T>(string? f) where T : IEncodeable, new() => ReadArray(f, x => { var v=new T(); DecodeInto(v,x.Bytes); return v; });
        public ArrayOf<T> ReadEncodeableArray<T>(string? f, ExpandedNodeId id) where T : IEncodeable => ReadArray(f, x => { if (!Context.Factory.TryGetEncodeableType(id, out IEncodeableType? act)) throw new ServiceResultException(StatusCodes.BadDecodingError); var v=(T)act.CreateInstance(); DecodeInto(v,x.Bytes); return v; });
        public ArrayOf<T> ReadEncodeableArrayAsExtensionObjects<T>(string? f) where T : IEncodeable => throw new NotSupportedException("Decoding abstract encodeable arrays requires generated subtype descriptors in the Protobuf reference decoder.");
        public MatrixOf<T> ReadEncodeableMatrix<T>(string? f, ExpandedNodeId id) where T : IEncodeable => throw new NotSupportedException("Decode encodeable matrix with an explicit generated T is not implemented in the minimal Protobuf reference decoder.");
        public MatrixOf<T> ReadEncodeableMatrix<T>(string? f) where T : IEncodeable, new() => throw new NotSupportedException("Decode encodeable matrix is not implemented in the minimal Protobuf reference decoder.");

        private ArrayOf<T> ReadArray<T>(string? f, Func<ProtoField,T> conv) { var fld=GetNullable(f); if (!fld.HasValue) return default; var m=Proto.Parse(fld.Value.Bytes); return new ArrayOf<T>(m.All(1).Select(conv).ToArray()); }
        private ProtoField Get(string? f) => GetNullable(f) ?? default;
        private ProtoField? GetNullable(string? f) { int n=Current.Next(f); var fld=Current.Message.First(n); return fld.HasValue && fld.Value.Number != 0 ? fld : null; }
        private Frame Current => m_stack.Peek();
        private static NodeId DecodeNodeId(ProtoMessage m) { ushort ns=m.First(1) is var nf && nf.HasValue ? (ushort)nf.Value.Varint : (ushort)0; if (m.First(3) is var s && s.HasValue) return new NodeId(Proto.String(s.Value.Bytes), ns); if (m.First(4) is var g && g.HasValue) return new NodeId(new Uuid(g.Value.Bytes.ToArray()), ns); if (m.First(5) is var o && o.HasValue) return new NodeId(ByteString.From(o.Value.Bytes.Span), ns); uint id=m.First(2) is var num && num.HasValue ? (uint)num.Value.Varint : 0; return new NodeId(id, ns); }
        private DiagnosticInfo DecodeDiagnosticInfo(ProtoMessage m) => new DiagnosticInfo { SymbolicId = m.First(1) is var f1 && f1.HasValue ? (int)(long)f1.Value.Varint : -1, NamespaceUri = m.First(2) is var f2 && f2.HasValue ? (int)(long)f2.Value.Varint : -1, Locale = m.First(3) is var f3 && f3.HasValue ? (int)(long)f3.Value.Varint : -1, LocalizedText = m.First(4) is var f4 && f4.HasValue ? (int)(long)f4.Value.Varint : -1, AdditionalInfo = m.First(5) is var f5 && f5.HasValue ? Proto.String(f5.Value.Bytes) : null, InnerStatusCode = m.First(6) is var f6 && f6.HasValue ? new StatusCode(f6.Value.Fixed32) : default, InnerDiagnosticInfo = m.First(7) is var f7 && f7.HasValue ? DecodeDiagnosticInfo(Proto.Parse(f7.Value.Bytes)) : null };
        private DataValue DecodeDataValue(ProtoMessage m) { Variant v=m.First(1) is var vf && vf.HasValue ? DecodeVariant(Proto.Parse(vf.Value.Bytes)) : Variant.Null; StatusCode sc=m.First(2) is var sf && sf.HasValue ? new StatusCode(sf.Value.Fixed32) : StatusCodes.Good; DateTimeUtc st=m.First(3) is var stf && stf.HasValue ? new DateTimeUtc((long)stf.Value.Fixed64) : default; DateTimeUtc sv=m.First(5) is var svf && svf.HasValue ? new DateTimeUtc((long)svf.Value.Fixed64) : default; ushort sp=m.First(4) is var spf && spf.HasValue ? (ushort)spf.Value.Varint : (ushort)0; ushort vp=m.First(6) is var vpf && vpf.HasValue ? (ushort)vpf.Value.Varint : (ushort)0; return new DataValue(v, sc, st, sv, sp, vp); }
        private ExtensionObject DecodeExtensionObject(ProtoMessage m) { ExpandedNodeId type=m.First(1) is var tf && tf.HasValue ? DecodeNodeId(Proto.Parse(tf.Value.Bytes)) : ExpandedNodeId.Null; if (m.First(3) is var of && of.HasValue) return new ExtensionObject(type, ByteString.From(of.Value.Bytes.Span)); if (m.First(2) is var bf && bf.HasValue) return new ExtensionObject(type, ByteString.From(bf.Value.Bytes.Span)); return new ExtensionObject(type); }
        private Variant DecodeVariant(ProtoMessage m) { if (!m.Has(1)) return Variant.Null; var t=(BuiltInType)m.First(1)!.Value.Varint; var payload=(m.First(2) ?? m.First(3) ?? m.First(4)); if (!payload.HasValue) return Variant.Null; var inner=Proto.Parse(payload.Value.Bytes); object? value = DecodeObjectFromField1(t, inner.First(1) ?? default); return value == null ? Variant.Null : new Variant(value); }
        private object? DecodeObjectFromField1(BuiltInType t, ProtoField f) => t switch { BuiltInType.Boolean => f.Varint!=0, BuiltInType.SByte => (sbyte)(long)f.Varint, BuiltInType.Byte => (byte)f.Varint, BuiltInType.Int16 => (short)(long)f.Varint, BuiltInType.UInt16 => (ushort)f.Varint, BuiltInType.Int32 or BuiltInType.Enumeration => (int)(long)f.Varint, BuiltInType.UInt32 => (uint)f.Varint, BuiltInType.Int64 => (long)f.Varint, BuiltInType.UInt64 => f.Varint, BuiltInType.Float => BitConverter.UInt32BitsToSingle(f.Fixed32), BuiltInType.Double => BitConverter.UInt64BitsToDouble(f.Fixed64), BuiltInType.String => Proto.Parse(f.Bytes).First(1) is var sf && sf.HasValue ? Proto.String(sf.Value.Bytes) : null, BuiltInType.DateTime => new DateTimeUtc((long)f.Fixed64), BuiltInType.Guid => new Uuid(f.Bytes.ToArray()), BuiltInType.ByteString => ByteString.From(Proto.Parse(f.Bytes).First(1)!.Value.Bytes.Span), BuiltInType.NodeId => DecodeNodeId(Proto.Parse(f.Bytes)), BuiltInType.StatusCode => new StatusCode(f.Fixed32), _ => null };
        private sealed class Frame { public Frame(ProtoMessage m){Message=m;} public ProtoMessage Message; public int NextField=1; public uint EncodingMask; public uint UnionSwitch; private readonly Dictionary<string,int> _names=new(); public int Next(string? name)=>FieldForName(name); public int FieldForName(string? name){ if (name==null) return NextField++; if (!_names.TryGetValue(name,out int n)){ n=NextField++; _names[name]=n;} return n; } }
        private readonly Stack<Frame> m_stack = new(); private ushort[]? m_namespaceMappings; private ushort[]? m_serverMappings;
    }
}




