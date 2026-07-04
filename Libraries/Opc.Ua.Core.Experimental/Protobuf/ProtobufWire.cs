#pragma warning disable RCS0056, RCS0023, RCS1007, CA1305, CS0618, CS0649, CS8604, CS8619
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Opc.Ua.Core.Experimental
{
    internal readonly record struct ProtoField(int Number, int WireType, ulong Varint, ReadOnlyMemory<byte> Bytes, uint Fixed32, ulong Fixed64);

    internal sealed class ProtoMessage
    {
        public List<ProtoField> Fields { get; } = new();
        public ProtoField? First(int number) { foreach (ProtoField field in Fields) { if (field.Number == number) { return field; } } return null; }
        public IEnumerable<ProtoField> All(int number) => Fields.Where(f => f.Number == number);
        public bool Has(int number) => Fields.Any(f => f.Number == number);
    }

    internal static class Proto
    {
        public static void WriteTag(BinaryWriter w, int field, int wire) => WriteVarint(w, ((ulong)field << 3) | (uint)wire);
        public static void WriteVarint(BinaryWriter w, ulong v) { while (v >= 0x80) { w.Write((byte)(v | 0x80)); v >>= 7; } w.Write((byte)v); }
        public static void WriteSignedVarint(BinaryWriter w, long v) => WriteVarint(w, unchecked((ulong)v));
        public static void WriteFixed32(BinaryWriter w, uint v) => w.Write(v);
        public static void WriteFixed64(BinaryWriter w, ulong v) => w.Write(v);
        public static void WriteBytes(BinaryWriter w, ReadOnlySpan<byte> b) { WriteVarint(w, (ulong)b.Length); w.Write(b); }
        public static void WriteString(BinaryWriter w, string s) => WriteBytes(w, Encoding.UTF8.GetBytes(s));
        public static ProtoMessage Parse(ReadOnlyMemory<byte> buffer)
        {
            var msg = new ProtoMessage(); int p=0; var span=buffer.Span;
            while (p < span.Length)
            {
                ulong tag = ReadVarint(span, ref p); int field=(int)(tag>>3); int wire=(int)(tag&7);
                switch (wire)
                {
                    case 0: msg.Fields.Add(new ProtoField(field,wire,ReadVarint(span,ref p),default,0,0)); break;
                    case 1: ulong f64=BinaryPrimitives.ReadUInt64LittleEndian(span[p..]); p+=8; msg.Fields.Add(new ProtoField(field,wire,0,default,0,f64)); break;
                    case 2: int len=checked((int)ReadVarint(span,ref p)); msg.Fields.Add(new ProtoField(field,wire,0,buffer.Slice(p,len),0,0)); p+=len; break;
                    case 5: uint f32=BinaryPrimitives.ReadUInt32LittleEndian(span[p..]); p+=4; msg.Fields.Add(new ProtoField(field,wire,0,default,f32,0)); break;
                    default: throw new ServiceResultException(StatusCodes.BadDecodingError, $"Unsupported Protobuf wire type {wire}.");
                }
            }
            return msg;
        }
        public static ulong ReadVarint(ReadOnlySpan<byte> span, ref int p) { ulong v=0; int shift=0; while (p<span.Length) { byte b=span[p++]; v |= (ulong)(b & 0x7f) << shift; if ((b & 0x80)==0) return v; shift += 7; } throw new EndOfStreamException(); }
        public static string String(ReadOnlyMemory<byte> bytes) => Encoding.UTF8.GetString(bytes.Span);
    }
}



