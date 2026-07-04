#pragma warning disable RCS0056, RCS1007, CS8600, CS8604, CS8620
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Opc.Ua.Core.Experimental
{
    internal sealed class AvroBinaryWriter
    {
        private readonly Stream m_stream;
        public AvroBinaryWriter(Stream stream) => m_stream = stream;
        public long Position => m_stream.CanSeek ? m_stream.Position : 0;
        public void Flush() => m_stream.Flush();
        public void WriteBoolean(bool value) => m_stream.WriteByte(value ? (byte)1 : (byte)0);
        public void WriteFixed(ReadOnlySpan<byte> bytes) => m_stream.Write(bytes);
        public void WriteFloat(float value)
        {
            Span<byte> b = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(b, BitConverter.SingleToInt32Bits(value));
            m_stream.Write(b);
        }
        public void WriteDouble(double value)
        {
            Span<byte> b = stackalloc byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(b, BitConverter.DoubleToInt64Bits(value));
            m_stream.Write(b);
        }
        public void WriteInt(int value) => WriteLong(value);
        public void WriteLong(long value)
        {
            ulong zigzag = ((ulong)value << 1) ^ (ulong)(value >> 63);
            while ((zigzag & ~0x7FUL) != 0)
            {
                m_stream.WriteByte((byte)((zigzag & 0x7F) | 0x80));
                zigzag >>= 7;
            }
            m_stream.WriteByte((byte)zigzag);
        }
        public void WriteBytes(ReadOnlySpan<byte> value)
        {
            WriteLong(value.Length);
            m_stream.Write(value);
        }
        public void WriteString(string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            WriteBytes(bytes);
        }
    }

    internal sealed class AvroBinaryReader
    {
        private readonly Stream m_stream;
        public AvroBinaryReader(Stream stream) => m_stream = stream;
        public bool ReadBoolean() => ReadByte() != 0;
        public byte ReadByte()
        {
            int value = m_stream.ReadByte();
            if (value < 0) throw new EndOfStreamException();
            return (byte)value;
        }
        public byte[] ReadFixed(int length)
        {
            byte[] bytes = new byte[length];
            ReadExactly(bytes);
            return bytes;
        }
        public float ReadFloat()
        {
            Span<byte> b = stackalloc byte[4];
            ReadExactly(b);
            return BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(b));
        }
        public double ReadDouble()
        {
            Span<byte> b = stackalloc byte[8];
            ReadExactly(b);
            return BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(b));
        }
        public int ReadInt() => checked((int)ReadLong());
        public long ReadLong()
        {
            ulong raw = 0;
            int shift = 0;
            while (shift < 64)
            {
                byte b = ReadByte();
                raw |= (ulong)(b & 0x7F) << shift;
                if ((b & 0x80) == 0)
                {
                    return (long)(raw >> 1) ^ -((long)raw & 1L);
                }
                shift += 7;
            }
            throw new FormatException("Invalid Avro variable-length integer.");
        }
        public byte[] ReadBytes()
        {
            long length = ReadLong();
            if (length < 0 || length > int.MaxValue) throw new FormatException("Invalid Avro byte length.");
            byte[] bytes = new byte[length];
            ReadExactly(bytes);
            return bytes;
        }
        public string ReadString() => Encoding.UTF8.GetString(ReadBytes());
        private void ReadExactly(Span<byte> buffer)
        {
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
            m_stream.ReadExactly(buffer);
#else
            int offset = 0;
            while (offset < buffer.Length)
            {
                int read = m_stream.Read(buffer.Slice(offset).ToArray(), 0, buffer.Length - offset);
                if (read == 0) throw new EndOfStreamException();
                offset += read;
            }
#endif
        }
    }
}

