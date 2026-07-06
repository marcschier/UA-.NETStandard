/* ========================================================================
 * Copyright (c) 2005-2025 The OPC Foundation, Inc. All rights reserved.
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
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Opc.Ua
{
    /// <summary>
    /// Reads Avro binary primitive values from the underlying stream.
    /// </summary>
    internal sealed class AvroBinaryReader
    {
        private readonly Stream m_stream;

        /// <summary>
        /// Initializes a new AvroBinaryReader instance for the experimental OPC UA encoding support.
        /// </summary>
        /// <param name = "stream">The stream that receives or supplies the encoded payload.</param>
        public AvroBinaryReader(Stream stream)
        {
            m_stream = stream;
        }

        /// <summary>
        /// Reads Boolean from the experimental encoded representation.
        /// </summary>
        /// <returns>The result produced by this codec helper.</returns>
        public bool ReadBoolean()
        {
            return ReadByte() != 0;
        }

        /// <summary>
        /// Reads Byte from the experimental encoded representation.
        /// </summary>
        /// <returns>The result produced by this codec helper.</returns>
        public byte ReadByte()
        {
            int value = m_stream.ReadByte();
            if (value < 0)
            {
                throw new EndOfStreamException();
            }

            return (byte)value;
        }

        /// <summary>
        /// Reads Fixed from the experimental encoded representation.
        /// </summary>
        /// <param name = "length">The number of bytes to read.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public byte[] ReadFixed(int length)
        {
            byte[] bytes = new byte[length];
            ReadExactly(bytes);
            return bytes;
        }

        /// <summary>
        /// Reads Float from the experimental encoded representation.
        /// </summary>
        /// <returns>The result produced by this codec helper.</returns>
        public float ReadFloat()
        {
            Span<byte> b = stackalloc byte[4];
            ReadExactly(b);
            return BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(b));
        }

        /// <summary>
        /// Reads Double from the experimental encoded representation.
        /// </summary>
        /// <returns>The result produced by this codec helper.</returns>
        public double ReadDouble()
        {
            Span<byte> b = stackalloc byte[8];
            ReadExactly(b);
            return BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(b));
        }

        /// <summary>
        /// Reads Int from the experimental encoded representation.
        /// </summary>
        /// <returns>The result produced by this codec helper.</returns>
        public int ReadInt()
        {
            return checked((int)ReadLong());
        }

        /// <summary>
        /// Reads Long from the experimental encoded representation.
        /// </summary>
        /// <returns>The result produced by this codec helper.</returns>
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

        /// <summary>
        /// Reads one OPC UA byte string from an Arrow binary array.
        /// </summary>
        /// <returns>The result produced by this codec helper.</returns>
        public byte[] ReadBytes()
        {
            long length = ReadLong();
            if (length < 0 || length > int.MaxValue)
            {
                throw new FormatException("Invalid Avro byte length.");
            }

            byte[] bytes = new byte[length];
            ReadExactly(bytes);
            return bytes;
        }

        /// <summary>
        /// Reads String from the experimental encoded representation.
        /// </summary>
        /// <returns>The result produced by this codec helper.</returns>
        public string ReadString()
        {
            return Encoding.UTF8.GetString(ReadBytes());
        }

        private void ReadExactly(Span<byte> buffer)
        {
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
            m_stream.ReadExactly(buffer);
#else
            int offset = 0;
            while (offset < buffer.Length)
            {
                int read = m_stream.Read(buffer.Slice(offset).ToArray(), 0, buffer.Length - offset);
                if (read == 0)
                    throw new EndOfStreamException();
                offset += read;
            }
#endif
        }
    }
}
