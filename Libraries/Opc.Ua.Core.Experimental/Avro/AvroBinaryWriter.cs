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
    /// Writes Avro binary primitive values to the underlying stream.
    /// </summary>
    internal sealed class AvroBinaryWriter
    {
        private readonly Stream m_stream;

        /// <summary>
        /// Initializes a new AvroBinaryWriter instance for the experimental OPC UA encoding support.
        /// </summary>
        /// <param name = "stream">The stream that receives or supplies the encoded payload.</param>
        public AvroBinaryWriter(Stream stream)
        {
            m_stream = stream;
        }

        /// <summary>
        /// Gets the current stream position when the Avro writer can seek.
        /// </summary>
        public long Position
        {
            get { return m_stream.CanSeek ? m_stream.Position : 0; }
        }

        /// <summary>
        /// Flushes buffered Avro binary data to the underlying stream.
        /// </summary>
        public void Flush()
        {
            m_stream.Flush();
        }

        /// <summary>
        /// Writes Boolean to the experimental encoded representation.
        /// </summary>
        /// <param name = "value">The primitive or OPC UA value to process.</param>
        public void WriteBoolean(bool value)
        {
            m_stream.WriteByte(value ? (byte)1 : (byte)0);
        }

        /// <summary>
        /// Writes Fixed to the experimental encoded representation.
        /// </summary>
        /// <param name = "bytes">The byte sequence to encode or decode.</param>
        public void WriteFixed(ReadOnlySpan<byte> bytes)
        {
            m_stream.Write(bytes);
        }

        /// <summary>
        /// Writes Float to the experimental encoded representation.
        /// </summary>
        /// <param name = "value">The primitive or OPC UA value to process.</param>
        public void WriteFloat(float value)
        {
            Span<byte> b = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(b, BitConverter.SingleToInt32Bits(value));
            m_stream.Write(b);
        }

        /// <summary>
        /// Writes Double to the experimental encoded representation.
        /// </summary>
        /// <param name = "value">The primitive or OPC UA value to process.</param>
        public void WriteDouble(double value)
        {
            Span<byte> b = stackalloc byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(b, BitConverter.DoubleToInt64Bits(value));
            m_stream.Write(b);
        }

        /// <summary>
        /// Writes Int to the experimental encoded representation.
        /// </summary>
        /// <param name = "value">The primitive or OPC UA value to process.</param>
        public void WriteInt(int value)
        {
            WriteLong(value);
        }

        /// <summary>
        /// Writes Long to the experimental encoded representation.
        /// </summary>
        /// <param name = "value">The primitive or OPC UA value to process.</param>
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

        /// <summary>
        /// Writes a length-delimited Protobuf byte sequence.
        /// </summary>
        /// <param name = "value">The primitive or OPC UA value to process.</param>
        public void WriteBytes(ReadOnlySpan<byte> value)
        {
            WriteLong(value.Length);
            m_stream.Write(value);
        }

        /// <summary>
        /// Writes a UTF-8 Protobuf string as a length-delimited field value.
        /// </summary>
        /// <param name = "value">The primitive or OPC UA value to process.</param>
        public void WriteString(string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            WriteBytes(bytes);
        }
    }
}
