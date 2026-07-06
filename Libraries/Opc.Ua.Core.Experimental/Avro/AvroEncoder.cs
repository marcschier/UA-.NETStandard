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
using System.Collections.Generic;
using System.IO;
using Opc.Ua;
using Opc.Ua.Types;

namespace Opc.Ua.Core.Experimental
{
    /// <summary>
    /// Encodes OPC UA values using the experimental Avro binary mapping.
    /// </summary>
    public sealed partial class AvroEncoder : IEncoder
    {
        /// <summary>
        /// Identifies the experimental Avro encoding value used by this encoder.
        /// </summary>
        public const EncodingType AvroEncodingType = (EncodingType)3;
        private readonly Stream m_stream;
        private readonly AvroBinaryWriter m_writer;
        private readonly bool m_leaveOpen;
        private bool m_closed;

        /// <summary>
        /// Initializes a new AvroEncoder instance for the experimental OPC UA encoding support.
        /// </summary>
        /// <param name="context">The service message context that supplies namespace, server URI, and encodeable type resolution tables.</param>
        public AvroEncoder(IServiceMessageContext context)
            : this(new MemoryStream(), context, false) { }

        /// <summary>
        /// Initializes a new AvroEncoder instance for the experimental OPC UA encoding support.
        /// </summary>
        /// <param name="stream">The stream that receives or supplies the encoded payload.</param>
        /// <param name="context">The service message context that supplies namespace, server URI, and encodeable type resolution tables.</param>
        /// <param name="leaveOpen">True to leave the caller-owned stream open when the codec is closed.</param>
        public AvroEncoder(Stream stream, IServiceMessageContext context, bool leaveOpen = true)
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
            m_stream = stream ?? throw new ArgumentNullException(nameof(stream));
            m_leaveOpen = leaveOpen;
            m_writer = new AvroBinaryWriter(m_stream);
        }

        /// <inheritdoc/>
        public EncodingType EncodingType => AvroEncodingType;

        /// <inheritdoc/>
        public bool CanOmitFields => false;

        /// <inheritdoc/>
        public IServiceMessageContext Context { get; }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (!m_closed)
            {
                Close();
            }
        }

        /// <inheritdoc/>
        public int Close()
        {
            m_writer.Flush();
            m_closed = true;
            int p = m_stream.CanSeek ? (int)m_stream.Position : 0;
            if (!m_leaveOpen)
            {
                m_stream.Dispose();
            }

            return p;
        }

        /// <summary>
        /// Completes the encoder and returns the encoded bytes from its memory stream.
        /// </summary>
        /// <returns>The encoded payload bytes.</returns>
        public byte[] CloseAndReturnBuffer()
        {
            Close();
            return m_stream is MemoryStream ms
                ? ms.ToArray()
                : throw new NotSupportedException("AvroEncoder was not created over a memory stream.");
        }

        /// <inheritdoc/>
        public string? CloseAndReturnText() => Convert.ToBase64String(CloseAndReturnBuffer());

        /// <inheritdoc/>
        public void SetMappingTables(NamespaceTable namespaceUris, StringTable serverUris) { }

        /// <inheritdoc/>
        public void PushNamespace(string namespaceUri) { }

        /// <inheritdoc/>
        public void PopNamespace() { }

        /// <inheritdoc/>
        public void EncodeMessage<T>(T message)
            where T : IEncodeable, new() => WriteEncodeable(null, message);

        /// <inheritdoc/>
        public void EncodeMessage<T>(T message, ExpandedNodeId encodeableTypeId)
            where T : IEncodeable => WriteEncodeable(null, message, encodeableTypeId);

        /// <inheritdoc/>
        public void WriteBoolean(string? fieldName, bool value) => m_writer.WriteBoolean(value);

        /// <inheritdoc/>
        public void WriteSByte(string? fieldName, sbyte value) => m_writer.WriteInt(value);

        /// <inheritdoc/>
        public void WriteByte(string? fieldName, byte value) => m_writer.WriteInt(value);

        /// <inheritdoc/>
        public void WriteInt16(string? fieldName, short value) => m_writer.WriteInt(value);

        /// <inheritdoc/>
        public void WriteUInt16(string? fieldName, ushort value) => m_writer.WriteInt(value);

        /// <inheritdoc/>
        public void WriteInt32(string? fieldName, int value) => m_writer.WriteInt(value);

        /// <inheritdoc/>
        public void WriteUInt32(string? fieldName, uint value) => m_writer.WriteInt(unchecked((int)value));

        /// <inheritdoc/>
        public void WriteInt64(string? fieldName, long value) => m_writer.WriteLong(value);

        /// <inheritdoc/>
        public void WriteUInt64(string? fieldName, ulong value) => m_writer.WriteLong(unchecked((long)value));

        /// <inheritdoc/>
        public void WriteFloat(string? fieldName, float value) => m_writer.WriteFloat(value);

        /// <inheritdoc/>
        public void WriteDouble(string? fieldName, double value) => m_writer.WriteDouble(value);

        /// <inheritdoc/>
        public void WriteString(string? fieldName, string? value) => WriteNullable(value, s => m_writer.WriteString(s));

        /// <inheritdoc/>
        public void WriteDateTime(string? fieldName, DateTimeUtc value) => m_writer.WriteLong(value.Value);

        /// <inheritdoc/>
        public void WriteGuid(string? fieldName, Uuid value) => m_writer.WriteFixed(value.ToByteArray());

        /// <inheritdoc/>
        public void WriteByteString(string? fieldName, ByteString value) => WriteNullableBytes(value);

#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
        /// <inheritdoc/>
        public void WriteByteString(string? fieldName, ReadOnlySpan<byte> value) =>
            WriteNullableBytes(ByteString.From(value));
#endif

        /// <inheritdoc/>
        public void WriteXmlElement(string? fieldName, XmlElement value) =>
            WriteNullable(value.IsNull ? null : value.OuterXml, s => m_writer.WriteString(s));

        /// <inheritdoc/>
        public void WriteNodeId(string? fieldName, NodeId value)
        {
            WriteUInt16(null, value.NamespaceIndex);
            WriteInt32(null, (int)value.IdType);
            switch (value.IdType)
            {
                case IdType.Numeric:
                    value.TryGetValue(out uint n);
                    WriteUInt32(null, n);
                    break;
                case IdType.String:
                    value.TryGetValue(out string s);
                    WriteString(null, s);
                    break;
                case IdType.Guid:
                    value.TryGetValue(out Guid g);
                    WriteGuid(null, new Uuid(g));
                    break;
                case IdType.Opaque:
                    value.TryGetValue(out ByteString b);
                    WriteByteString(null, b);
                    break;
                default:
                    throw new NotSupportedException($"Unsupported NodeId identifier type {value.IdType}.");
            }
        }

        /// <inheritdoc/>
        public void WriteExpandedNodeId(string? fieldName, ExpandedNodeId value)
        {
            WriteNodeId(null, value.InnerNodeId);
            WriteString(null, value.NamespaceUri);
            WriteUInt32(null, value.ServerIndex);
        }

        /// <inheritdoc/>
        public void WriteStatusCode(string? fieldName, StatusCode value) => WriteUInt32(null, value.Code);

        /// <inheritdoc/>
        public void WriteQualifiedName(string? fieldName, QualifiedName value)
        {
            WriteUInt16(null, value.NamespaceIndex);
            WriteString(null, value.Name);
        }

        /// <inheritdoc/>
        public void WriteLocalizedText(string? fieldName, LocalizedText value)
        {
            if (value.IsNull)
            {
                m_writer.WriteLong(0);
                return;
            }
            m_writer.WriteLong(1);
            WriteString(null, value.Locale);
            WriteString(null, value.Text);
        }

        /// <inheritdoc/>
        public void WriteDiagnosticInfo(string? fieldName, DiagnosticInfo? value)
        {
            if (value == null)
            {
                m_writer.WriteLong(0);
                return;
            }
            m_writer.WriteLong(1);
            WriteNullableInt(value.SymbolicId >= 0, value.SymbolicId);
            WriteNullableInt(value.NamespaceUri >= 0, value.NamespaceUri);
            WriteNullableInt(value.Locale >= 0, value.Locale);
            WriteNullableInt(value.LocalizedText >= 0, value.LocalizedText);
            WriteString(null, value.AdditionalInfo);
            WriteNullable(
                value.InnerStatusCode.Code != StatusCodes.Good,
                value.InnerStatusCode,
                v => WriteStatusCode(null, v)
            );
            WriteDiagnosticInfo(null, value.InnerDiagnosticInfo);
        }

        /// <inheritdoc/>
        public void WriteDataValue(string? fieldName, in DataValue value)
        {
            if (value.IsNull)
            {
                WriteNullFields(6);
                return;
            }
            WriteNullable(!value.WrappedValue.IsNull, value.WrappedValue, v => WriteVariant(null, in v));
            WriteNullable(
                !value.StatusCode.Equals(StatusCodes.Good, StatusCodeComparison.AllBits),
                value.StatusCode,
                v => WriteStatusCode(null, v)
            );
            WriteNullable(!value.SourceTimestamp.IsNull, value.SourceTimestamp, v => WriteDateTime(null, v));
            WriteNullable(value.SourcePicoseconds != 0, value.SourcePicoseconds, v => WriteUInt16(null, v));
            WriteNullable(!value.ServerTimestamp.IsNull, value.ServerTimestamp, v => WriteDateTime(null, v));
            WriteNullable(value.ServerPicoseconds != 0, value.ServerPicoseconds, v => WriteUInt16(null, v));
        }

        /// <inheritdoc/>
        public void WriteExtensionObject(string? fieldName, ExtensionObject value)
        {
            WriteExpandedNodeId(null, value.TypeId);
            if (value.IsNull || value.Encoding == ExtensionObjectEncoding.None)
            {
                m_writer.WriteLong(0);
                return;
            }
            if (value.TryGetValue(out IEncodeable? enc))
            {
                m_writer.WriteLong(1);
                enc!.Encode(this);
                return;
            }
            if (value.TryGetAsBinary(out ByteString bytes))
            {
                m_writer.WriteLong(2);
                m_writer.WriteBytes(bytes.Span);
                return;
            }
            if (value.TryGetAsXml(out XmlElement xml))
            {
                m_writer.WriteLong(3);
                m_writer.WriteString(xml.OuterXml ?? string.Empty);
                return;
            }
            throw new NotSupportedException($"Unsupported ExtensionObject body encoding {value.Encoding}.");
        }

        /// <inheritdoc/>
        public void WriteEncodeable<T>(string? fieldName, T value)
            where T : IEncodeable, new()
        {
            (value ?? new T()).Encode(this);
        }

        /// <inheritdoc/>
        public void WriteEncodeable<T>(string? fieldName, T value, ExpandedNodeId encodeableTypeId)
            where T : IEncodeable
        {
            value.Encode(this);
        }

        /// <inheritdoc/>
        public void WriteEncodeableAsExtensionObject<T>(string? fieldName, T value)
            where T : IEncodeable => WriteExtensionObject(fieldName, new ExtensionObject(value));

        /// <inheritdoc/>
        public void WriteEnumerated<T>(string? fieldName, T value)
            where T : struct, Enum => WriteInt32(fieldName, EnumHelper.EnumToInt32(value));

        /// <inheritdoc/>
        public void WriteEnumerated(string? fieldName, EnumValue value) => WriteInt32(fieldName, value.Value);

        /// <inheritdoc/>
        public void WriteSwitchField(uint switchField, out string? fieldName)
        {
            fieldName = null;
            WriteUInt32("switch", switchField);
        }

        /// <inheritdoc/>
        public void WriteEncodingMask(uint encodingMask) => WriteUInt32("encodingMask", encodingMask);

        private void WriteNullable<T>(bool hasValue, T value, Action<T> write)
        {
            if (!hasValue)
            {
                m_writer.WriteLong(0);
                return;
            }
            m_writer.WriteLong(1);
            write(value);
        }

        private void WriteNullable<T>(T? value, Action<T> write)
            where T : class
        {
            if (value == null)
            {
                m_writer.WriteLong(0);
                return;
            }
            m_writer.WriteLong(1);
            write(value);
        }

        private void WriteNullableInt(bool hasValue, int value) =>
            WriteNullable(hasValue, value, v => WriteInt32(null, v));

        private void WriteNullFields(int count)
        {
            for (int i = 0; i < count; i++)
            {
                m_writer.WriteLong(0);
            }
        }

        private void WriteNullableBytes(ByteString value)
        {
            if (value.IsNull)
            {
                m_writer.WriteLong(0);
                return;
            }
            m_writer.WriteLong(1);
            m_writer.WriteBytes(value.Span);
        }

        private void WriteArray<T>(ArrayOf<T> values, Action<T> write)
        {
            if (values.IsNull)
            {
                m_writer.WriteLong(0);
                return;
            }
            m_writer.WriteLong(1);
            if (values.Count > 0)
            {
                m_writer.WriteLong(values.Count);

                foreach (T value in values.Span)
                {
                    write(value);
                }
            }
            m_writer.WriteLong(0);
        }

        private void WriteMatrix<T>(MatrixOf<T> matrix, Action<ArrayOf<T>> writeArray)
        {
            if (matrix.IsNull)
            {
                m_writer.WriteLong(0);
                return;
            }
            m_writer.WriteLong(1);
            WriteInt32Array(null, matrix.Dimensions);
            writeArray(matrix.ToArrayOf());
        }

        /// <inheritdoc/>
        public void WriteBooleanArray(string? fieldName, ArrayOf<bool> values) =>
            WriteArray(values, v => WriteBoolean(null, v));

        /// <inheritdoc/>
        public void WriteSByteArray(string? fieldName, ArrayOf<sbyte> values) =>
            WriteArray(values, v => WriteSByte(null, v));

        /// <inheritdoc/>
        public void WriteByteArray(string? fieldName, ArrayOf<byte> values) =>
            WriteArray(values, v => WriteByte(null, v));

        /// <inheritdoc/>
        public void WriteInt16Array(string? fieldName, ArrayOf<short> values) =>
            WriteArray(values, v => WriteInt16(null, v));

        /// <inheritdoc/>
        public void WriteUInt16Array(string? fieldName, ArrayOf<ushort> values) =>
            WriteArray(values, v => WriteUInt16(null, v));

        /// <inheritdoc/>
        public void WriteInt32Array(string? fieldName, ArrayOf<int> values) =>
            WriteArray(values, v => WriteInt32(null, v));

        /// <inheritdoc/>
        public void WriteUInt32Array(string? fieldName, ArrayOf<uint> values) =>
            WriteArray(values, v => WriteUInt32(null, v));

        /// <inheritdoc/>
        public void WriteInt64Array(string? fieldName, ArrayOf<long> values) =>
            WriteArray(values, v => WriteInt64(null, v));

        /// <inheritdoc/>
        public void WriteUInt64Array(string? fieldName, ArrayOf<ulong> values) =>
            WriteArray(values, v => WriteUInt64(null, v));

        /// <inheritdoc/>
        public void WriteFloatArray(string? fieldName, ArrayOf<float> values) =>
            WriteArray(values, v => WriteFloat(null, v));

        /// <inheritdoc/>
        public void WriteDoubleArray(string? fieldName, ArrayOf<double> values) =>
            WriteArray(values, v => WriteDouble(null, v));

        /// <inheritdoc/>
        public void WriteStringArray(string? fieldName, ArrayOf<string> values) =>
            WriteArray(values, v => WriteString(null, v));

        /// <inheritdoc/>
        public void WriteDateTimeArray(string? fieldName, ArrayOf<DateTimeUtc> values) =>
            WriteArray(values, v => WriteDateTime(null, v));

        /// <inheritdoc/>
        public void WriteGuidArray(string? fieldName, ArrayOf<Uuid> values) =>
            WriteArray(values, v => WriteGuid(null, v));

        /// <inheritdoc/>
        public void WriteByteStringArray(string? fieldName, ArrayOf<ByteString> values) =>
            WriteArray(values, v => WriteByteString(null, v));

        /// <inheritdoc/>
        public void WriteXmlElementArray(string? fieldName, ArrayOf<XmlElement> values) =>
            WriteArray(values, v => WriteXmlElement(null, v));

        /// <inheritdoc/>
        public void WriteNodeIdArray(string? fieldName, ArrayOf<NodeId> values) =>
            WriteArray(values, v => WriteNodeId(null, v));

        /// <inheritdoc/>
        public void WriteExpandedNodeIdArray(string? fieldName, ArrayOf<ExpandedNodeId> values) =>
            WriteArray(values, v => WriteExpandedNodeId(null, v));

        /// <inheritdoc/>
        public void WriteStatusCodeArray(string? fieldName, ArrayOf<StatusCode> values) =>
            WriteArray(values, v => WriteStatusCode(null, v));

        /// <inheritdoc/>
        public void WriteDiagnosticInfoArray(string? fieldName, ArrayOf<DiagnosticInfo> values) =>
            WriteArray(values, v => WriteDiagnosticInfo(null, v));

        /// <inheritdoc/>
        public void WriteQualifiedNameArray(string? fieldName, ArrayOf<QualifiedName> values) =>
            WriteArray(values, v => WriteQualifiedName(null, v));

        /// <inheritdoc/>
        public void WriteLocalizedTextArray(string? fieldName, ArrayOf<LocalizedText> values) =>
            WriteArray(values, v => WriteLocalizedText(null, v));

        /// <inheritdoc/>
        public void WriteVariantArray(string? fieldName, ArrayOf<Variant> values) =>
            WriteArray(values, v => WriteVariant(null, in v));

        /// <inheritdoc/>
        public void WriteDataValueArray(string? fieldName, ArrayOf<DataValue> values) =>
            WriteArray(values, v => WriteDataValue(null, in v));

        /// <inheritdoc/>
        public void WriteExtensionObjectArray(string? fieldName, ArrayOf<ExtensionObject> values) =>
            WriteArray(values, v => WriteExtensionObject(null, v));

        /// <inheritdoc/>
        public void WriteEncodeableArray<T>(string? fieldName, ArrayOf<T> values)
            where T : IEncodeable, new() => WriteArray(values, v => WriteEncodeable(null, v));

        /// <inheritdoc/>
        public void WriteEncodeableArray<T>(string? fieldName, ArrayOf<T> values, ExpandedNodeId encodeableTypeId)
            where T : IEncodeable => WriteArray(values, v => WriteEncodeable(null, v, encodeableTypeId));

        /// <inheritdoc/>
        public void WriteEncodeableArrayAsExtensionObjects<T>(string? fieldName, ArrayOf<T> values)
            where T : IEncodeable => WriteArray(values, v => WriteEncodeableAsExtensionObject(null, v));

        /// <inheritdoc/>
        public void WriteEnumeratedArray<T>(string? fieldName, ArrayOf<T> values)
            where T : struct, Enum => WriteArray(values, v => WriteEnumerated(null, v));

        /// <inheritdoc/>
        public void WriteEnumeratedArray(string? fieldName, ArrayOf<EnumValue> values) =>
            WriteArray(values, v => WriteEnumerated(null, v));

        /// <inheritdoc/>
        public void WriteEncodeableMatrix<T>(string? fieldName, MatrixOf<T> values)
            where T : IEncodeable, new() => WriteMatrix(values, a => WriteEncodeableArray(null, a));

        /// <inheritdoc/>
        public void WriteEncodeableMatrix<T>(string? fieldName, MatrixOf<T> values, ExpandedNodeId encodeableTypeId)
            where T : IEncodeable => WriteMatrix(values, a => WriteEncodeableArray(null, a, encodeableTypeId));
    }
}
