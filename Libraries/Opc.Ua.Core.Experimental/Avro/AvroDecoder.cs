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
using System.Collections.Generic;
using System.IO;
using Opc.Ua;
using Opc.Ua.Types;

namespace Opc.Ua.Core.Experimental
{
    /// <summary>
    /// Decodes OPC UA values using the experimental Avro binary mapping.
    /// </summary>
    public sealed partial class AvroDecoder : IDecoder
    {
        private readonly Stream m_stream;
        private readonly AvroBinaryReader m_reader;
        private readonly bool m_leaveOpen;

        /// <summary>
        /// Initializes a new AvroDecoder instance for the experimental OPC UA encoding support.
        /// </summary>
        /// <param name="buffer">The encoded payload buffer to decode.</param>
        /// <param name="context">The service message context that supplies namespace, server URI, and encodeable type resolution tables.</param>
        public AvroDecoder(byte[] buffer, IServiceMessageContext context)
            : this(new MemoryStream(buffer, false), context, false) { }

        /// <summary>
        /// Initializes a new AvroDecoder instance for the experimental OPC UA encoding support.
        /// </summary>
        /// <param name="stream">The stream that receives or supplies the encoded payload.</param>
        /// <param name="context">The service message context that supplies namespace, server URI, and encodeable type resolution tables.</param>
        /// <param name="leaveOpen">True to leave the caller-owned stream open when the codec is closed.</param>
        public AvroDecoder(Stream stream, IServiceMessageContext context, bool leaveOpen = true)
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
            m_stream = stream ?? throw new ArgumentNullException(nameof(stream));
            m_leaveOpen = leaveOpen;
            m_reader = new AvroBinaryReader(m_stream);
        }

        /// <inheritdoc/>
        public EncodingType EncodingType => AvroEncoder.AvroEncodingType;

        /// <inheritdoc/>
        public IServiceMessageContext Context { get; }

        /// <inheritdoc/>
        public void Dispose() => Close();

        /// <inheritdoc/>
        public void Close()
        {
            if (!m_leaveOpen)
            {
                m_stream.Dispose();
            }
        }

        /// <inheritdoc/>
        public void SetMappingTables(NamespaceTable namespaceUris, StringTable serverUris) { }

        /// <inheritdoc/>
        public void PushNamespace(string namespaceUri) { }

        /// <inheritdoc/>
        public void PopNamespace() { }

        /// <inheritdoc/>
        public T DecodeMessage<T>()
            where T : IEncodeable
        {
            T value =
                Activator.CreateInstance<T>()
                ?? throw new NotSupportedException($"Cannot create {typeof(T).FullName}.");
            value.Decode(this);
            return value;
        }

        /// <inheritdoc/>
        public bool ReadBoolean(string? fieldName) => m_reader.ReadBoolean();

        /// <inheritdoc/>
        public sbyte ReadSByte(string? fieldName) => checked((sbyte)m_reader.ReadInt());

        /// <inheritdoc/>
        public byte ReadByte(string? fieldName) => checked((byte)m_reader.ReadInt());

        /// <inheritdoc/>
        public short ReadInt16(string? fieldName) => checked((short)m_reader.ReadInt());

        /// <inheritdoc/>
        public ushort ReadUInt16(string? fieldName) => checked((ushort)m_reader.ReadInt());

        /// <inheritdoc/>
        public int ReadInt32(string? fieldName) => m_reader.ReadInt();

        /// <inheritdoc/>
        public uint ReadUInt32(string? fieldName) => unchecked((uint)m_reader.ReadInt());

        /// <inheritdoc/>
        public long ReadInt64(string? fieldName) => m_reader.ReadLong();

        /// <inheritdoc/>
        public ulong ReadUInt64(string? fieldName) => unchecked((ulong)m_reader.ReadLong());

        /// <inheritdoc/>
        public float ReadFloat(string? fieldName) => m_reader.ReadFloat();

        /// <inheritdoc/>
        public double ReadDouble(string? fieldName) => m_reader.ReadDouble();

        /// <inheritdoc/>
        public string? ReadString(string? fieldName) => ReadNullable(() => m_reader.ReadString());

        /// <inheritdoc/>
        public DateTimeUtc ReadDateTime(string? fieldName) => new DateTimeUtc(m_reader.ReadLong());

        /// <inheritdoc/>
        public Uuid ReadGuid(string? fieldName) => new Uuid(m_reader.ReadFixed(16));

        /// <inheritdoc/>
        public ByteString ReadByteString(string? fieldName)
        {
            byte[]? bytes = ReadNullable(() => m_reader.ReadBytes());
            return bytes == null ? default : ByteString.From(bytes);
        }

        /// <inheritdoc/>
        public XmlElement ReadXmlElement(string? fieldName) => XmlElement.From(ReadString(fieldName));

        /// <inheritdoc/>
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
                _ => throw new NotSupportedException($"Unsupported NodeId identifier type {type}."),
            };
        }

        /// <inheritdoc/>
        public ExpandedNodeId ReadExpandedNodeId(string? fieldName) =>
            new ExpandedNodeId(ReadNodeId(null), ReadString(null), ReadUInt32(null));

        /// <inheritdoc/>
        public StatusCode ReadStatusCode(string? fieldName) => new StatusCode(ReadUInt32(null));

        /// <inheritdoc/>
        public QualifiedName ReadQualifiedName(string? fieldName)
        {
            ushort namespaceIndex = ReadUInt16(null);
            string? name = ReadString(null);
            return new QualifiedName(name, namespaceIndex);
        }

        /// <inheritdoc/>
        public LocalizedText ReadLocalizedText(string? fieldName)
        {
            long branch = m_reader.ReadLong();

            if (branch == 0)
            {
                return LocalizedText.Null;
            }

            ExpectBranch(branch, 1);
            return new LocalizedText(ReadString(null), ReadString(null));
        }

        /// <inheritdoc/>
        public DiagnosticInfo? ReadDiagnosticInfo(string? fieldName)
        {
            long branch = m_reader.ReadLong();

            if (branch == 0)
            {
                return null;
            }

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

        /// <inheritdoc/>
        public DataValue ReadDataValue(string? fieldName)
        {
            Variant value = ReadNullableValue(() => ReadVariant(null), Variant.Null);
            StatusCode status = ReadNullableValue(() => ReadStatusCode(null), StatusCodes.Good);
            DateTimeUtc sourceTs = ReadNullableValue(() => ReadDateTime(null), DateTimeUtc.MinValue);
            ushort sourcePs = ReadNullableValue(() => ReadUInt16(null), (ushort)0);
            DateTimeUtc serverTs = ReadNullableValue(() => ReadDateTime(null), DateTimeUtc.MinValue);
            ushort serverPs = ReadNullableValue(() => ReadUInt16(null), (ushort)0);

            if (
                value.IsNull
                && status.Equals(StatusCodes.Good, StatusCodeComparison.AllBits)
                && sourceTs.IsNull
                && serverTs.IsNull
                && sourcePs == 0
                && serverPs == 0
            )
            {
                return DataValue.Null;
            }
            return new DataValue(value, status, sourceTs, serverTs, sourcePs, serverPs);
        }

        /// <inheritdoc/>
        public ExtensionObject ReadExtensionObject(string? fieldName)
        {
            ExpandedNodeId typeId = ReadExpandedNodeId(null);
            long branch = m_reader.ReadLong();

            if (branch == 0)
            {
                return new ExtensionObject(typeId);
            }

            if (branch == 1)
            {
                if (!Context.Factory.TryGetEncodeableType(typeId, out IEncodeableType? activator))
                {
                    throw new NotSupportedException(
                        $"Cannot decode Avro ExtensionObject body for unregistered type {typeId}."
                    );
                }
                IEncodeable body = activator.CreateInstance();
                body.Decode(this);
                return new ExtensionObject(typeId, body);
            }
            if (branch == 2)
            {
                return new ExtensionObject(typeId, ByteString.From(m_reader.ReadBytes()));
            }

            if (branch == 3)
            {
                return new ExtensionObject(typeId, XmlElement.From(m_reader.ReadString()));
            }

            throw new FormatException($"Invalid ExtensionObject Avro body branch {branch}.");
        }

        /// <inheritdoc/>
        public T ReadEncodeable<T>(string? fieldName, ExpandedNodeId encodeableTypeId)
            where T : IEncodeable
        {
            if (!Context.Factory.TryGetEncodeableType(encodeableTypeId, out IEncodeableType? activator))
            {
                throw new NotSupportedException($"Cannot decode type {encodeableTypeId}.");
            }

            var value = (T)activator.CreateInstance();
            value.Decode(this);
            return value;
        }

        /// <inheritdoc/>
        public T ReadEncodeable<T>(string? fieldName)
            where T : IEncodeable, new()
        {
            var value = new T();
            value.Decode(this);
            return value;
        }

        /// <inheritdoc/>
        public T ReadEncodeableAsExtensionObject<T>(string? fieldName)
            where T : IEncodeable
        {
            ExtensionObject eo = ReadExtensionObject(fieldName);
            return eo.TryGetValue(out T? value) ? value! : default!;
        }

        /// <inheritdoc/>
        public T ReadEnumerated<T>(string? fieldName)
            where T : struct, Enum => EnumHelper.Int32ToEnum<T>(ReadInt32(fieldName));

        /// <inheritdoc/>
        public EnumValue ReadEnumerated(string? fieldName) => EnumValue.From(ReadInt32(fieldName));

        /// <inheritdoc/>
        public uint ReadSwitchField(IList<string> switches, out string? fieldName)
        {
            fieldName = null;
            return ReadUInt32("switch");
        }

        /// <inheritdoc/>
        public uint ReadEncodingMask(IList<string> masks) => ReadUInt32("encodingMask");

        /// <inheritdoc/>
        public bool HasField(string fieldName) => true;

        private T? ReadNullable<T>(Func<T> read)
            where T : class
        {
            long b = m_reader.ReadLong();
            if (b == 0)
            {
                return null;
            }
            ExpectBranch(b, 1);
            return read();
        }

        private T ReadNullableValue<T>(Func<T> read, T defaultValue)
        {
            long b = m_reader.ReadLong();
            if (b == 0)
            {
                return defaultValue;
            }
            ExpectBranch(b, 1);
            return read();
        }

        private static void ExpectBranch(long actual, long expected)
        {
            if (actual != expected)
            {
                throw new FormatException($"Unexpected Avro union branch {actual}; expected {expected}.");
            }
        }

        private ArrayOf<T> ReadArray<T>(Func<T> read)
        {
            long branch = m_reader.ReadLong();

            if (branch == 0)
            {
                return default;
            }

            ExpectBranch(branch, 1);
            var values = new List<T>();
            while (true)
            {
                long count = m_reader.ReadLong();
                if (count == 0)
                {
                    break;
                }

                if (count < 0)
                {
                    _ = m_reader.ReadLong();
                    count = -count;
                }
                for (long i = 0; i < count; i++)
                {
                    values.Add(read());
                }
            }
            return values.ToArray();
        }

        private MatrixOf<T> ReadMatrix<T>(Func<ArrayOf<T>> readArray)
        {
            long branch = m_reader.ReadLong();

            if (branch == 0)
            {
                return default;
            }

            ExpectBranch(branch, 1);
            int[] dims = ReadInt32Array(null).ToArray() ?? Array.Empty<int>();
            return readArray().ToMatrix(dims);
        }

        /// <inheritdoc/>
        public ArrayOf<bool> ReadBooleanArray(string? fieldName) => ReadArray(() => ReadBoolean(null));

        /// <inheritdoc/>
        public ArrayOf<sbyte> ReadSByteArray(string? fieldName) => ReadArray(() => ReadSByte(null));

        /// <inheritdoc/>
        public ArrayOf<byte> ReadByteArray(string? fieldName) => ReadArray(() => ReadByte(null));

        /// <inheritdoc/>
        public ArrayOf<short> ReadInt16Array(string? fieldName) => ReadArray(() => ReadInt16(null));

        /// <inheritdoc/>
        public ArrayOf<ushort> ReadUInt16Array(string? fieldName) => ReadArray(() => ReadUInt16(null));

        /// <inheritdoc/>
        public ArrayOf<int> ReadInt32Array(string? fieldName) => ReadArray(() => ReadInt32(null));

        /// <inheritdoc/>
        public ArrayOf<uint> ReadUInt32Array(string? fieldName) => ReadArray(() => ReadUInt32(null));

        /// <inheritdoc/>
        public ArrayOf<long> ReadInt64Array(string? fieldName) => ReadArray(() => ReadInt64(null));

        /// <inheritdoc/>
        public ArrayOf<ulong> ReadUInt64Array(string? fieldName) => ReadArray(() => ReadUInt64(null));

        /// <inheritdoc/>
        public ArrayOf<float> ReadFloatArray(string? fieldName) => ReadArray(() => ReadFloat(null));

        /// <inheritdoc/>
        public ArrayOf<double> ReadDoubleArray(string? fieldName) => ReadArray(() => ReadDouble(null));

        /// <inheritdoc/>
        public ArrayOf<string?> ReadStringArray(string? fieldName) => ReadArray(() => ReadString(null));

        /// <inheritdoc/>
        public ArrayOf<DateTimeUtc> ReadDateTimeArray(string? fieldName) => ReadArray(() => ReadDateTime(null));

        /// <inheritdoc/>
        public ArrayOf<Uuid> ReadGuidArray(string? fieldName) => ReadArray(() => ReadGuid(null));

        /// <inheritdoc/>
        public ArrayOf<ByteString> ReadByteStringArray(string? fieldName) => ReadArray(() => ReadByteString(null));

        /// <inheritdoc/>
        public ArrayOf<XmlElement> ReadXmlElementArray(string? fieldName) => ReadArray(() => ReadXmlElement(null));

        /// <inheritdoc/>
        public ArrayOf<NodeId> ReadNodeIdArray(string? fieldName) => ReadArray(() => ReadNodeId(null));

        /// <inheritdoc/>
        public ArrayOf<ExpandedNodeId> ReadExpandedNodeIdArray(string? fieldName) =>
            ReadArray(() => ReadExpandedNodeId(null));

        /// <inheritdoc/>
        public ArrayOf<StatusCode> ReadStatusCodeArray(string? fieldName) => ReadArray(() => ReadStatusCode(null));

        /// <inheritdoc/>
        public ArrayOf<DiagnosticInfo?> ReadDiagnosticInfoArray(string? fieldName) =>
            ReadArray(() => ReadDiagnosticInfo(null));

        /// <inheritdoc/>
        public ArrayOf<QualifiedName> ReadQualifiedNameArray(string? fieldName) =>
            ReadArray(() => ReadQualifiedName(null));

        /// <inheritdoc/>
        public ArrayOf<LocalizedText> ReadLocalizedTextArray(string? fieldName) =>
            ReadArray(() => ReadLocalizedText(null));

        /// <inheritdoc/>
        public ArrayOf<Variant> ReadVariantArray(string? fieldName) => ReadArray(() => ReadVariant(null));

        /// <inheritdoc/>
        public ArrayOf<DataValue> ReadDataValueArray(string? fieldName) => ReadArray(() => ReadDataValue(null));

        /// <inheritdoc/>
        public ArrayOf<ExtensionObject> ReadExtensionObjectArray(string? fieldName) =>
            ReadArray(() => ReadExtensionObject(null));

        /// <summary>
        /// Reads EncodeableArray from the experimental encoded representation.
        /// </summary>
        /// <typeparam name="T">The OPC UA encodeable or value type processed by this member.</typeparam>
        /// <param name="fieldName">The OPC UA field name associated with the encoded member.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public ArrayOf<T> ReadEncodeableArray<T>(string? fieldName)
            where T : IEncodeable, new() => ReadArray(() => ReadEncodeable<T>(null));

        /// <summary>
        /// Reads EncodeableArray from the experimental encoded representation.
        /// </summary>
        /// <typeparam name="T">The OPC UA encodeable or value type processed by this member.</typeparam>
        /// <param name="fieldName">The OPC UA field name associated with the encoded member.</param>
        /// <param name="encodeableTypeId">The expanded type identifier used to resolve the encodeable body.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public ArrayOf<T> ReadEncodeableArray<T>(string? fieldName, ExpandedNodeId encodeableTypeId)
            where T : IEncodeable => ReadArray(() => ReadEncodeable<T>(null, encodeableTypeId));

        /// <summary>
        /// Reads EncodeableArrayAsExtensionObjects from the experimental encoded representation.
        /// </summary>
        /// <typeparam name="T">The OPC UA encodeable or value type processed by this member.</typeparam>
        /// <param name="fieldName">The OPC UA field name associated with the encoded member.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public ArrayOf<T> ReadEncodeableArrayAsExtensionObjects<T>(string? fieldName)
            where T : IEncodeable => ReadArray(() => ReadEncodeableAsExtensionObject<T>(null));

        /// <summary>
        /// Reads EncodeableMatrix from the experimental encoded representation.
        /// </summary>
        /// <typeparam name="T">The OPC UA encodeable or value type processed by this member.</typeparam>
        /// <param name="fieldName">The OPC UA field name associated with the encoded member.</param>
        /// <param name="encodeableTypeId">The expanded type identifier used to resolve the encodeable body.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public MatrixOf<T> ReadEncodeableMatrix<T>(string? fieldName, ExpandedNodeId encodeableTypeId)
            where T : IEncodeable => ReadMatrix(() => ReadEncodeableArray<T>(null, encodeableTypeId));

        /// <summary>
        /// Reads EncodeableMatrix from the experimental encoded representation.
        /// </summary>
        /// <typeparam name="T">The OPC UA encodeable or value type processed by this member.</typeparam>
        /// <param name="fieldName">The OPC UA field name associated with the encoded member.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public MatrixOf<T> ReadEncodeableMatrix<T>(string? fieldName)
            where T : IEncodeable, new() => ReadMatrix(() => ReadEncodeableArray<T>(null));

        /// <inheritdoc/>
        public ArrayOf<T> ReadEnumeratedArray<T>(string? fieldName)
            where T : struct, Enum => ReadArray(() => ReadEnumerated<T>(null));

        /// <inheritdoc/>
        public ArrayOf<EnumValue> ReadEnumeratedArray(string? fieldName) => ReadArray(() => ReadEnumerated(null));
    }
}
