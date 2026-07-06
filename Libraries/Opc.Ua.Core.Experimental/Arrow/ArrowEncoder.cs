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
    /// <summary>
    /// Encodes OPC UA values into the experimental Apache Arrow stream representation.
    /// </summary>
    public sealed class ArrowEncoder : IEncoder
    {
        /// <summary>
        /// Names the default Arrow field used when no OPC UA field name is supplied.
        /// </summary>
        internal const string ValueName = "value";

        /// <summary>
        /// Names the synthetic Arrow field that stores union switch values.
        /// </summary>
        internal const string SwitchName = "__switch";

        /// <summary>
        /// Names the synthetic Arrow field that stores optional-field encoding masks.
        /// </summary>
        internal const string MaskName = "__encodingMask";
        private readonly Stream _stream;
        private readonly bool _ownsStream;
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);
        private bool _closed;

        /// <summary>
        /// Initializes a new ArrowEncoder instance for the experimental OPC UA encoding support.
        /// </summary>
        /// <param name="context">The service message context that supplies namespace, server URI, and encodeable type resolution tables.</param>
        public ArrowEncoder(IServiceMessageContext context)
            : this(new MemoryStream(), context, false) { }

        /// <summary>
        /// Initializes a new ArrowEncoder instance for the experimental OPC UA encoding support.
        /// </summary>
        /// <param name="stream">The stream that receives or supplies the encoded payload.</param>
        /// <param name="context">The service message context that supplies namespace, server URI, and encodeable type resolution tables.</param>
        /// <param name="leaveOpen">True to leave the caller-owned stream open when the codec is closed.</param>
        public ArrowEncoder(Stream stream, IServiceMessageContext context, bool leaveOpen = true)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            Context = context ?? throw new ArgumentNullException(nameof(context));
            _ownsStream = !leaveOpen;
        }

        /// <inheritdoc/>
        public EncodingType EncodingType => EncodingType.Binary;

        /// <inheritdoc/>
        public bool CanOmitFields => false;

        /// <inheritdoc/>
        public IServiceMessageContext Context { get; }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (!_closed)
            {
                Close();
            }
            if (_ownsStream)
            {
                _stream.Dispose();
            }
        }

        /// <inheritdoc/>
        public void PushNamespace(string namespaceUri) { }

        /// <inheritdoc/>
        public void PopNamespace() { }

        /// <inheritdoc/>
        public void SetMappingTables(NamespaceTable namespaceUris, StringTable serverUris) { }

        /// <inheritdoc/>
        public int Close()
        {
            if (_closed)
            {
                throw new ObjectDisposedException(nameof(ArrowEncoder));
            }
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

        /// <inheritdoc/>
        public string? CloseAndReturnText() => Convert.ToBase64String(CloseAndReturnBuffer());

        /// <summary>
        /// Completes the encoder and returns the encoded bytes from its memory stream.
        /// </summary>
        /// <returns>The encoded payload bytes.</returns>
        public byte[] CloseAndReturnBuffer()
        {
            Close();
            if (_stream is MemoryStream ms)
            {
                return ms.ToArray();
            }
            throw new NotSupportedException("ArrowEncoder can only return bytes when backed by a MemoryStream.");
        }

        private void Put(string? name, Slot slot) => _slots[name ?? ValueName] = slot;

        private static NotSupportedException Unsupported(string member) =>
            new($"OPC UA Arrow reference encoder does not yet support {member}.");

        /// <inheritdoc/>
        public void EncodeMessage<T>(T message)
            where T : IEncodeable, new() => WriteEncodeable(ValueName, message);

        /// <inheritdoc/>
        public void EncodeMessage<T>(T message, ExpandedNodeId encodeableTypeId)
            where T : IEncodeable => WriteEncodeable(ValueName, message, encodeableTypeId);

        /// <inheritdoc/>
        public void WriteBoolean(string? fieldName, bool value) => Put(fieldName, A.Bool(value));

        /// <inheritdoc/>
        public void WriteSByte(string? fieldName, sbyte value) => Put(fieldName, A.I8(value));

        /// <inheritdoc/>
        public void WriteByte(string? fieldName, byte value) => Put(fieldName, A.U8(value));

        /// <inheritdoc/>
        public void WriteInt16(string? fieldName, short value) => Put(fieldName, A.I16(value));

        /// <inheritdoc/>
        public void WriteUInt16(string? fieldName, ushort value) => Put(fieldName, A.U16(value));

        /// <inheritdoc/>
        public void WriteInt32(string? fieldName, int value) => Put(fieldName, A.I32(value));

        /// <inheritdoc/>
        public void WriteUInt32(string? fieldName, uint value) => Put(fieldName, A.U32(value));

        /// <inheritdoc/>
        public void WriteInt64(string? fieldName, long value) => Put(fieldName, A.I64(value));

        /// <inheritdoc/>
        public void WriteUInt64(string? fieldName, ulong value) => Put(fieldName, A.U64(value));

        /// <inheritdoc/>
        public void WriteFloat(string? fieldName, float value) => Put(fieldName, A.F32(value));

        /// <inheritdoc/>
        public void WriteDouble(string? fieldName, double value) => Put(fieldName, A.F64(value));

        /// <inheritdoc/>
        public void WriteString(string? fieldName, string? value) => Put(fieldName, A.Str(value));

        /// <inheritdoc/>
        public void WriteDateTime(string? fieldName, DateTimeUtc value) => Put(fieldName, A.DateTime(value));

        /// <inheritdoc/>
        public void WriteGuid(string? fieldName, Uuid value) => Put(fieldName, A.Guid(value));

        /// <inheritdoc/>
        public void WriteByteString(string? fieldName, ByteString value) => Put(fieldName, A.Bytes(value));

#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
        /// <inheritdoc/>
        public void WriteByteString(string? fieldName, ReadOnlySpan<byte> value) =>
            WriteByteString(fieldName, ByteString.From(value));
#endif

        /// <inheritdoc/>
        public void WriteXmlElement(string? fieldName, XmlElement value) => Put(fieldName, A.Str(value.OuterXml));

        /// <inheritdoc/>
        public void WriteNodeId(string? fieldName, NodeId value) => Put(fieldName, A.NodeId(value));

        /// <inheritdoc/>
        public void WriteExpandedNodeId(string? fieldName, ExpandedNodeId value) =>
            Put(fieldName, A.ExpandedNodeId(value));

        /// <inheritdoc/>
        public void WriteStatusCode(string? fieldName, StatusCode value) => Put(fieldName, A.Status(value));

        /// <inheritdoc/>
        public void WriteDiagnosticInfo(string? fieldName, DiagnosticInfo? value) =>
            Put(fieldName, A.Diagnostic(value));

        /// <inheritdoc/>
        public void WriteQualifiedName(string? fieldName, QualifiedName value) =>
            Put(fieldName, A.QualifiedName(value));

        /// <inheritdoc/>
        public void WriteLocalizedText(string? fieldName, LocalizedText value) =>
            Put(fieldName, A.LocalizedText(value));

        /// <inheritdoc/>
        public void WriteVariant(string? fieldName, in Variant value)
        {
            Variant v = value;
            Put(fieldName, A.Variant(v));
        }

        /// <inheritdoc/>
        public void WriteDataValue(string? fieldName, in DataValue value)
        {
            DataValue v = value;
            Put(fieldName, A.DataValue(v));
        }

        /// <inheritdoc/>
        public void WriteExtensionObject(string? fieldName, ExtensionObject value) =>
            Put(fieldName, A.Extension(value));

        /// <inheritdoc/>
        public void WriteEncodeable<T>(string? fieldName, T value)
            where T : IEncodeable, new() => throw Unsupported(nameof(WriteEncodeable));

        /// <inheritdoc/>
        public void WriteEncodeable<T>(string? fieldName, T value, ExpandedNodeId encodeableTypeId)
            where T : IEncodeable => throw Unsupported(nameof(WriteEncodeable));

        /// <inheritdoc/>
        public void WriteEncodeableAsExtensionObject<T>(string? fieldName, T value)
            where T : IEncodeable => WriteExtensionObject(fieldName, new ExtensionObject(value));

        /// <inheritdoc/>
        public void WriteEnumerated<T>(string? fieldName, T value)
            where T : struct, Enum => WriteInt32(fieldName, Convert.ToInt32(value, CultureInfo.InvariantCulture));

        /// <inheritdoc/>
        public void WriteEnumerated(string? fieldName, EnumValue value) => WriteInt32(fieldName, value.Value);

        /// <inheritdoc/>
        public void WriteBooleanArray(string? fieldName, ArrayOf<bool> values) =>
            Put(fieldName, A.List(values, A.BoolMany));

        /// <inheritdoc/>
        public void WriteSByteArray(string? fieldName, ArrayOf<sbyte> values) =>
            Put(fieldName, A.List(values, A.I8Many));

        /// <inheritdoc/>
        public void WriteByteArray(string? fieldName, ArrayOf<byte> values) => Put(fieldName, A.List(values, A.U8Many));

        /// <inheritdoc/>
        public void WriteInt16Array(string? fieldName, ArrayOf<short> values) =>
            Put(fieldName, A.List(values, A.I16Many));

        /// <inheritdoc/>
        public void WriteUInt16Array(string? fieldName, ArrayOf<ushort> values) =>
            Put(fieldName, A.List(values, A.U16Many));

        /// <inheritdoc/>
        public void WriteInt32Array(string? fieldName, ArrayOf<int> values) =>
            Put(fieldName, A.List(values, A.I32Many));

        /// <inheritdoc/>
        public void WriteUInt32Array(string? fieldName, ArrayOf<uint> values) =>
            Put(fieldName, A.List(values, A.U32Many));

        /// <inheritdoc/>
        public void WriteInt64Array(string? fieldName, ArrayOf<long> values) =>
            Put(fieldName, A.List(values, A.I64Many));

        /// <inheritdoc/>
        public void WriteUInt64Array(string? fieldName, ArrayOf<ulong> values) =>
            Put(fieldName, A.List(values, A.U64Many));

        /// <inheritdoc/>
        public void WriteFloatArray(string? fieldName, ArrayOf<float> values) =>
            Put(fieldName, A.List(values, A.F32Many));

        /// <inheritdoc/>
        public void WriteDoubleArray(string? fieldName, ArrayOf<double> values) =>
            Put(fieldName, A.List(values, A.F64Many));

        /// <inheritdoc/>
        public void WriteStringArray(string? fieldName, ArrayOf<string> values) =>
            Put(fieldName, A.List(values, A.StrMany));

        /// <inheritdoc/>
        public void WriteDateTimeArray(string? fieldName, ArrayOf<DateTimeUtc> values) =>
            Put(fieldName, A.List(values, A.DateTimeMany));

        /// <inheritdoc/>
        public void WriteGuidArray(string? fieldName, ArrayOf<Uuid> values) =>
            Put(fieldName, A.List(values, A.GuidMany));

        /// <inheritdoc/>
        public void WriteByteStringArray(string? fieldName, ArrayOf<ByteString> values) =>
            Put(fieldName, A.List(values, A.BytesMany));

        /// <inheritdoc/>
        public void WriteXmlElementArray(string? fieldName, ArrayOf<XmlElement> values) =>
            Put(fieldName, A.List(values.ConvertAll<string>(x => x.OuterXml!), A.StrMany));

        /// <inheritdoc/>
        public void WriteNodeIdArray(string? fieldName, ArrayOf<NodeId> values) =>
            Put(fieldName, A.ListStruct(values, A.NodeId));

        /// <inheritdoc/>
        public void WriteExpandedNodeIdArray(string? fieldName, ArrayOf<ExpandedNodeId> values) =>
            Put(fieldName, A.ListStruct(values, A.ExpandedNodeId));

        /// <inheritdoc/>
        public void WriteStatusCodeArray(string? fieldName, ArrayOf<StatusCode> values) =>
            Put(fieldName, A.List(values.ConvertAll(x => x.Code), A.U32Many));

        /// <inheritdoc/>
        public void WriteDiagnosticInfoArray(string? fieldName, ArrayOf<DiagnosticInfo> values) =>
            Put(fieldName, A.ListStruct(values, A.Diagnostic));

        /// <inheritdoc/>
        public void WriteQualifiedNameArray(string? fieldName, ArrayOf<QualifiedName> values) =>
            Put(fieldName, A.ListStruct(values, A.QualifiedName));

        /// <inheritdoc/>
        public void WriteLocalizedTextArray(string? fieldName, ArrayOf<LocalizedText> values) =>
            Put(fieldName, A.ListStruct(values, A.LocalizedText));

        /// <inheritdoc/>
        public void WriteVariantArray(string? fieldName, ArrayOf<Variant> values) =>
            Put(fieldName, A.ListStruct(values, A.Variant));

        /// <inheritdoc/>
        public void WriteDataValueArray(string? fieldName, ArrayOf<DataValue> values) =>
            Put(fieldName, A.ListStruct(values, A.DataValue));

        /// <inheritdoc/>
        public void WriteExtensionObjectArray(string? fieldName, ArrayOf<ExtensionObject> values) =>
            Put(fieldName, A.ListStruct(values, A.Extension));

        /// <inheritdoc/>
        public void WriteEncodeableArray<T>(string? fieldName, ArrayOf<T> values)
            where T : IEncodeable, new() => throw Unsupported(nameof(WriteEncodeableArray));

        /// <inheritdoc/>
        public void WriteEncodeableArray<T>(string? fieldName, ArrayOf<T> values, ExpandedNodeId encodeableTypeId)
            where T : IEncodeable => throw Unsupported(nameof(WriteEncodeableArray));

        /// <inheritdoc/>
        public void WriteEncodeableArrayAsExtensionObjects<T>(string? fieldName, ArrayOf<T> values)
            where T : IEncodeable =>
            WriteExtensionObjectArray(fieldName, values.ConvertAll(x => new ExtensionObject(x)));

        /// <inheritdoc/>
        public void WriteEnumeratedArray<T>(string? fieldName, ArrayOf<T> values)
            where T : struct, Enum =>
            WriteInt32Array(fieldName, values.ConvertAll(x => Convert.ToInt32(x, CultureInfo.InvariantCulture)));

        /// <inheritdoc/>
        public void WriteEnumeratedArray(string? fieldName, ArrayOf<EnumValue> values) =>
            WriteInt32Array(fieldName, values.ConvertAll(x => x.Value));

        /// <inheritdoc/>
        public void WriteVariantValue(string? fieldName, in Variant value)
        {
            Variant v = value;
            Put(fieldName, A.Variant(v));
        }

        /// <inheritdoc/>
        public void WriteEncodeableMatrix<T>(string? fieldName, MatrixOf<T> values)
            where T : IEncodeable, new() => throw Unsupported(nameof(WriteEncodeableMatrix));

        /// <inheritdoc/>
        public void WriteEncodeableMatrix<T>(string? fieldName, MatrixOf<T> values, ExpandedNodeId encodeableTypeId)
            where T : IEncodeable => throw Unsupported(nameof(WriteEncodeableMatrix));

        /// <inheritdoc/>
        public void WriteSwitchField(uint switchField, out string? fieldName)
        {
            fieldName = null;
            WriteUInt32(SwitchName, switchField);
        }

        /// <inheritdoc/>
        public void WriteEncodingMask(uint encodingMask) => WriteUInt32(MaskName, encodingMask);
    }

    /// <summary>
    /// Decodes OPC UA values from the experimental Apache Arrow stream representation.
    /// </summary>
    public sealed class ArrowDecoder : IDecoder
    {
        private readonly RecordBatch _batch;
        private readonly Dictionary<string, int> _columns = new(StringComparer.Ordinal);
        private bool _closed;

        /// <summary>
        /// Initializes a new ArrowDecoder instance for the experimental OPC UA encoding support.
        /// </summary>
        /// <param name="buffer">The encoded payload buffer to decode.</param>
        /// <param name="context">The service message context that supplies namespace, server URI, and encodeable type resolution tables.</param>
        public ArrowDecoder(byte[] buffer, IServiceMessageContext context)
            : this(new MemoryStream(buffer, false), context) { }

        /// <summary>
        /// Initializes a new ArrowDecoder instance for the experimental OPC UA encoding support.
        /// </summary>
        /// <param name="buffer">The encoded payload buffer to decode.</param>
        /// <param name="context">The service message context that supplies namespace, server URI, and encodeable type resolution tables.</param>
        public ArrowDecoder(ReadOnlyMemory<byte> buffer, IServiceMessageContext context)
            : this(buffer.ToArray(), context) { }

        /// <summary>
        /// Initializes a new ArrowDecoder instance for the experimental OPC UA encoding support.
        /// </summary>
        /// <param name="stream">The stream that receives or supplies the encoded payload.</param>
        /// <param name="context">The service message context that supplies namespace, server URI, and encodeable type resolution tables.</param>
        public ArrowDecoder(Stream stream, IServiceMessageContext context)
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
            using var reader = new ArrowStreamReader(
                stream ?? throw new ArgumentNullException(nameof(stream)),
                leaveOpen: true
            );
            _batch =
                reader.ReadNextRecordBatch() ?? throw new FormatException("Arrow stream contains no record batch.");
            for (int ii = 0; ii < _batch.Schema.FieldsList.Count; ii++)
            {
                _columns[_batch.Schema.GetFieldByIndex(ii).Name] = ii;
            }
        }

        /// <inheritdoc/>
        public EncodingType EncodingType => EncodingType.Binary;

        /// <inheritdoc/>
        public IServiceMessageContext Context { get; }

        /// <inheritdoc/>
        public void Dispose() => Close();

        /// <inheritdoc/>
        public void Close()
        {
            if (!_closed)
            {
                _batch.Dispose();
                _closed = true;
            }
        }

        /// <inheritdoc/>
        public void SetMappingTables(NamespaceTable namespaceUris, StringTable serverUris) { }

        /// <inheritdoc/>
        public void PushNamespace(string namespaceUri) { }

        /// <inheritdoc/>
        public void PopNamespace() { }

        private (Field Field, IArrowArray Array) Col(string? name)
        {
            if (_closed)
            {
                throw new ObjectDisposedException(nameof(ArrowDecoder));
            }
            string key = name ?? ArrowEncoder.ValueName;
            if (!_columns.TryGetValue(key, out int index))
            {
                throw new FormatException($"Arrow field '{key}' is not present.");
            }
            return (_batch.Schema.GetFieldByIndex(index), _batch.Column(index));
        }

        /// <inheritdoc/>
        public T DecodeMessage<T>()
            where T : IEncodeable => throw new NotSupportedException("Arrow message decode is not supported yet.");

        /// <inheritdoc/>
        public bool ReadBoolean(string? fieldName) => ((BooleanArray)Col(fieldName).Array).GetValue(0) ?? false;

        /// <inheritdoc/>
        public sbyte ReadSByte(string? fieldName) => ((Int8Array)Col(fieldName).Array).GetValue(0) ?? default;

        /// <inheritdoc/>
        public byte ReadByte(string? fieldName) => ((UInt8Array)Col(fieldName).Array).GetValue(0) ?? default;

        /// <inheritdoc/>
        public short ReadInt16(string? fieldName) => ((Int16Array)Col(fieldName).Array).GetValue(0) ?? default;

        /// <inheritdoc/>
        public ushort ReadUInt16(string? fieldName) => ((UInt16Array)Col(fieldName).Array).GetValue(0) ?? default;

        /// <inheritdoc/>
        public int ReadInt32(string? fieldName) => ((Int32Array)Col(fieldName).Array).GetValue(0) ?? default;

        /// <inheritdoc/>
        public uint ReadUInt32(string? fieldName) => ((UInt32Array)Col(fieldName).Array).GetValue(0) ?? default;

        /// <inheritdoc/>
        public long ReadInt64(string? fieldName) => ((Int64Array)Col(fieldName).Array).GetValue(0) ?? default;

        /// <inheritdoc/>
        public ulong ReadUInt64(string? fieldName) => ((UInt64Array)Col(fieldName).Array).GetValue(0) ?? default;

        /// <inheritdoc/>
        public float ReadFloat(string? fieldName) => ((FloatArray)Col(fieldName).Array).GetValue(0) ?? default;

        /// <inheritdoc/>
        public double ReadDouble(string? fieldName) => ((DoubleArray)Col(fieldName).Array).GetValue(0) ?? default;

        /// <inheritdoc/>
        public string? ReadString(string? fieldName)
        {
            var a = (StringArray)Col(fieldName).Array;
            return a.IsNull(0) ? null : a.GetString(0);
        }

        /// <inheritdoc/>
        public DateTimeUtc ReadDateTime(string? fieldName)
        {
            var a = (Int64Array)Col(fieldName).Array;
            return a.IsNull(0) ? default : new DateTimeUtc(a.GetValue(0) ?? 0);
        }

        /// <inheritdoc/>
        public Uuid ReadGuid(string? fieldName) => A.ReadGuid(Col(fieldName).Array, 0);

        /// <inheritdoc/>
        public ByteString ReadByteString(string? fieldName) => A.ReadBytes(Col(fieldName).Array, 0);

        /// <inheritdoc/>
        public XmlElement ReadXmlElement(string? fieldName)
        {
            string? xml = ReadString(fieldName);
            return xml == null ? default! : (XmlElement)xml;
        }

        /// <inheritdoc/>
        public NodeId ReadNodeId(string? fieldName) => A.ReadNodeId(Col(fieldName).Array, 0);

        /// <inheritdoc/>
        public ExpandedNodeId ReadExpandedNodeId(string? fieldName) => A.ReadExpandedNodeId(Col(fieldName).Array, 0);

        /// <inheritdoc/>
        public StatusCode ReadStatusCode(string? fieldName) => new StatusCode(ReadUInt32(fieldName));

        /// <inheritdoc/>
        public DiagnosticInfo? ReadDiagnosticInfo(string? fieldName) => A.ReadDiagnostic(Col(fieldName).Array, 0);

        /// <inheritdoc/>
        public QualifiedName ReadQualifiedName(string? fieldName) => A.ReadQualifiedName(Col(fieldName).Array, 0);

        /// <inheritdoc/>
        public LocalizedText ReadLocalizedText(string? fieldName) => A.ReadLocalizedText(Col(fieldName).Array, 0);

        /// <inheritdoc/>
        public Variant ReadVariant(string? fieldName) => A.ReadVariant(Col(fieldName).Array, 0);

        /// <inheritdoc/>
        public DataValue ReadDataValue(string? fieldName) => A.ReadDataValue(Col(fieldName).Array, 0);

        /// <inheritdoc/>
        public ExtensionObject ReadExtensionObject(string? fieldName) => A.ReadExtension(Col(fieldName).Array, 0);

        /// <inheritdoc/>
        public T ReadEncodeable<T>(string? fieldName, ExpandedNodeId encodeableTypeId)
            where T : IEncodeable =>
            throw new NotSupportedException("Arrow encodeable decode by type id is not supported yet.");

        /// <inheritdoc/>
        public T ReadEncodeable<T>(string? fieldName)
            where T : IEncodeable, new() =>
            throw new NotSupportedException("Arrow encodeable decode is not supported yet.");

        /// <inheritdoc/>
        public T ReadEncodeableAsExtensionObject<T>(string? fieldName)
            where T : IEncodeable =>
            throw new NotSupportedException("Arrow abstract encodeable decode is not supported yet.");

        /// <inheritdoc/>
        public T ReadEnumerated<T>(string? fieldName)
            where T : struct, Enum => (T)Enum.ToObject(typeof(T), ReadInt32(fieldName));

        /// <inheritdoc/>
        public EnumValue ReadEnumerated(string? fieldName) => new EnumValue(ReadInt32(fieldName));

        /// <inheritdoc/>
        public ArrayOf<bool> ReadBooleanArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadBoolMany);

        /// <inheritdoc/>
        public ArrayOf<sbyte> ReadSByteArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadI8Many);

        /// <inheritdoc/>
        public ArrayOf<byte> ReadByteArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadU8Many);

        /// <inheritdoc/>
        public ArrayOf<short> ReadInt16Array(string? fieldName) => A.ReadList(Col(fieldName), A.ReadI16Many);

        /// <inheritdoc/>
        public ArrayOf<ushort> ReadUInt16Array(string? fieldName) => A.ReadList(Col(fieldName), A.ReadU16Many);

        /// <inheritdoc/>
        public ArrayOf<int> ReadInt32Array(string? fieldName) => A.ReadList(Col(fieldName), A.ReadI32Many);

        /// <inheritdoc/>
        public ArrayOf<uint> ReadUInt32Array(string? fieldName) => A.ReadList(Col(fieldName), A.ReadU32Many);

        /// <inheritdoc/>
        public ArrayOf<long> ReadInt64Array(string? fieldName) => A.ReadList(Col(fieldName), A.ReadI64Many);

        /// <inheritdoc/>
        public ArrayOf<ulong> ReadUInt64Array(string? fieldName) => A.ReadList(Col(fieldName), A.ReadU64Many);

        /// <inheritdoc/>
        public ArrayOf<float> ReadFloatArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadF32Many);

        /// <inheritdoc/>
        public ArrayOf<double> ReadDoubleArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadF64Many);

        /// <inheritdoc/>
        public ArrayOf<string?> ReadStringArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadStrMany);

        /// <inheritdoc/>
        public ArrayOf<DateTimeUtc> ReadDateTimeArray(string? fieldName) =>
            A.ReadList(Col(fieldName), A.ReadDateTimeMany);

        /// <inheritdoc/>
        public ArrayOf<Uuid> ReadGuidArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadGuidMany);

        /// <inheritdoc/>
        public ArrayOf<ByteString> ReadByteStringArray(string? fieldName) =>
            A.ReadList(Col(fieldName), A.ReadBytesMany);

        /// <inheritdoc/>
        public ArrayOf<XmlElement> ReadXmlElementArray(string? fieldName) =>
            ReadStringArray(fieldName).ConvertAll(x => x == null ? default! : (XmlElement)x);

        /// <inheritdoc/>
        public ArrayOf<NodeId> ReadNodeIdArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadNodeIdMany);

        /// <inheritdoc/>
        public ArrayOf<ExpandedNodeId> ReadExpandedNodeIdArray(string? fieldName) =>
            A.ReadList(Col(fieldName), A.ReadExpandedNodeIdMany);

        /// <inheritdoc/>
        public ArrayOf<StatusCode> ReadStatusCodeArray(string? fieldName) =>
            A.ReadList(Col(fieldName), A.ReadStatusMany);

        /// <inheritdoc/>
        public ArrayOf<DiagnosticInfo?> ReadDiagnosticInfoArray(string? fieldName) =>
            A.ReadList(Col(fieldName), A.ReadDiagnosticMany);

        /// <inheritdoc/>
        public ArrayOf<QualifiedName> ReadQualifiedNameArray(string? fieldName) =>
            A.ReadList(Col(fieldName), A.ReadQualifiedNameMany);

        /// <inheritdoc/>
        public ArrayOf<LocalizedText> ReadLocalizedTextArray(string? fieldName) =>
            A.ReadList(Col(fieldName), A.ReadLocalizedTextMany);

        /// <inheritdoc/>
        public ArrayOf<Variant> ReadVariantArray(string? fieldName) => A.ReadList(Col(fieldName), A.ReadVariantMany);

        /// <inheritdoc/>
        public ArrayOf<DataValue> ReadDataValueArray(string? fieldName) =>
            A.ReadList(Col(fieldName), A.ReadDataValueMany);

        /// <inheritdoc/>
        public ArrayOf<ExtensionObject> ReadExtensionObjectArray(string? fieldName) =>
            A.ReadList(Col(fieldName), A.ReadExtensionMany);

        /// <summary>
        /// Reads EncodeableArray from the experimental encoded representation.
        /// </summary>
        /// <typeparam name="T">The OPC UA encodeable or value type processed by this member.</typeparam>
        /// <param name="fieldName">The OPC UA field name associated with the encoded member.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public ArrayOf<T> ReadEncodeableArray<T>(string? fieldName)
            where T : IEncodeable, new() =>
            throw new NotSupportedException("Arrow encodeable arrays are not supported yet.");

        /// <summary>
        /// Reads EncodeableArray from the experimental encoded representation.
        /// </summary>
        /// <typeparam name="T">The OPC UA encodeable or value type processed by this member.</typeparam>
        /// <param name="fieldName">The OPC UA field name associated with the encoded member.</param>
        /// <param name="encodeableTypeId">The expanded type identifier used to resolve the encodeable body.</param>
        /// <returns>The result produced by this codec helper.</returns>
        /// <exception cref="NotSupportedException">The requested OPC UA value shape is not supported by this experimental codec.</exception>
        public ArrayOf<T> ReadEncodeableArray<T>(string? fieldName, ExpandedNodeId encodeableTypeId)
            where T : IEncodeable => throw new NotSupportedException("Arrow encodeable arrays are not supported yet.");

        /// <summary>
        /// Reads EncodeableArrayAsExtensionObjects from the experimental encoded representation.
        /// </summary>
        /// <typeparam name="T">The OPC UA encodeable or value type processed by this member.</typeparam>
        /// <param name="fieldName">The OPC UA field name associated with the encoded member.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public ArrayOf<T> ReadEncodeableArrayAsExtensionObjects<T>(string? fieldName)
            where T : IEncodeable =>
            throw new NotSupportedException("Arrow abstract encodeable arrays are not supported yet.");

        /// <summary>
        /// Reads EncodeableMatrix from the experimental encoded representation.
        /// </summary>
        /// <typeparam name="T">The OPC UA encodeable or value type processed by this member.</typeparam>
        /// <param name="fieldName">The OPC UA field name associated with the encoded member.</param>
        /// <param name="encodeableTypeId">The expanded type identifier used to resolve the encodeable body.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public MatrixOf<T> ReadEncodeableMatrix<T>(string? fieldName, ExpandedNodeId encodeableTypeId)
            where T : IEncodeable =>
            throw new NotSupportedException("Arrow encodeable matrices are not supported yet.");

        /// <summary>
        /// Reads EncodeableMatrix from the experimental encoded representation.
        /// </summary>
        /// <typeparam name="T">The OPC UA encodeable or value type processed by this member.</typeparam>
        /// <param name="fieldName">The OPC UA field name associated with the encoded member.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public MatrixOf<T> ReadEncodeableMatrix<T>(string? fieldName)
            where T : IEncodeable, new() =>
            throw new NotSupportedException("Arrow encodeable matrices are not supported yet.");

        /// <inheritdoc/>
        public ArrayOf<T> ReadEnumeratedArray<T>(string? fieldName)
            where T : struct, Enum => ReadInt32Array(fieldName).ConvertAll(x => (T)Enum.ToObject(typeof(T), x));

        /// <inheritdoc/>
        public ArrayOf<EnumValue> ReadEnumeratedArray(string? fieldName) =>
            ReadInt32Array(fieldName).ConvertAll(x => new EnumValue(x));

        /// <inheritdoc/>
        public Variant ReadVariantValue(string? fieldName, TypeInfo typeInfo) => ReadVariant(fieldName);

        /// <inheritdoc/>
        public uint ReadSwitchField(IList<string> switches, out string? fieldName)
        {
            fieldName = null;
            return ReadUInt32(ArrowEncoder.SwitchName);
        }

        /// <inheritdoc/>
        public uint ReadEncodingMask(IList<string> masks) =>
            HasField(ArrowEncoder.MaskName) ? ReadUInt32(ArrowEncoder.MaskName) : 0;

        /// <inheritdoc/>
        public bool HasField(string fieldName) => _columns.ContainsKey(fieldName);
    }

    /// <summary>
    /// Pairs an Arrow field template with the single-column array produced for an encoded OPC UA value.
    /// </summary>
    /// <param name="Template">The input required by this experimental codec helper.</param>
    /// <param name="Array">The input required by this experimental codec helper.</param>
    internal sealed record Slot(Field Template, IArrowArray Array)
    {
        /// <summary>
        /// Creates an Arrow field with the supplied column name and this slot's template metadata.
        /// </summary>
        /// <param name="name">The field or column name to assign.</param>
        /// <returns>The Arrow field with the supplied name.</returns>
        public Field Field(string name) => new(name, Template.DataType, Template.IsNullable, Template.Metadata);
    }

    /// <summary>
    /// Builds and reads the Arrow arrays used by the experimental Arrow encoder and decoder.
    /// </summary>
    internal static class A
    {
        private static readonly MemoryAllocator Alloc = MemoryAllocator.Default.Value;

        private static Field F(string n, IArrowType t, bool nullable = true) => new(n, t, nullable, null);

        private static ArrowBuffer B<T>(params T[] values)
            where T : struct
        {
            var b = new ArrowBuffer.Builder<T>(values.Length);
            b.Append(values.AsSpan());
            return b.Build(Alloc);
        }

        private static ArrowBuffer V(int length, bool valid)
        {
            var b = new ArrowBuffer.BitmapBuilder(length);
            b.AppendRange(valid, length);
            return b.Build(Alloc);
        }

        /// <summary>
        /// Creates an Arrow slot containing one Boolean value.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot Bool(bool v)
        {
            var b = new BooleanArray.Builder();
            b.Append(v);
            return new(F(string.Empty, BooleanType.Default, false), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one signed 8-bit integer.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot I8(sbyte v)
        {
            var b = new Int8Array.Builder();
            b.Append(v);
            return new(F(string.Empty, Int8Type.Default, false), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one unsigned 8-bit integer.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot U8(byte v)
        {
            var b = new UInt8Array.Builder();
            b.Append(v);
            return new(F(string.Empty, UInt8Type.Default, false), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one signed 16-bit integer.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot I16(short v)
        {
            var b = new Int16Array.Builder();
            b.Append(v);
            return new(F(string.Empty, Int16Type.Default, false), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one unsigned 16-bit integer.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot U16(ushort v)
        {
            var b = new UInt16Array.Builder();
            b.Append(v);
            return new(F(string.Empty, UInt16Type.Default, false), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one signed 32-bit integer.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot I32(int v)
        {
            var b = new Int32Array.Builder();
            b.Append(v);
            return new(F(string.Empty, Int32Type.Default, false), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one unsigned 32-bit integer.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot U32(uint v)
        {
            var b = new UInt32Array.Builder();
            b.Append(v);
            return new(F(string.Empty, UInt32Type.Default, false), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one signed 64-bit integer.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot I64(long v)
        {
            var b = new Int64Array.Builder();
            b.Append(v);
            return new(F(string.Empty, Int64Type.Default, false), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one unsigned 64-bit integer.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot U64(ulong v)
        {
            var b = new UInt64Array.Builder();
            b.Append(v);
            return new(F(string.Empty, UInt64Type.Default, false), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one single-precision floating-point value.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot F32(float v)
        {
            var b = new FloatArray.Builder();
            b.Append(v);
            return new(F(string.Empty, FloatType.Default, false), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one double-precision floating-point value.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot F64(double v)
        {
            var b = new DoubleArray.Builder();
            b.Append(v);
            return new(F(string.Empty, DoubleType.Default, false), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one nullable UTF-8 string value.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot Str(string? v)
        {
            var b = new StringArray.Builder();
            if (v == null)
            {
                b.AppendNull();
            }
            else
            {
                b.Append(v);
            }
            return new(F(string.Empty, StringType.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one OPC UA DateTime value as ticks.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot DateTime(DateTimeUtc v)
        {
            var b = new Int64Array.Builder();
            if (v.IsNull)
            {
                b.AppendNull();
            }
            else
            {
                b.Append(v.Value);
            }
            return new(F(string.Empty, Int64Type.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one OPC UA StatusCode value.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot Status(StatusCode v)
        {
            var b = new UInt32Array.Builder();
            b.Append(v.Code);
            return new(F(string.Empty, UInt32Type.Default, false), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one nullable byte-string value.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot Bytes(ByteString v)
        {
            var b = new BinaryArray.Builder();
            if (v.IsNull)
            {
                b.AppendNull();
            }
            else
            {
                b.Append(v.Span);
            }
            return new(F(string.Empty, BinaryType.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow slot containing one OPC UA Guid value.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot Guid(Uuid v) => GuidMany(new[] { v });

        /// <summary>
        /// Creates an Arrow fixed-size binary slot containing OPC UA Guid values.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot GuidMany(ReadOnlyMemory<Uuid> v)
        {
            var bytes = new List<byte>();
            foreach (var x in v.Span)
            {
                bytes.AddRange(x.Guid.ToByteArray());
            }
#pragma warning disable CA2000 // Justification: the Arrow array is handed off to Slot and disposed with the RecordBatch.
            var a = new FixedSizeBinaryArray(
                new ArrayData(
                    new FixedSizeBinaryType(16),
                    v.Length,
                    0,
                    0,
                    new[] { V(v.Length, true), B(bytes.ToArray()) },
                    System.Array.Empty<ArrayData>()
                )
            );
            return new(F(string.Empty, new FixedSizeBinaryType(16)), a);
#pragma warning restore CA2000
        }

        /// <summary>
        /// Creates an Arrow struct slot for an OPC UA NodeId.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot NodeId(NodeId v)
        {
            byte t = v.IsNull ? (byte)0 : (byte)v.IdType;
            uint n = !v.IsNull && v.TryGetValue(out uint numericIdentifier) ? numericIdentifier : 0;
            string? s = !v.IsNull && v.TryGetValue(out string stringIdentifier) ? stringIdentifier : null;
            Uuid g = !v.IsNull && v.TryGetValue(out Guid guidIdentifier) ? new Uuid(guidIdentifier) : default;
            ByteString o = !v.IsNull && v.TryGetValue(out ByteString opaqueIdentifier) ? opaqueIdentifier : default;

            return Struct(
                new() { U16(v.NamespaceIndex), U8(t), U32(n), Str(s), Guid(g), Bytes(o) },
                new() { "namespace", "id_type", "numeric", "string", "guid", "opaque" },
                !v.IsNull
            );
        }

        /// <summary>
        /// Creates an Arrow struct slot for an OPC UA ExpandedNodeId.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot ExpandedNodeId(ExpandedNodeId v) =>
            Struct(
                new() { NodeId(v.InnerNodeId), Str(v.NamespaceUri), U32(v.ServerIndex) },
                new() { "node_id", "namespace_uri", "server_index" },
                !v.IsNull
            );

        /// <summary>
        /// Creates an Arrow struct slot for an OPC UA QualifiedName.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot QualifiedName(QualifiedName v) =>
            Struct(new() { U16(v.NamespaceIndex), Str(v.Name) }, new() { "namespace", "name" }, !v.IsNull);

        /// <summary>
        /// Creates an Arrow struct slot for an OPC UA LocalizedText.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot LocalizedText(LocalizedText v) =>
            Struct(new() { Str(v.Locale), Str(v.Text) }, new() { "locale", "text" }, !v.IsNull);

        /// <summary>
        /// Creates an Arrow struct slot for an OPC UA DataValue.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot DataValue(DataValue v) =>
            Struct(
                new()
                {
                    Variant(v.WrappedValue),
                    Status(v.StatusCode),
                    DateTime(v.SourceTimestamp),
                    U16(v.SourcePicoseconds),
                    DateTime(v.ServerTimestamp),
                    U16(v.ServerPicoseconds),
                },
                new()
                {
                    "value",
                    "status",
                    "source_timestamp",
                    "source_picoseconds",
                    "server_timestamp",
                    "server_picoseconds",
                },
                !v.IsNull
            );

        /// <summary>
        /// Creates an Arrow struct slot for an OPC UA DiagnosticInfo.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot Diagnostic(DiagnosticInfo? v) =>
            v == null
                ? Struct(
                    new() { I32(-1), I32(-1), I32(-1), I32(-1), Str(null), Status(StatusCodes.Good), Null() },
                    new()
                    {
                        "symbolic_id",
                        "namespace_uri",
                        "locale",
                        "localized_text",
                        "additional_info",
                        "inner_status_code",
                        "inner_diagnostic_info",
                    },
                    false
                )
                : Struct(
                    new()
                    {
                        I32(v.SymbolicId),
                        I32(v.NamespaceUri),
                        I32(v.Locale),
                        I32(v.LocalizedText),
                        Str(v.AdditionalInfo),
                        Status(v.InnerStatusCode),
                        Diagnostic(v.InnerDiagnosticInfo),
                    },
                    new()
                    {
                        "symbolic_id",
                        "namespace_uri",
                        "locale",
                        "localized_text",
                        "additional_info",
                        "inner_status_code",
                        "inner_diagnostic_info",
                    }
                );

        /// <summary>
        /// Creates an Arrow struct slot for an OPC UA ExtensionObject.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot Extension(ExtensionObject v)
        {
            ByteString body = default;
            if (v.TryGetAsBinary(out ByteString b))
            {
                body = b;
            }

            return Struct(
                new()
                {
                    ExpandedNodeId(v.TypeId),
                    Union(v.IsNull ? 0 : 1, new() { Null(), Bytes(body) }, new() { "null", "binary" }),
                },
                new() { "type_id", "body" },
                !v.IsNull
            );
        }

        /// <summary>
        /// Creates an Arrow slot containing a null value.
        /// </summary>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot Null()
        {
            var b = new NullArray.Builder();
            b.AppendNull();
            return new(F(string.Empty, NullType.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Creates an Arrow struct slot from child slots and field names.
        /// </summary>
        /// <param name="children">The child Arrow slots that make up the composite value.</param>
        /// <param name="names">The field names for the child Arrow slots.</param>
        /// <param name="valid">True when the composite Arrow value is not null.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot Struct(List<Slot> children, List<string> names, bool valid = true)
        {
            var fields = children.Select((c, i) => c.Field(names[i])).ToList();
            var t = new StructType(fields);
#pragma warning disable CA2000 // Justification: the Arrow array is handed off to Slot and disposed with the RecordBatch.
            return new(
                F(string.Empty, t),
                new StructArray(t, 1, children.Select(c => c.Array), V(1, valid), valid ? 0 : 1, 0)
            );
#pragma warning restore CA2000
        }

        /// <summary>
        /// Creates a dense Arrow union slot with the selected child branch.
        /// </summary>
        /// <param name="selected">The dense union branch selected for the Arrow value.</param>
        /// <param name="children">The child Arrow slots that make up the composite value.</param>
        /// <param name="names">The field names for the child Arrow slots.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot Union(int selected, List<Slot> children, List<string> names)
        {
            var fields = children.Select((c, i) => c.Field(names[i])).ToList();
            // The dense-union type-ids buffer stores `selected`, so the declared union type-ids
            // must contain it or external Arrow readers (pyarrow/ADBC) cannot map a slot to its
            // child. When `selected` is a child index (e.g. the ExtensionObject body union) the
            // natural [0,1,..] mapping is correct; when it is an OPC BuiltInType code (Variant
            // union, whose value is always child 1) declare [0, selected].
            IEnumerable<int> typeIds =
                selected < fields.Count ? Enumerable.Range(0, fields.Count) : new[] { 0, selected };
            var t = new UnionType(fields, typeIds, UnionMode.Dense);
#pragma warning disable CA2000 // Justification: the Arrow array is handed off to Slot and disposed with the RecordBatch.
            return new(
                F(string.Empty, t),
                new DenseUnionArray(t, 1, children.Select(c => c.Array), B((byte)selected), B(0), 0, 0)
            );
#pragma warning restore CA2000
        }

        /// <summary>
        /// Creates an Arrow union slot for an OPC UA Variant.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot Variant(Variant v)
        {
            if (v.IsNull)
            {
                return Union(0, new() { Null() }, new() { "null" });
            }
            if (v.TypeInfo.IsMatrix && v.TypeInfo.BuiltInType == BuiltInType.Int32)
            {
                return Union(
                    21,
                    new() { Null(), Matrix(v.GetInt32Matrix(), I32Many) },
                    new() { "null", "matrix_int32" }
                );
            }
            object? x = v.AsBoxedObject(Opc.Ua.Variant.BoxingBehavior.None);
            return x switch
            {
                int i => Union(6, new() { Null(), I32(i) }, new() { "null", "int32" }),
                string s => Union(12, new() { Null(), Str(s) }, new() { "null", "string" }),
                ExtensionObject e => Union(17, new() { Null(), Extension(e) }, new() { "null", "extensionobject" }),
                DataValue d => Union(18, new() { Null(), DataValue(d) }, new() { "null", "datavalue" }),
                MatrixOf<int> m => Union(21, new() { Null(), Matrix(m, I32Many) }, new() { "null", "matrix_int32" }),
                _ => throw new NotSupportedException($"Arrow Variant branch '{v.TypeInfo}' is not supported yet."),
            };
        }

        /// <summary>
        /// Creates an Arrow struct slot containing matrix dimensions and values.
        /// </summary>
        /// <typeparam name="T">The OPC UA encodeable or value type processed by this member.</typeparam>
        /// <param name="values">The values to encode or decode.</param>
        /// <param name="elem">The delegate that builds a slot for list or matrix elements.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot Matrix<T>(MatrixOf<T> values, Func<ReadOnlyMemory<T>, Slot> elem) =>
            Struct(
                new() { List(new ArrayOf<int>(values.Dimensions), I32Many), List(new ArrayOf<T>(values.Memory), elem) },
                new() { "dimensions", "values" },
                !values.IsNull
            );

        /// <summary>
        /// Creates an Arrow list slot from an OPC UA array.
        /// </summary>
        /// <typeparam name="T">The OPC UA encodeable or value type processed by this member.</typeparam>
        /// <param name="values">The values to encode or decode.</param>
        /// <param name="elem">The delegate that builds a slot for list or matrix elements.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot List<T>(ArrayOf<T> values, Func<ReadOnlyMemory<T>, Slot> elem)
        {
            Slot child = elem(values.IsNull ? ReadOnlyMemory<T>.Empty : values.Memory);
            var t = new ListType(child.Field("item"));

#pragma warning disable CA2000 // Justification: the Arrow array is handed off to Slot and disposed with the RecordBatch.
            return new(
                F(string.Empty, t),
                new ListArray(
                    t,
                    1,
                    B(0, values.IsNull ? 0 : values.Count),
                    child.Array,
                    V(1, !values.IsNull),
                    values.IsNull ? 1 : 0,
                    0
                )
            );
#pragma warning restore CA2000
        }

        /// <summary>
        /// Creates an Arrow list slot for a single struct element.
        /// </summary>
        /// <typeparam name="T">The OPC UA encodeable or value type processed by this member.</typeparam>
        /// <param name="values">The values to encode or decode.</param>
        /// <param name="elem">The delegate that builds a slot for list or matrix elements.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot ListStruct<T>(ArrayOf<T> values, Func<T, Slot> elem) =>
            values.Count == 1
                ? List(values, s => elem(s.Span[0]))
                : throw new NotSupportedException("Struct lists currently support one element.");

        /// <summary>
        /// Reads Boolean values from an Arrow array segment.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot BoolMany(ReadOnlyMemory<bool> v)
        {
            var b = new BooleanArray.Builder();
            foreach (bool x in v.Span)
            {
                b.Append(x);
            }
            return new(F(string.Empty, BooleanType.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Reads signed 8-bit integer values from an Arrow array segment.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot I8Many(ReadOnlyMemory<sbyte> v)
        {
            var b = new Int8Array.Builder();
            foreach (sbyte x in v.Span)
            {
                b.Append(x);
            }
            return new(F(string.Empty, Int8Type.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Reads unsigned 8-bit integer values from an Arrow array segment.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot U8Many(ReadOnlyMemory<byte> v)
        {
            var b = new UInt8Array.Builder();
            foreach (byte x in v.Span)
            {
                b.Append(x);
            }
            return new(F(string.Empty, UInt8Type.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Reads signed 16-bit integer values from an Arrow array segment.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot I16Many(ReadOnlyMemory<short> v)
        {
            var b = new Int16Array.Builder();
            foreach (short x in v.Span)
            {
                b.Append(x);
            }
            return new(F(string.Empty, Int16Type.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Reads unsigned 16-bit integer values from an Arrow array segment.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot U16Many(ReadOnlyMemory<ushort> v)
        {
            var b = new UInt16Array.Builder();
            foreach (ushort x in v.Span)
            {
                b.Append(x);
            }
            return new(F(string.Empty, UInt16Type.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Reads signed 32-bit integer values from an Arrow array segment.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot I32Many(ReadOnlyMemory<int> v)
        {
            var b = new Int32Array.Builder();
            foreach (int x in v.Span)
            {
                b.Append(x);
            }
            return new(F(string.Empty, Int32Type.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Reads unsigned 32-bit integer values from an Arrow array segment.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot U32Many(ReadOnlyMemory<uint> v)
        {
            var b = new UInt32Array.Builder();
            foreach (uint x in v.Span)
            {
                b.Append(x);
            }
            return new(F(string.Empty, UInt32Type.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Reads signed 64-bit integer values from an Arrow array segment.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot I64Many(ReadOnlyMemory<long> v)
        {
            var b = new Int64Array.Builder();
            foreach (long x in v.Span)
            {
                b.Append(x);
            }
            return new(F(string.Empty, Int64Type.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Reads unsigned 64-bit integer values from an Arrow array segment.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot U64Many(ReadOnlyMemory<ulong> v)
        {
            var b = new UInt64Array.Builder();
            foreach (ulong x in v.Span)
            {
                b.Append(x);
            }
            return new(F(string.Empty, UInt64Type.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Reads single-precision floating-point values from an Arrow array segment.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot F32Many(ReadOnlyMemory<float> v)
        {
            var b = new FloatArray.Builder();
            foreach (float x in v.Span)
            {
                b.Append(x);
            }
            return new(F(string.Empty, FloatType.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Reads double-precision floating-point values from an Arrow array segment.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot F64Many(ReadOnlyMemory<double> v)
        {
            var b = new DoubleArray.Builder();
            foreach (double x in v.Span)
            {
                b.Append(x);
            }
            return new(F(string.Empty, DoubleType.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Reads nullable UTF-8 string values from an Arrow array segment.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot StrMany(ReadOnlyMemory<string> v)
        {
            var b = new StringArray.Builder();
            foreach (string x in v.Span)
            {
                if (x == null)
                {
                    b.AppendNull();
                }
                else
                {
                    b.Append(x);
                }
            }
            return new(F(string.Empty, StringType.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Reads OPC UA DateTime values from an Arrow array segment.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot DateTimeMany(ReadOnlyMemory<DateTimeUtc> v)
        {
            var b = new Int64Array.Builder();
            foreach (DateTimeUtc x in v.Span)
            {
                if (x.IsNull)
                {
                    b.AppendNull();
                }
                else
                {
                    b.Append(x.Value);
                }
            }
            return new(F(string.Empty, Int64Type.Default), b.Build(Alloc));
        }

        /// <summary>
        /// Reads OPC UA byte-string values from an Arrow array segment.
        /// </summary>
        /// <param name="v">The input required by this experimental codec helper.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Slot BytesMany(ReadOnlyMemory<ByteString> v)
        {
            var b = new BinaryArray.Builder();
            foreach (ByteString x in v.Span)
            {
                if (x.IsNull)
                {
                    b.AppendNull();
                }
                else
                {
                    b.Append(x.Span);
                }
            }
            return new(F(string.Empty, BinaryType.Default), b.Build(Alloc));
        }

        /// <inheritdoc/>
        public static Uuid ReadGuid(IArrowArray a, int i) => new(((FixedSizeBinaryArray)a).GetBytes(i).ToArray());

        /// <summary>
        /// Reads one OPC UA byte string from an Arrow binary array.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="i">The row or value index to read.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static ByteString ReadBytes(IArrowArray a, int i) =>
            ((BinaryArray)a).IsNull(i) ? default : ByteString.From(((BinaryArray)a).GetBytes(i).ToArray());

        /// <inheritdoc/>
        public static Opc.Ua.NodeId ReadNodeId(IArrowArray a, int i)
        {
            var s = (StructArray)a;
            if (s.IsNull(i))
            {
                return Opc.Ua.NodeId.Null;
            }
            ushort ns = ((UInt16Array)s.Fields[0]).GetValue(i) ?? 0;
            byte t = ((UInt8Array)s.Fields[1]).GetValue(i) ?? 0;
            return (IdType)t switch
            {
                IdType.String => new Opc.Ua.NodeId(((StringArray)s.Fields[3]).GetString(i), ns),
                IdType.Guid => new Opc.Ua.NodeId(ReadGuid(s.Fields[4], i).Guid, ns),
                IdType.Opaque => new Opc.Ua.NodeId(ReadBytes(s.Fields[5], i), ns),
                _ => new Opc.Ua.NodeId(((UInt32Array)s.Fields[2]).GetValue(i) ?? 0, ns),
            };
        }

        /// <inheritdoc/>
        public static ExpandedNodeId ReadExpandedNodeId(IArrowArray a, int i)
        {
            var s = (StructArray)a;
            return new ExpandedNodeId(
                ReadNodeId(s.Fields[0], i),
                ((StringArray)s.Fields[1]).IsNull(i) ? null : ((StringArray)s.Fields[1]).GetString(i),
                ((UInt32Array)s.Fields[2]).GetValue(i) ?? 0
            );
        }

        /// <inheritdoc/>
        public static QualifiedName ReadQualifiedName(IArrowArray a, int i)
        {
            var s = (StructArray)a;
            return new QualifiedName(
                ((StringArray)s.Fields[1]).IsNull(i) ? null : ((StringArray)s.Fields[1]).GetString(i),
                ((UInt16Array)s.Fields[0]).GetValue(i) ?? 0
            );
        }

        /// <inheritdoc/>
        public static LocalizedText ReadLocalizedText(IArrowArray a, int i)
        {
            var s = (StructArray)a;
            return new LocalizedText(
                ((StringArray)s.Fields[0]).IsNull(i) ? null : ((StringArray)s.Fields[0]).GetString(i),
                ((StringArray)s.Fields[1]).IsNull(i) ? null : ((StringArray)s.Fields[1]).GetString(i)
            );
        }

        /// <inheritdoc/>
        public static DataValue ReadDataValue(IArrowArray a, int i)
        {
            var s = (StructArray)a;
            return new DataValue(
                ReadVariant(s.Fields[0], i),
                new StatusCode(((UInt32Array)s.Fields[1]).GetValue(i) ?? 0),
                new DateTimeUtc(((Int64Array)s.Fields[2]).GetValue(i) ?? 0),
                new DateTimeUtc(((Int64Array)s.Fields[4]).GetValue(i) ?? 0),
                ((UInt16Array)s.Fields[3]).GetValue(i) ?? 0,
                ((UInt16Array)s.Fields[5]).GetValue(i) ?? 0
            );
        }

        /// <summary>
        /// Reads one OPC UA DiagnosticInfo from an Arrow struct array.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="i">The row or value index to read.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static DiagnosticInfo? ReadDiagnostic(IArrowArray a, int i)
        {
            var s = (StructArray)a;
            if (s.IsNull(i))
            {
                return null;
            }
            return new DiagnosticInfo
            {
                SymbolicId = ((Int32Array)s.Fields[0]).GetValue(i) ?? -1,
                NamespaceUri = ((Int32Array)s.Fields[1]).GetValue(i) ?? -1,
                Locale = ((Int32Array)s.Fields[2]).GetValue(i) ?? -1,
                LocalizedText = ((Int32Array)s.Fields[3]).GetValue(i) ?? -1,
                AdditionalInfo = ((StringArray)s.Fields[4]).IsNull(i) ? null : ((StringArray)s.Fields[4]).GetString(i),
                InnerStatusCode = new StatusCode(((UInt32Array)s.Fields[5]).GetValue(i) ?? 0),
                InnerDiagnosticInfo = ReadDiagnostic(s.Fields[6], i),
            };
        }

        /// <summary>
        /// Reads one OPC UA ExtensionObject from an Arrow struct array.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="i">The row or value index to read.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static ExtensionObject ReadExtension(IArrowArray a, int i)
        {
            var s = (StructArray)a;
            if (s.IsNull(i))
            {
                return ExtensionObject.Null;
            }
            var u = (DenseUnionArray)s.Fields[1];
            return u.TypeIds[i] == 1
                ? new ExtensionObject(ReadExpandedNodeId(s.Fields[0], i), ReadBytes(u.Fields[1], u.ValueOffsets[i]))
                : new ExtensionObject(ReadExpandedNodeId(s.Fields[0], i));
        }

        /// <inheritdoc/>
        public static Opc.Ua.Variant ReadVariant(IArrowArray a, int i)
        {
            var u = (DenseUnionArray)a;
            int code = u.TypeIds[i];
            int off = u.ValueOffsets[i];
            return code switch
            {
                0 => Opc.Ua.Variant.Null,
                6 => new Opc.Ua.Variant(((Int32Array)u.Fields[1]).GetValue(off) ?? 0),
                12 => new Opc.Ua.Variant(((StringArray)u.Fields[1]).GetString(off)),
                17 => new Opc.Ua.Variant(ReadExtension(u.Fields[1], off)),
                18 => new Opc.Ua.Variant(ReadDataValue(u.Fields[1], off)),
                21 => new Opc.Ua.Variant(ReadMatrixInt32(u.Fields[1], off)),
                _ => throw new NotSupportedException($"Unknown Variant union code {code}."),
            };
        }

        private static MatrixOf<int> ReadMatrixInt32(IArrowArray a, int i)
        {
            var s = (StructArray)a;
            var dims = ReadList((null!, s.Fields[0]), ReadI32Many);
            var vals = ReadList((null!, s.Fields[1]), ReadI32Many);
            return vals.ToMatrix(dims);
        }

        /// <summary>
        /// Reads an OPC UA array from an Arrow list array.
        /// </summary>
        /// <typeparam name="T">The OPC UA encodeable or value type processed by this member.</typeparam>
        /// <param name="c">The Arrow field and array pair to read.</param>
        /// <param name="read">The delegate that reads the list value range.</param>
        /// <returns>The decoded OPC UA array.</returns>
        public static ArrayOf<T> ReadList<T>((Field Field, IArrowArray Array) c, Func<IArrowArray, int, int, T[]> read)
        {
            var l = (ListArray)c.Array;
            if (l.IsNull(0))
            {
                return ArrayOf<T>.Null;
            }
            return new ArrayOf<T>(read(l.Values, l.ValueOffsets[0], l.ValueOffsets[1] - l.ValueOffsets[0]));
        }

        /// <summary>
        /// Reads BoolMany from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static bool[] ReadBoolMany(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ((BooleanArray)a).GetValue(i) ?? false).ToArray();

        /// <summary>
        /// Reads I8Many from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static sbyte[] ReadI8Many(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ((Int8Array)a).GetValue(i) ?? 0).ToArray();

        /// <summary>
        /// Reads U8Many from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static byte[] ReadU8Many(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ((UInt8Array)a).GetValue(i) ?? 0).ToArray();

        /// <summary>
        /// Reads I16Many from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static short[] ReadI16Many(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ((Int16Array)a).GetValue(i) ?? 0).ToArray();

        /// <summary>
        /// Reads U16Many from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static ushort[] ReadU16Many(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ((UInt16Array)a).GetValue(i) ?? 0).ToArray();

        /// <summary>
        /// Reads I32Many from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static int[] ReadI32Many(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ((Int32Array)a).GetValue(i) ?? 0).ToArray();

        /// <summary>
        /// Reads U32Many from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static uint[] ReadU32Many(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ((UInt32Array)a).GetValue(i) ?? 0).ToArray();

        /// <summary>
        /// Reads I64Many from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static long[] ReadI64Many(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ((Int64Array)a).GetValue(i) ?? 0).ToArray();

        /// <summary>
        /// Reads U64Many from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static ulong[] ReadU64Many(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ((UInt64Array)a).GetValue(i) ?? 0).ToArray();

        /// <summary>
        /// Reads F32Many from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static float[] ReadF32Many(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ((FloatArray)a).GetValue(i) ?? 0).ToArray();

        /// <summary>
        /// Reads F64Many from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static double[] ReadF64Many(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ((DoubleArray)a).GetValue(i) ?? 0).ToArray();

        /// <summary>
        /// Reads StrMany from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static string?[] ReadStrMany(IArrowArray a, int s, int n) =>
            Enumerable
                .Range(s, n)
                .Select(i => ((StringArray)a).IsNull(i) ? null : ((StringArray)a).GetString(i))
                .ToArray();

        /// <summary>
        /// Reads DateTimeMany from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static DateTimeUtc[] ReadDateTimeMany(IArrowArray a, int s, int n) =>
            Enumerable
                .Range(s, n)
                .Select(i => ((Int64Array)a).IsNull(i) ? default : new DateTimeUtc(((Int64Array)a).GetValue(i) ?? 0))
                .ToArray();

        /// <summary>
        /// Reads GuidMany from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Uuid[] ReadGuidMany(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ReadGuid(a, i)).ToArray();

        /// <summary>
        /// Reads BytesMany from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static ByteString[] ReadBytesMany(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ReadBytes(a, i)).ToArray();

        /// <summary>
        /// Reads NodeIdMany from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static NodeId[] ReadNodeIdMany(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ReadNodeId(a, i)).ToArray();

        /// <summary>
        /// Reads ExpandedNodeIdMany from the experimental encoded representation.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static ExpandedNodeId[] ReadExpandedNodeIdMany(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ReadExpandedNodeId(a, i)).ToArray();

        /// <summary>
        /// Reads OPC UA StatusCode values from an Arrow array segment.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static StatusCode[] ReadStatusMany(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => new StatusCode(((UInt32Array)a).GetValue(i) ?? 0)).ToArray();

        /// <summary>
        /// Reads OPC UA QualifiedName values from an Arrow array segment.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static QualifiedName[] ReadQualifiedNameMany(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ReadQualifiedName(a, i)).ToArray();

        /// <summary>
        /// Reads OPC UA LocalizedText values from an Arrow array segment.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static LocalizedText[] ReadLocalizedTextMany(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ReadLocalizedText(a, i)).ToArray();

        /// <summary>
        /// Reads OPC UA DiagnosticInfo values from an Arrow array segment.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static DiagnosticInfo?[] ReadDiagnosticMany(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ReadDiagnostic(a, i)).ToArray();

        /// <summary>
        /// Reads OPC UA Variant values from an Arrow array segment.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static Variant[] ReadVariantMany(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ReadVariant(a, i)).ToArray();

        /// <summary>
        /// Reads OPC UA DataValue values from an Arrow array segment.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static DataValue[] ReadDataValueMany(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ReadDataValue(a, i)).ToArray();

        /// <summary>
        /// Reads OPC UA ExtensionObject values from an Arrow array segment.
        /// </summary>
        /// <param name="a">The Arrow array to read.</param>
        /// <param name="s">The first value index in the Arrow segment.</param>
        /// <param name="n">The number of values in the Arrow segment.</param>
        /// <returns>The result produced by this codec helper.</returns>
        public static ExtensionObject[] ReadExtensionMany(IArrowArray a, int s, int n) =>
            Enumerable.Range(s, n).Select(i => ReadExtension(a, i)).ToArray();
    }
}
