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

using Opc.Ua;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Apache.Arrow;
using Apache.Arrow.Arrays;
using Apache.Arrow.Ipc;
using Apache.Arrow.Types;
using Opc.Ua.PubSub.Diagnostics;

namespace Opc.Ua.PubSub.Encoding;

/// <summary>
/// Decodes the experimental Arrow PubSub IPC-stream mapping. It expects
/// one DataSet schema per stream, leading per-row header columns, and
/// typed RawData field columns; unsupported Arrow/OPC UA type pairings
/// throw rather than falling back to blobs or JSON.
/// </summary>
public sealed class ArrowNetworkMessageDecoder : INetworkMessageDecoder
{
    private const string Magic = "OPC-UA-PubSub-Arrow";
    private const string Version = "1";
    private const int HeaderColumnCount = 5;

    /// <inheritdoc/>
    public string TransportProfileUri
    {
        get { return ArrowNetworkMessage.PubSubMqttArrowTransport; }
    }

    /// <summary>
    /// Gets the SchemaId cache used by the decoder.
    /// </summary>
    public SchemaCache SchemaCache { get; } = new();

    /// <summary>
    /// Gets or sets the resolver invoked when a referenced SchemaId is not cached.
    /// </summary>
    public ISchemaResolver? SchemaResolver { get; set; }

    /// <summary>
    /// Ingests an Arrow schema announcement into the decoder cache.
    /// </summary>
    /// <param name="announcement">The schema announcement to ingest.</param>
    public void Ingest(ArrowSchemaAnnouncement announcement)
    {
        SchemaCache.Add(announcement);
    }

    /// <inheritdoc/>
    public async ValueTask<PubSubNetworkMessage?> TryDecodeAsync(
        ReadOnlyMemory<byte> frame,
        PubSubNetworkMessageContext context,
        CancellationToken cancellationToken = default)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }
        cancellationToken.ThrowIfCancellationRequested();
        await Task.CompletedTask.ConfigureAwait(false);
        return DecodeCore(frame, context);
    }

    private PubSubNetworkMessage? DecodeCore(
        ReadOnlyMemory<byte> frame,
        PubSubNetworkMessageContext context)
    {
        try
        {
            using MemoryStream stream = new(frame.ToArray(), writable: false);
            using ArrowStreamReader reader = new(stream, leaveOpen: true);
            using RecordBatch? batch = reader.ReadNextRecordBatch();
            if (batch is null)
            {
                context.Diagnostics.Increment(PubSubDiagnosticsCounterKind.ReceivedInvalidNetworkMessages);
                return null;
            }

            IReadOnlyDictionary<string, string> metadata = batch.Schema.Metadata;
            if (!string.Equals(ReadMeta(metadata, "magic"), Magic, StringComparison.Ordinal)
                || !string.Equals(ReadMeta(metadata, "version"), Version, StringComparison.Ordinal))
            {
                context.Diagnostics.Increment(PubSubDiagnosticsCounterKind.ReceivedInvalidNetworkMessages);
                return null;
            }

            PublisherId publisherId = string.IsNullOrEmpty(ReadMeta(metadata, "publisherId"))
                ? PublisherId.Null
                : PublisherId.FromString(ReadMeta(metadata, "publisherId"));
            ushort writerGroupId = ParseUInt16(ReadMeta(metadata, "writerGroupId"));
            Uuid dataSetClassId = ParseUuid(ReadMeta(metadata, "dataSetClassId"));
            string schemaId = ReadMeta(metadata, "schemaId");
            if (SchemaCache.TryParseKey(schemaId, out ByteString schemaIdBytes)
                && !SchemaCache.TryGetOrResolve(schemaIdBytes, SchemaResolver, out _))
            {
                throw new FormatException($"Arrow schema '{schemaId}' is not available.");
            }
            uint majorVersion = ParseUInt32(ReadMeta(metadata, "majorVersion"));
            uint minorVersion = ParseUInt32(ReadMeta(metadata, "minorVersion"));

            ArrowNetworkMessage envelope = new()
            {
                PublisherId = publisherId,
                WriterGroupId = writerGroupId == 0 ? null : writerGroupId,
                DataSetClassId = dataSetClassId,
                SchemaId = schemaId
            };

            int rowCount = checked((int)batch.Length);
            var messages = new List<PubSubDataSetMessage>(rowCount);
            for (int row = 0; row < rowCount; row++)
            {
                ArrowDataSetMessage message = ReadDataSetMessage(
                    batch,
                    envelope,
                    context,
                    row,
                    majorVersion,
                    minorVersion);
                messages.Add(message);
            }

            context.Diagnostics.Increment(PubSubDiagnosticsCounterKind.ReceivedNetworkMessages);
            context.Diagnostics.Increment(PubSubDiagnosticsCounterKind.ReceivedDataSetMessages, messages.Count);
            return envelope with { DataSetMessages = messages };
        }
        catch (Exception ex) when (ex is FormatException
            or InvalidCastException
            or EndOfStreamException
            or OverflowException
            or NotSupportedException)
        {
            context.Diagnostics.Increment(PubSubDiagnosticsCounterKind.ReceivedInvalidNetworkMessages);
            context.Diagnostics.RecordError((StatusCode)StatusCodes.BadDecodingError, ex.Message);
            return null;
        }
    }

    private static ArrowDataSetMessage ReadDataSetMessage(
        RecordBatch batch,
        ArrowNetworkMessage envelope,
        PubSubNetworkMessageContext context,
        int row,
        uint majorVersion,
        uint minorVersion)
    {
        ushort writerId = ((UInt16Array)batch.Column(0)).GetValue(row) ?? 0;
        uint sequenceNumber = ((UInt32Array)batch.Column(1)).GetValue(row) ?? 0;
        StatusCode status = new(((UInt32Array)batch.Column(2)).GetValue(row) ?? 0);
        DateTimeUtc timestamp = new(((Int64Array)batch.Column(3)).GetValue(row) ?? 0);
        PubSubDataSetMessageType messageType =
            (PubSubDataSetMessageType)(((Int32Array)batch.Column(4)).GetValue(row) ?? 0);

        var message = new ArrowDataSetMessage
        {
            DataSetWriterId = writerId,
            SequenceNumber = sequenceNumber,
            Status = status,
            Timestamp = timestamp,
            MessageType = messageType,
            MetaDataVersion = new ConfigurationVersionDataType
            {
                MajorVersion = majorVersion,
                MinorVersion = minorVersion
            },
            FieldContentMask = DataSetFieldContentMask.RawData
        };

        DataSetMetaDataType? metaData = ExperimentalMessageEncoding.ResolveMetaData(
            envelope,
            message,
            context,
            envelope.DataSetClassId);
        var fields = new List<DataSetField>(Math.Max(0, batch.ColumnCount - HeaderColumnCount));
        for (int col = HeaderColumnCount; col < batch.ColumnCount; col++)
        {
            Field arrowField = batch.Schema.GetFieldByIndex(col);
            int fieldIndex = col - HeaderColumnCount;
            TypeInfo typeInfo = ExperimentalMessageEncoding.ResolveFieldType(metaData, arrowField.Name, fieldIndex)
                ?? InferTypeInfo(arrowField.Name, arrowField.DataType);
            fields.Add(new DataSetField
            {
                Name = arrowField.Name,
                FieldIndex = fieldIndex,
                Encoding = PubSubFieldEncoding.RawData,
                Value = ReadVariant(batch.Column(col), row, arrowField.Name, typeInfo)
            });
        }

        return message with { Fields = fields };
    }

    private static Variant ReadVariant(IArrowArray array, int row, string fieldName, TypeInfo typeInfo)
    {
        if (typeInfo.ValueRank >= 0)
        {
            return ReadListVariant((ListArray)array, row, fieldName, typeInfo.BuiltInType);
        }
        return typeInfo.BuiltInType switch
        {
            BuiltInType.Boolean => ((BooleanArray)array).IsNull(row)
                ? Variant.Null
                : new Variant(((BooleanArray)array).GetValue(row) ?? false),
            BuiltInType.SByte => ((Int8Array)array).IsNull(row)
                ? Variant.Null
                : new Variant(((Int8Array)array).GetValue(row) ?? 0),
            BuiltInType.Byte => ((UInt8Array)array).IsNull(row)
                ? Variant.Null
                : new Variant(((UInt8Array)array).GetValue(row) ?? 0),
            BuiltInType.Int16 => ((Int16Array)array).IsNull(row)
                ? Variant.Null
                : new Variant(((Int16Array)array).GetValue(row) ?? 0),
            BuiltInType.UInt16 => ((UInt16Array)array).IsNull(row)
                ? Variant.Null
                : new Variant(((UInt16Array)array).GetValue(row) ?? 0),
            BuiltInType.Int32 => ((Int32Array)array).IsNull(row)
                ? Variant.Null
                : new Variant(((Int32Array)array).GetValue(row) ?? 0),
            BuiltInType.UInt32 => ((UInt32Array)array).IsNull(row)
                ? Variant.Null
                : new Variant(((UInt32Array)array).GetValue(row) ?? 0),
            BuiltInType.Int64 => ((Int64Array)array).IsNull(row)
                ? Variant.Null
                : new Variant(((Int64Array)array).GetValue(row) ?? 0),
            BuiltInType.UInt64 => ((UInt64Array)array).IsNull(row)
                ? Variant.Null
                : new Variant(((UInt64Array)array).GetValue(row) ?? 0),
            BuiltInType.Float => ((FloatArray)array).IsNull(row)
                ? Variant.Null
                : new Variant(((FloatArray)array).GetValue(row) ?? 0),
            BuiltInType.Double => ((DoubleArray)array).IsNull(row)
                ? Variant.Null
                : new Variant(((DoubleArray)array).GetValue(row) ?? 0),
            BuiltInType.String => ((StringArray)array).IsNull(row)
                ? Variant.Null
                : new Variant(((StringArray)array).GetString(row)),
            BuiltInType.DateTime => ((Int64Array)array).IsNull(row)
                ? Variant.Null
                : new Variant(new DateTimeUtc(((Int64Array)array).GetValue(row) ?? 0)),
            BuiltInType.Guid => ((FixedSizeBinaryArray)array).IsNull(row)
                ? Variant.Null
                : new Variant(new Uuid(((FixedSizeBinaryArray)array).GetBytes(row).ToArray())),
            BuiltInType.ByteString => ((BinaryArray)array).IsNull(row)
                ? Variant.Null
                : new Variant(ByteString.From(((BinaryArray)array).GetBytes(row).ToArray())),
            BuiltInType.StatusCode => ((UInt32Array)array).IsNull(row)
                ? Variant.Null
                : new Variant(new StatusCode(((UInt32Array)array).GetValue(row) ?? 0)),
            _ => throw Unsupported(fieldName, typeInfo)
        };
    }

    private static Variant ReadListVariant(ListArray list, int row, string fieldName, BuiltInType type)
    {
        if (list.IsNull(row))
        {
            return Variant.Null;
        }
        int start = list.ValueOffsets[row];
        int length = list.ValueOffsets[row + 1] - start;
        IArrowArray values = list.Values;
        return type switch
        {
            BuiltInType.Boolean => new Variant(new ArrayOf<bool>(
                Enumerable.Range(start, length).Select(i => ((BooleanArray)values).GetValue(i) ?? false).ToArray())),
            BuiltInType.SByte => new Variant(new ArrayOf<sbyte>(
                Enumerable.Range(start, length).Select(i => ((Int8Array)values).GetValue(i) ?? 0).ToArray())),
            BuiltInType.Byte => new Variant(new ArrayOf<byte>(
                Enumerable.Range(start, length).Select(i => ((UInt8Array)values).GetValue(i) ?? 0).ToArray())),
            BuiltInType.Int16 => new Variant(new ArrayOf<short>(
                Enumerable.Range(start, length).Select(i => ((Int16Array)values).GetValue(i) ?? 0).ToArray())),
            BuiltInType.UInt16 => new Variant(new ArrayOf<ushort>(
                Enumerable.Range(start, length).Select(i => ((UInt16Array)values).GetValue(i) ?? 0).ToArray())),
            BuiltInType.Int32 => new Variant(new ArrayOf<int>(
                Enumerable.Range(start, length).Select(i => ((Int32Array)values).GetValue(i) ?? 0).ToArray())),
            BuiltInType.UInt32 => new Variant(new ArrayOf<uint>(
                Enumerable.Range(start, length).Select(i => ((UInt32Array)values).GetValue(i) ?? 0).ToArray())),
            BuiltInType.Int64 => new Variant(new ArrayOf<long>(
                Enumerable.Range(start, length).Select(i => ((Int64Array)values).GetValue(i) ?? 0).ToArray())),
            BuiltInType.UInt64 => new Variant(new ArrayOf<ulong>(
                Enumerable.Range(start, length).Select(i => ((UInt64Array)values).GetValue(i) ?? 0).ToArray())),
            BuiltInType.Float => new Variant(new ArrayOf<float>(
                Enumerable.Range(start, length).Select(i => ((FloatArray)values).GetValue(i) ?? 0).ToArray())),
            BuiltInType.Double => new Variant(new ArrayOf<double>(
                Enumerable.Range(start, length).Select(i => ((DoubleArray)values).GetValue(i) ?? 0).ToArray())),
            BuiltInType.String => new Variant(new ArrayOf<string>(
                Enumerable.Range(start, length)
                    .Select(i => ((StringArray)values).IsNull(i) ? null : ((StringArray)values).GetString(i))
                    .ToArray()!)),
            BuiltInType.DateTime => new Variant(new ArrayOf<DateTimeUtc>(
                Enumerable.Range(start, length)
                    .Select(i => ((Int64Array)values).IsNull(i)
                        ? default
                        : new DateTimeUtc(((Int64Array)values).GetValue(i) ?? 0))
                    .ToArray())),
            BuiltInType.Guid => new Variant(new ArrayOf<Uuid>(
                Enumerable.Range(start, length)
                    .Select(i => new Uuid(((FixedSizeBinaryArray)values).GetBytes(i).ToArray()))
                    .ToArray())),
            BuiltInType.ByteString => new Variant(new ArrayOf<ByteString>(
                Enumerable.Range(start, length)
                    .Select(i => ((BinaryArray)values).IsNull(i)
                        ? default
                        : ByteString.From(((BinaryArray)values).GetBytes(i).ToArray()))
                    .ToArray())),
            BuiltInType.StatusCode => new Variant(new ArrayOf<StatusCode>(
                Enumerable.Range(start, length)
                    .Select(i => new StatusCode(((UInt32Array)values).GetValue(i) ?? 0))
                    .ToArray())),
            _ => throw new NotSupportedException(
                $"Arrow list field '{fieldName}' with element type {type} is not supported.")
        };
    }

    private static TypeInfo InferTypeInfo(string fieldName, IArrowType type)
    {
        if (type is ListType listType)
        {
            TypeInfo scalar = InferTypeInfo(fieldName, listType.ValueField.DataType);
            return TypeInfo.Create(scalar.BuiltInType, ValueRanks.OneDimension);
        }
        BuiltInType builtIn = type.TypeId switch
        {
            ArrowTypeId.Boolean => BuiltInType.Boolean,
            ArrowTypeId.Int8 => BuiltInType.SByte,
            ArrowTypeId.UInt8 => BuiltInType.Byte,
            ArrowTypeId.Int16 => BuiltInType.Int16,
            ArrowTypeId.UInt16 => BuiltInType.UInt16,
            ArrowTypeId.Int32 => BuiltInType.Int32,
            ArrowTypeId.UInt32 => BuiltInType.UInt32,
            ArrowTypeId.Int64 => BuiltInType.Int64,
            ArrowTypeId.UInt64 => BuiltInType.UInt64,
            ArrowTypeId.Float => BuiltInType.Float,
            ArrowTypeId.Double => BuiltInType.Double,
            ArrowTypeId.String => BuiltInType.String,
            ArrowTypeId.FixedSizedBinary => BuiltInType.Guid,
            ArrowTypeId.Binary => BuiltInType.ByteString,
            _ => throw new NotSupportedException(
                $"Arrow field '{fieldName}' with Arrow type {type.Name} is not supported.")
        };
        return TypeInfo.Create(builtIn, ValueRanks.Scalar);
    }

    private static string ReadMeta(IReadOnlyDictionary<string, string> metadata, string key)
    {
        return metadata.TryGetValue(key, out string? value) ? value : string.Empty;
    }

    private static ushort ParseUInt16(string value)
    {
        return ushort.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out ushort parsed)
            ? parsed
            : (ushort)0;
    }

    private static uint ParseUInt32(string value)
    {
        return uint.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint parsed) ? parsed : 0;
    }

    private static Uuid ParseUuid(string value)
    {
        return Guid.TryParse(value, out Guid guid) ? new Uuid(guid) : Uuid.Empty;
    }

    private static NotSupportedException Unsupported(string fieldName, TypeInfo typeInfo)
    {
        return new NotSupportedException(
            $"Arrow RawData field '{fieldName}' with type {typeInfo} is not supported by this adapter.");
    }
}
