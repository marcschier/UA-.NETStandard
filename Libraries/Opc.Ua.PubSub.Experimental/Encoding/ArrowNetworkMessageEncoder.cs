#pragma warning disable RCS0056, RCS1007, RCS1126, RCS1229, CA1508, CA1859, CA2000
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
using Apache.Arrow.Memory;
using Apache.Arrow.Types;
using Opc.Ua.PubSub.Encoding;

namespace Opc.Ua.PubSub.Experimental;

/// <summary>
/// Encodes an <see cref="ArrowNetworkMessage"/> as a genuine Apache Arrow
/// IPC stream: one schema for one DataSet, one RecordBatch, rows as
/// DataSetMessage samples, leading per-sample header columns, and typed
/// RawData field columns. Supported field types are Boolean, integer widths,
/// Float, Double, String, DateTime, Guid, ByteString, StatusCode and
/// one-dimensional arrays of those types; other BuiltInTypes throw.
/// </summary>
public sealed class ArrowNetworkMessageEncoder : INetworkMessageEncoder
{
    private const string Magic = "OPC-UA-PubSub-Arrow";
    private const string Version = "1";
    private static readonly MemoryAllocator s_allocator = MemoryAllocator.Default.Value;

    public string TransportProfileUri => ArrowNetworkMessage.PubSubMqttArrowTransport;

    public int EstimatedHeaderOverhead => 256;

    public async ValueTask<ReadOnlyMemory<byte>> EncodeAsync(
        PubSubNetworkMessage networkMessage,
        PubSubNetworkMessageContext context,
        CancellationToken cancellationToken = default)
    {
        if (networkMessage is null)
        {
            throw new ArgumentNullException(nameof(networkMessage));
        }
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (networkMessage is not ArrowNetworkMessage message)
        {
            throw new ArgumentException("Network message type is not supported by the Arrow encoder.", nameof(networkMessage));
        }

        DataSetMetaDataType? metaData = ResolveBatchMetaData(message, context);
        FieldPlan[] fields = BuildFieldPlan(message, metaData);
        int rowCount = AllKeepAlive(message)
            ? 0
            : message.DataSetMessages.Count;
        ValidateHomogeneous(message, fields, metaData, rowCount);

        var schemaBuilder = new Apache.Arrow.Schema.Builder()
            .Metadata("magic", Magic)
            .Metadata("version", Version)
            .Metadata("publisherId", message.PublisherId.ToString())
            .Metadata("writerGroupId", (message.WriterGroupId ?? 0).ToString(CultureInfo.InvariantCulture))
            .Metadata("dataSetClassId", message.DataSetClassId.ToString())
            .Metadata("schemaId", message.SchemaId ?? string.Empty)
            .Metadata("majorVersion", FirstVersion(message).MajorVersion.ToString(CultureInfo.InvariantCulture))
            .Metadata("minorVersion", FirstVersion(message).MinorVersion.ToString(CultureInfo.InvariantCulture));

        var arrays = new List<IArrowArray>();
        AddHeaderColumns(schemaBuilder, arrays, message, rowCount);
        foreach (FieldPlan field in fields)
        {
            schemaBuilder.Field(new Field(field.Name, field.ArrowType, nullable: true, metadata: null));
            arrays.Add(BuildFieldArray(message, field, rowCount));
        }

        Apache.Arrow.Schema schema = schemaBuilder.Build();
        using RecordBatch batch = new(schema, arrays, rowCount);
        using MemoryStream stream = new();
        using (ArrowStreamWriter writer = new(stream, schema, leaveOpen: true))
        {
            writer.WriteStart();
            writer.WriteRecordBatch(batch);
            writer.WriteEnd();
        }
        await Task.CompletedTask.ConfigureAwait(false);
        return stream.ToArray();
    }

    private static DataSetMetaDataType? ResolveBatchMetaData(
        ArrowNetworkMessage message,
        PubSubNetworkMessageContext context)
    {
        ArrowDataSetMessage? first = FirstArrowMessage(message);
        if (first is null)
        {
            return message.MetaData;
        }

        return ExperimentalMessageEncoding.ResolveMetaData(message, first, context, message.DataSetClassId);
    }

    private static ConfigurationVersionDataType FirstVersion(ArrowNetworkMessage message)
    {
        return FirstArrowMessage(message)?.MetaDataVersion
            ?? message.MetaData?.ConfigurationVersion
            ?? new ConfigurationVersionDataType();
    }

    private static ArrowDataSetMessage? FirstArrowMessage(
        ArrowNetworkMessage message,
        bool skipKeepAlive = false)
    {
        for (int i = 0; i < message.DataSetMessages.Count; i++)
        {
            if (message.DataSetMessages[i] is ArrowDataSetMessage candidate
                && (!skipKeepAlive || candidate.MessageType != PubSubDataSetMessageType.KeepAlive))
            {
                return candidate;
            }
        }
        return null;
    }

    private static bool AllKeepAlive(ArrowNetworkMessage message)
    {
        if (message.DataSetMessages.Count == 0)
        {
            return false;
        }
        for (int i = 0; i < message.DataSetMessages.Count; i++)
        {
            if (message.DataSetMessages[i].MessageType != PubSubDataSetMessageType.KeepAlive)
            {
                return false;
            }
        }
        return true;
    }

    private static FieldPlan[] BuildFieldPlan(
        ArrowNetworkMessage message,
        DataSetMetaDataType? metaData)
    {
        if (metaData is not null && metaData.Fields.Count > 0)
        {
            var plans = new FieldPlan[metaData.Fields.Count];
            for (int i = 0; i < plans.Length; i++)
            {
                FieldMetaData field = metaData.Fields[i];
                string name = string.IsNullOrEmpty(field.Name) ? FormattableString.Invariant($"Field{i}") : field.Name;
                TypeInfo typeInfo = TypeInfo.Create((BuiltInType)field.BuiltInType, field.ValueRank);
                plans[i] = new FieldPlan(name, i, typeInfo, ToArrowType(name, typeInfo));
            }
            return plans;
        }

        ArrowDataSetMessage? first = FirstArrowMessage(message, skipKeepAlive: true);
        if (first is null)
        {
            return [];
        }
        var inferred = new FieldPlan[first.Fields.Count];
        for (int i = 0; i < first.Fields.Count; i++)
        {
            DataSetField field = first.Fields[i];
            if (field.Value.IsNull)
            {
                throw new ArgumentException($"Arrow field '{field.Name}' requires DataSetMetaData when the first value is null.");
            }
            inferred[i] = new FieldPlan(
                ExperimentalMessageEncoding.ResolveFieldName(field, null, i),
                i,
                field.Value.TypeInfo,
                ToArrowType(field.Name, field.Value.TypeInfo));
        }
        return inferred;
    }

    private static void ValidateHomogeneous(
        ArrowNetworkMessage message,
        FieldPlan[] fields,
        DataSetMetaDataType? metaData,
        int rowCount)
    {
        if (rowCount == 0)
        {
            return;
        }
        foreach (PubSubDataSetMessage candidate in message.DataSetMessages)
        {
            if (candidate is not ArrowDataSetMessage dataSetMessage)
            {
                throw new ArgumentException("DataSetMessage entries must be ArrowDataSetMessage instances.", nameof(message));
            }
            if (dataSetMessage.MessageType is not PubSubDataSetMessageType.KeyFrame)
            {
                throw new NotSupportedException("The first Arrow PubSub adapter supports key frames and keep-alive schema batches only.");
            }
        }
    }

    private static void AddHeaderColumns(
        Apache.Arrow.Schema.Builder schemaBuilder,
        List<IArrowArray> arrays,
        ArrowNetworkMessage message,
        int rowCount)
    {
        schemaBuilder.Field(new Field("dataSetWriterId", UInt16Type.Default, nullable: false, metadata: null));
        schemaBuilder.Field(new Field("sequenceNumber", UInt32Type.Default, nullable: false, metadata: null));
        schemaBuilder.Field(new Field("status", UInt32Type.Default, nullable: false, metadata: null));
        schemaBuilder.Field(new Field("timestamp", Int64Type.Default, nullable: false, metadata: null));
        schemaBuilder.Field(new Field("messageType", Int32Type.Default, nullable: false, metadata: null));

        var writerId = new UInt16Array.Builder();
        var sequence = new UInt32Array.Builder();
        var status = new UInt32Array.Builder();
        var timestamp = new Int64Array.Builder();
        var messageType = new Int32Array.Builder();
        if (rowCount > 0)
        {
            foreach (PubSubDataSetMessage entry in message.DataSetMessages)
            {
                var row = (ArrowDataSetMessage)entry;
                writerId.Append(row.DataSetWriterId);
                sequence.Append(row.SequenceNumber);
                status.Append(row.Status.Code);
                timestamp.Append(row.Timestamp.Value);
                messageType.Append((int)row.MessageType);
            }
        }
        arrays.Add(writerId.Build(s_allocator));
        arrays.Add(sequence.Build(s_allocator));
        arrays.Add(status.Build(s_allocator));
        arrays.Add(timestamp.Build(s_allocator));
        arrays.Add(messageType.Build(s_allocator));
    }

    private static IArrowArray BuildFieldArray(
        ArrowNetworkMessage message,
        FieldPlan plan,
        int rowCount)
    {
        if (plan.TypeInfo.ValueRank >= 0)
        {
            return BuildListArray(message, plan, rowCount);
        }

        return plan.TypeInfo.BuiltInType switch
        {
            BuiltInType.Boolean => BuildBoolean(message, plan, rowCount),
            BuiltInType.SByte => BuildInt8(message, plan, rowCount),
            BuiltInType.Byte => BuildUInt8(message, plan, rowCount),
            BuiltInType.Int16 => BuildInt16(message, plan, rowCount),
            BuiltInType.UInt16 => BuildUInt16(message, plan, rowCount),
            BuiltInType.Int32 => BuildInt32(message, plan, rowCount),
            BuiltInType.UInt32 => BuildUInt32(message, plan, rowCount),
            BuiltInType.Int64 => BuildInt64(message, plan, rowCount),
            BuiltInType.UInt64 => BuildUInt64(message, plan, rowCount),
            BuiltInType.Float => BuildFloat(message, plan, rowCount),
            BuiltInType.Double => BuildDouble(message, plan, rowCount),
            BuiltInType.String => BuildString(message, plan, rowCount),
            BuiltInType.DateTime => BuildDateTime(message, plan, rowCount),
            BuiltInType.Guid => BuildGuid(message, plan, rowCount),
            BuiltInType.ByteString => BuildBytes(message, plan, rowCount),
            BuiltInType.StatusCode => BuildStatus(message, plan, rowCount),
            _ => throw Unsupported(plan.Name, plan.TypeInfo)
        };
    }

    private static DataSetField? FindField(
        ArrowDataSetMessage message,
        string name,
        DataSetMetaDataType? metaData,
        int index)
    {
        for (int i = 0; i < message.Fields.Count; i++)
        {
            string candidate = ExperimentalMessageEncoding.ResolveFieldName(message.Fields[i], metaData, i);
            if (string.Equals(candidate, name, StringComparison.Ordinal))
            {
                return message.Fields[i];
            }
        }
        return index < message.Fields.Count ? message.Fields[index] : null;
    }

    private static Variant FieldValue(ArrowNetworkMessage message, FieldPlan plan, int row)
    {
        ArrowDataSetMessage dataSetMessage = (ArrowDataSetMessage)message.DataSetMessages[row];
        DataSetField? field = FindField(dataSetMessage, plan.Name, message.MetaData, plan.Index);
        return field?.Value ?? Variant.Null;
    }

    private static IArrowType ToArrowType(string fieldName, TypeInfo typeInfo)
    {
        IArrowType scalar = typeInfo.BuiltInType switch
        {
            BuiltInType.Boolean => BooleanType.Default,
            BuiltInType.SByte => Int8Type.Default,
            BuiltInType.Byte => UInt8Type.Default,
            BuiltInType.Int16 => Int16Type.Default,
            BuiltInType.UInt16 => UInt16Type.Default,
            BuiltInType.Int32 => Int32Type.Default,
            BuiltInType.UInt32 => UInt32Type.Default,
            BuiltInType.Int64 => Int64Type.Default,
            BuiltInType.UInt64 => UInt64Type.Default,
            BuiltInType.Float => FloatType.Default,
            BuiltInType.Double => DoubleType.Default,
            BuiltInType.String => StringType.Default,
            BuiltInType.DateTime => Int64Type.Default,
            BuiltInType.Guid => new FixedSizeBinaryType(16),
            BuiltInType.ByteString => BinaryType.Default,
            BuiltInType.StatusCode => UInt32Type.Default,
            _ => throw Unsupported(fieldName, typeInfo)
        };
        return typeInfo.ValueRank >= 0 ? new ListType(new Field("item", scalar, nullable: true, metadata: null)) : scalar;
    }

    private static NotSupportedException Unsupported(string fieldName, TypeInfo typeInfo)
    {
        return new NotSupportedException($"Arrow RawData field '{fieldName}' with type {typeInfo} is not supported by this adapter.");
    }

    private static IArrowArray BuildBoolean(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new BooleanArray.Builder(); ForRows(m, p, n, v => { if (v.IsNull) b.AppendNull(); else b.Append(v.GetBoolean()); }); return b.Build(s_allocator); }
    private static IArrowArray BuildInt8(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new Int8Array.Builder(); ForRows(m, p, n, v => { if (v.IsNull) b.AppendNull(); else b.Append(v.GetSByte()); }); return b.Build(s_allocator); }
    private static IArrowArray BuildUInt8(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new UInt8Array.Builder(); ForRows(m, p, n, v => { if (v.IsNull) b.AppendNull(); else b.Append(v.GetByte()); }); return b.Build(s_allocator); }
    private static IArrowArray BuildInt16(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new Int16Array.Builder(); ForRows(m, p, n, v => { if (v.IsNull) b.AppendNull(); else b.Append(v.GetInt16()); }); return b.Build(s_allocator); }
    private static IArrowArray BuildUInt16(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new UInt16Array.Builder(); ForRows(m, p, n, v => { if (v.IsNull) b.AppendNull(); else b.Append(v.GetUInt16()); }); return b.Build(s_allocator); }
    private static IArrowArray BuildInt32(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new Int32Array.Builder(); ForRows(m, p, n, v => { if (v.IsNull) b.AppendNull(); else b.Append(v.GetInt32()); }); return b.Build(s_allocator); }
    private static IArrowArray BuildUInt32(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new UInt32Array.Builder(); ForRows(m, p, n, v => { if (v.IsNull) b.AppendNull(); else b.Append(v.GetUInt32()); }); return b.Build(s_allocator); }
    private static IArrowArray BuildInt64(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new Int64Array.Builder(); ForRows(m, p, n, v => { if (v.IsNull) b.AppendNull(); else b.Append(v.GetInt64()); }); return b.Build(s_allocator); }
    private static IArrowArray BuildUInt64(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new UInt64Array.Builder(); ForRows(m, p, n, v => { if (v.IsNull) b.AppendNull(); else b.Append(v.GetUInt64()); }); return b.Build(s_allocator); }
    private static IArrowArray BuildFloat(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new FloatArray.Builder(); ForRows(m, p, n, v => { if (v.IsNull) b.AppendNull(); else b.Append(v.GetFloat()); }); return b.Build(s_allocator); }
    private static IArrowArray BuildDouble(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new DoubleArray.Builder(); ForRows(m, p, n, v => { if (v.IsNull) b.AppendNull(); else b.Append(v.GetDouble()); }); return b.Build(s_allocator); }
    private static IArrowArray BuildString(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new StringArray.Builder(); ForRows(m, p, n, v => { if (v.IsNull) b.AppendNull(); else b.Append(v.GetString()); }); return b.Build(s_allocator); }
    private static IArrowArray BuildDateTime(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new Int64Array.Builder(); ForRows(m, p, n, v => { if (v.IsNull) b.AppendNull(); else b.Append(v.GetDateTime().Value); }); return b.Build(s_allocator); }
    private static IArrowArray BuildBytes(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new BinaryArray.Builder(); ForRows(m, p, n, v => { if (v.IsNull || v.GetByteString().IsNull) b.AppendNull(); else b.Append(v.GetByteString().Span); }); return b.Build(s_allocator); }
    private static IArrowArray BuildStatus(ArrowNetworkMessage m, FieldPlan p, int n) { var b = new UInt32Array.Builder(); ForRows(m, p, n, v => { if (v.IsNull) b.AppendNull(); else b.Append(v.GetStatusCode().Code); }); return b.Build(s_allocator); }

    private static IArrowArray BuildGuid(ArrowNetworkMessage message, FieldPlan plan, int rowCount)
    {
        var bytes = new List<byte>(rowCount * 16);
        var validity = new ArrowBuffer.BitmapBuilder(rowCount);
        ForRows(message, plan, rowCount, value =>
        {
            bool valid = !value.IsNull;
            validity.Append(valid);
            bytes.AddRange(valid ? value.GetGuid().ToByteArray() : new byte[16]);
        });
        return new FixedSizeBinaryArray(new ArrayData(new FixedSizeBinaryType(16), rowCount, rowCount - validity.SetBitCount, 0, [validity.Build(s_allocator), BuildBuffer(bytes.ToArray())], []));
    }

    private static IArrowArray BuildListArray(ArrowNetworkMessage message, FieldPlan plan, int rowCount)
    {
        return plan.TypeInfo.BuiltInType switch
        {
            BuiltInType.Boolean => BuildList(message, plan, rowCount, BooleanType.Default, AppendBoolArray),
            BuiltInType.SByte => BuildList(message, plan, rowCount, Int8Type.Default, AppendSByteArray),
            BuiltInType.Byte => BuildList(message, plan, rowCount, UInt8Type.Default, AppendByteArray),
            BuiltInType.Int16 => BuildList(message, plan, rowCount, Int16Type.Default, AppendInt16Array),
            BuiltInType.UInt16 => BuildList(message, plan, rowCount, UInt16Type.Default, AppendUInt16Array),
            BuiltInType.Int32 => BuildList(message, plan, rowCount, Int32Type.Default, AppendInt32Array),
            BuiltInType.UInt32 => BuildList(message, plan, rowCount, UInt32Type.Default, AppendUInt32Array),
            BuiltInType.Int64 => BuildList(message, plan, rowCount, Int64Type.Default, AppendInt64Array),
            BuiltInType.UInt64 => BuildList(message, plan, rowCount, UInt64Type.Default, AppendUInt64Array),
            BuiltInType.Float => BuildList(message, plan, rowCount, FloatType.Default, AppendFloatArray),
            BuiltInType.Double => BuildList(message, plan, rowCount, DoubleType.Default, AppendDoubleArray),
            BuiltInType.String => BuildList(message, plan, rowCount, StringType.Default, AppendStringArray),
            BuiltInType.DateTime => BuildList(message, plan, rowCount, Int64Type.Default, AppendDateTimeArray),
            BuiltInType.Guid => BuildList(message, plan, rowCount, new FixedSizeBinaryType(16), AppendGuidArray),
            BuiltInType.ByteString => BuildList(message, plan, rowCount, BinaryType.Default, AppendByteStringArray),
            BuiltInType.StatusCode => BuildList(message, plan, rowCount, UInt32Type.Default, AppendStatusArray),
            _ => throw Unsupported(plan.Name, plan.TypeInfo)
        };
    }

    private static IArrowArray BuildList(ArrowNetworkMessage message, FieldPlan plan, int rowCount, IArrowType itemType, Func<List<Variant>, IArrowArray> buildChild)
    {
        var offsets = new int[rowCount + 1];
        var validity = new ArrowBuffer.BitmapBuilder(rowCount);
        var items = new List<Variant>();
        for (int row = 0; row < rowCount; row++)
        {
            Variant value = FieldValue(message, plan, row);
            if (value.IsNull)
            {
                validity.Append(false);
            }
            else
            {
                validity.Append(true);
                AppendArrayElements(value, plan.TypeInfo.BuiltInType, items);
            }
            offsets[row + 1] = items.Count;
        }
        IArrowArray child = buildChild(items);
        var listType = new ListType(new Field("item", itemType, nullable: true, metadata: null));
        return new ListArray(listType, rowCount, BuildBuffer(offsets), child, validity.Build(s_allocator), rowCount - validity.SetBitCount, 0);
    }

    private static void ForRows(ArrowNetworkMessage message, FieldPlan plan, int rowCount, Action<Variant> action)
    {
        for (int row = 0; row < rowCount; row++)
        {
            action(FieldValue(message, plan, row));
        }
    }

    private static ArrowBuffer BuildBuffer<T>(params T[] values) where T : struct
    {
        var builder = new ArrowBuffer.Builder<T>(values.Length);
        builder.Append(values.AsSpan());
        return builder.Build(s_allocator);
    }

    private static void AppendArrayElements(Variant value, BuiltInType type, List<Variant> items)
    {
        switch (type)
        {
            case BuiltInType.Boolean: foreach (bool v in value.GetBooleanArray().Span) items.Add(new Variant(v)); break;
            case BuiltInType.SByte: foreach (sbyte v in value.GetSByteArray().Span) items.Add(new Variant(v)); break;
            case BuiltInType.Byte: foreach (byte v in value.GetByteArray().Span) items.Add(new Variant(v)); break;
            case BuiltInType.Int16: foreach (short v in value.GetInt16Array().Span) items.Add(new Variant(v)); break;
            case BuiltInType.UInt16: foreach (ushort v in value.GetUInt16Array().Span) items.Add(new Variant(v)); break;
            case BuiltInType.Int32: foreach (int v in value.GetInt32Array().Span) items.Add(new Variant(v)); break;
            case BuiltInType.UInt32: foreach (uint v in value.GetUInt32Array().Span) items.Add(new Variant(v)); break;
            case BuiltInType.Int64: foreach (long v in value.GetInt64Array().Span) items.Add(new Variant(v)); break;
            case BuiltInType.UInt64: foreach (ulong v in value.GetUInt64Array().Span) items.Add(new Variant(v)); break;
            case BuiltInType.Float: foreach (float v in value.GetFloatArray().Span) items.Add(new Variant(v)); break;
            case BuiltInType.Double: foreach (double v in value.GetDoubleArray().Span) items.Add(new Variant(v)); break;
            case BuiltInType.String: foreach (string? v in value.GetStringArray().Span) items.Add(v is null ? Variant.Null : new Variant(v)); break;
            case BuiltInType.DateTime: foreach (DateTimeUtc v in value.GetDateTimeArray().Span) items.Add(v.IsNull ? Variant.Null : new Variant(v)); break;
            case BuiltInType.Guid: foreach (Uuid v in value.GetGuidArray().Span) items.Add(new Variant(v)); break;
            case BuiltInType.ByteString: foreach (ByteString v in value.GetByteStringArray().Span) items.Add(v.IsNull ? Variant.Null : new Variant(v)); break;
            case BuiltInType.StatusCode: foreach (StatusCode v in value.GetStatusCodeArray().Span) items.Add(new Variant(v)); break;
            default: throw new NotSupportedException($"Arrow list field element type {type} is not supported.");
        }
    }

    private static IArrowArray AppendBoolArray(List<Variant> values) { var b = new BooleanArray.Builder(); foreach (Variant v in values) { if (v.IsNull) b.AppendNull(); else b.Append(v.GetBoolean()); } return b.Build(s_allocator); }
    private static IArrowArray AppendSByteArray(List<Variant> values) { var b = new Int8Array.Builder(); foreach (Variant v in values) { if (v.IsNull) b.AppendNull(); else b.Append(v.GetSByte()); } return b.Build(s_allocator); }
    private static IArrowArray AppendByteArray(List<Variant> values) { var b = new UInt8Array.Builder(); foreach (Variant v in values) { if (v.IsNull) b.AppendNull(); else b.Append(v.GetByte()); } return b.Build(s_allocator); }
    private static IArrowArray AppendInt16Array(List<Variant> values) { var b = new Int16Array.Builder(); foreach (Variant v in values) { if (v.IsNull) b.AppendNull(); else b.Append(v.GetInt16()); } return b.Build(s_allocator); }
    private static IArrowArray AppendUInt16Array(List<Variant> values) { var b = new UInt16Array.Builder(); foreach (Variant v in values) { if (v.IsNull) b.AppendNull(); else b.Append(v.GetUInt16()); } return b.Build(s_allocator); }
    private static IArrowArray AppendInt32Array(List<Variant> values) { var b = new Int32Array.Builder(); foreach (Variant v in values) { if (v.IsNull) b.AppendNull(); else b.Append(v.GetInt32()); } return b.Build(s_allocator); }
    private static IArrowArray AppendUInt32Array(List<Variant> values) { var b = new UInt32Array.Builder(); foreach (Variant v in values) { if (v.IsNull) b.AppendNull(); else b.Append(v.GetUInt32()); } return b.Build(s_allocator); }
    private static IArrowArray AppendInt64Array(List<Variant> values) { var b = new Int64Array.Builder(); foreach (Variant v in values) { if (v.IsNull) b.AppendNull(); else b.Append(v.GetInt64()); } return b.Build(s_allocator); }
    private static IArrowArray AppendUInt64Array(List<Variant> values) { var b = new UInt64Array.Builder(); foreach (Variant v in values) { if (v.IsNull) b.AppendNull(); else b.Append(v.GetUInt64()); } return b.Build(s_allocator); }
    private static IArrowArray AppendFloatArray(List<Variant> values) { var b = new FloatArray.Builder(); foreach (Variant v in values) { if (v.IsNull) b.AppendNull(); else b.Append(v.GetFloat()); } return b.Build(s_allocator); }
    private static IArrowArray AppendDoubleArray(List<Variant> values) { var b = new DoubleArray.Builder(); foreach (Variant v in values) { if (v.IsNull) b.AppendNull(); else b.Append(v.GetDouble()); } return b.Build(s_allocator); }
    private static IArrowArray AppendStringArray(List<Variant> values) { var b = new StringArray.Builder(); foreach (Variant v in values) { if (v.IsNull) b.AppendNull(); else b.Append(v.GetString()); } return b.Build(s_allocator); }
    private static IArrowArray AppendDateTimeArray(List<Variant> values) { var b = new Int64Array.Builder(); foreach (Variant v in values) { if (v.IsNull) b.AppendNull(); else b.Append(v.GetDateTime().Value); } return b.Build(s_allocator); }
    private static IArrowArray AppendByteStringArray(List<Variant> values) { var b = new BinaryArray.Builder(); foreach (Variant v in values) { if (v.IsNull || v.GetByteString().IsNull) b.AppendNull(); else b.Append(v.GetByteString().Span); } return b.Build(s_allocator); }
    private static IArrowArray AppendStatusArray(List<Variant> values) { var b = new UInt32Array.Builder(); foreach (Variant v in values) { if (v.IsNull) b.AppendNull(); else b.Append(v.GetStatusCode().Code); } return b.Build(s_allocator); }
    private static IArrowArray AppendGuidArray(List<Variant> values)
    {
        var bytes = new List<byte>(values.Count * 16);
        var validity = new ArrowBuffer.BitmapBuilder(values.Count);
        foreach (Variant v in values)
        {
            bool valid = !v.IsNull;
            validity.Append(valid);
            bytes.AddRange(valid ? v.GetGuid().ToByteArray() : new byte[16]);
        }
        return new FixedSizeBinaryArray(new ArrayData(new FixedSizeBinaryType(16), values.Count, values.Count - validity.SetBitCount, 0, [validity.Build(s_allocator), BuildBuffer(bytes.ToArray())], []));
    }

    private readonly record struct FieldPlan(string Name, int Index, TypeInfo TypeInfo, IArrowType ArrowType);
}
