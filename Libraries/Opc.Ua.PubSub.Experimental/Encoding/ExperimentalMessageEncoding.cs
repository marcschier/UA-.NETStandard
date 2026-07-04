using System;
using Opc.Ua.PubSub.Encoding;
using Opc.Ua.PubSub.MetaData;

namespace Opc.Ua.PubSub.Experimental;

internal static class ExperimentalMessageEncoding
{
    public static DataSetMetaDataType? ResolveMetaData(
        PubSubNetworkMessage envelope,
        PubSubDataSetMessage dataSetMessage,
        PubSubNetworkMessageContext context,
        Uuid dataSetClassId)
    {
        if (envelope.MetaData is not null)
        {
            return envelope.MetaData;
        }

        DataSetMetaDataKey key = new(
            envelope.PublisherId,
            envelope.WriterGroupId ?? 0,
            dataSetMessage.DataSetWriterId,
            dataSetClassId,
            dataSetMessage.MetaDataVersion.MajorVersion);
        MetaDataMatchResult match = context.MetaDataRegistry.TryGet(
            in key,
            out DataSetMetaDataType? metaData);
        return match is MetaDataMatchResult.Match or MetaDataMatchResult.MinorVersionMismatch
            ? metaData
            : null;
    }

    public static string ResolveFieldName(
        DataSetField field,
        DataSetMetaDataType? metaData,
        int index)
    {
        if (!string.IsNullOrEmpty(field.Name))
        {
            return field.Name;
        }
        if (metaData is not null
            && metaData.Fields.Count > index
            && metaData.Fields[index].Name is { Length: > 0 } name)
        {
            return name;
        }
        return FormattableString.Invariant($"Field{index}");
    }

    public static FieldMetaData? ResolveFieldMetaData(
        DataSetMetaDataType? metaData,
        string name,
        int index)
    {
        if (metaData is null || metaData.Fields.Count == 0)
        {
            return null;
        }
        for (int i = 0; i < metaData.Fields.Count; i++)
        {
            FieldMetaData candidate = metaData.Fields[i];
            if (string.Equals(candidate.Name, name, StringComparison.Ordinal))
            {
                return candidate;
            }
        }
        return index >= 0 && index < metaData.Fields.Count ? metaData.Fields[index] : null;
    }

    public static TypeInfo? ResolveFieldType(
        DataSetMetaDataType? metaData,
        string name,
        int index)
    {
        FieldMetaData? field = ResolveFieldMetaData(metaData, name, index);
        return field is null
            ? null
            : TypeInfo.Create((BuiltInType)field.BuiltInType, field.ValueRank);
    }

    public static DataValue BuildDataValue(DataSetField field, DataSetFieldContentMask mask)
    {
        if (mask == DataSetFieldContentMask.None)
        {
            return new DataValue(
                field.Value,
                field.StatusCode,
                field.SourceTimestamp,
                field.ServerTimestamp,
                field.SourcePicoSeconds,
                field.ServerPicoSeconds);
        }

        StatusCode statusCode = (mask & DataSetFieldContentMask.StatusCode) != 0
            ? field.StatusCode : default;
        DateTimeUtc sourceTimestamp = (mask & DataSetFieldContentMask.SourceTimestamp) != 0
            ? field.SourceTimestamp : default;
        ushort sourcePicoSeconds = (mask & DataSetFieldContentMask.SourcePicoSeconds) != 0
            ? field.SourcePicoSeconds : (ushort)0;
        DateTimeUtc serverTimestamp = (mask & DataSetFieldContentMask.ServerTimestamp) != 0
            ? field.ServerTimestamp : default;
        ushort serverPicoSeconds = (mask & DataSetFieldContentMask.ServerPicoSeconds) != 0
            ? field.ServerPicoSeconds : (ushort)0;
        return new DataValue(
            field.Value,
            statusCode,
            sourceTimestamp,
            serverTimestamp,
            sourcePicoSeconds,
            serverPicoSeconds);
    }

    public static DataSetField FromDataValue(
        string name,
        int index,
        DataValue value,
        DataSetFieldContentMask mask)
    {
        return new DataSetField
        {
            Name = name,
            FieldIndex = index,
            Value = value.WrappedValue,
            StatusCode = mask == DataSetFieldContentMask.None
                || (mask & DataSetFieldContentMask.StatusCode) != 0
                    ? value.StatusCode
                    : (StatusCode)StatusCodes.Good,
            SourceTimestamp = mask == DataSetFieldContentMask.None
                || (mask & DataSetFieldContentMask.SourceTimestamp) != 0
                    ? value.SourceTimestamp
                    : default,
            SourcePicoSeconds = mask == DataSetFieldContentMask.None
                || (mask & DataSetFieldContentMask.SourcePicoSeconds) != 0
                    ? value.SourcePicoseconds
                    : (ushort)0,
            ServerTimestamp = mask == DataSetFieldContentMask.None
                || (mask & DataSetFieldContentMask.ServerTimestamp) != 0
                    ? value.ServerTimestamp
                    : default,
            ServerPicoSeconds = mask == DataSetFieldContentMask.None
                || (mask & DataSetFieldContentMask.ServerPicoSeconds) != 0
                    ? value.ServerPicoseconds
                    : (ushort)0,
            Encoding = PubSubFieldEncoding.DataValue
        };
    }
}
