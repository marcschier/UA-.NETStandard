#pragma warning disable RCS0056, RCS1007, CS8600, CS8604, CS8620
using System;
using Opc.Ua;
using Opc.Ua.Types;

namespace Opc.Ua.Core.Experimental
{
    public sealed partial class AvroDecoder
    {
        public Variant ReadVariant(string? fieldName)
        {
            BuiltInType type = (BuiltInType)ReadInt32(null);
            int? valueRank = ReadNullableValue<int?>(() => ReadInt32(null), null);
            int[]? dimensions = valueRank.HasValue && valueRank.Value >= 0 ? ReadInt32Array(null).ToArray() : null;
            return ReadVariantBody(type, valueRank, dimensions);
        }

        public Variant ReadVariantValue(string? fieldName, TypeInfo typeInfo)
            => ReadVariantBody(typeInfo.BuiltInType, typeInfo.ValueRank, null);

        private Variant ReadVariantBody(BuiltInType expectedType, int? valueRank, int[]? dimensions)
        {
            long branch = m_reader.ReadLong();
            if (branch == 0 || expectedType == BuiltInType.Null) return Variant.Null;
            if (branch != (int)expectedType) throw new FormatException($"Unexpected Variant branch {branch}; expected {(int)expectedType}.");
            if (!valueRank.HasValue || valueRank.Value < 0) return ReadScalarVariant(expectedType);
            if (dimensions == null || dimensions.Length <= 1) return ReadArrayVariant(expectedType);
            return ReadMatrixVariant(expectedType);
        }

        private Variant ReadScalarVariant(BuiltInType type) => type switch
        {
            BuiltInType.Boolean => Variant.From(ReadBoolean(null)),
            BuiltInType.SByte => Variant.From(ReadSByte(null)),
            BuiltInType.Byte => Variant.From(ReadByte(null)),
            BuiltInType.Int16 => Variant.From(ReadInt16(null)),
            BuiltInType.UInt16 => Variant.From(ReadUInt16(null)),
            BuiltInType.Int32 => Variant.From(ReadInt32(null)),
            BuiltInType.Enumeration => Variant.From(ReadEnumerated(null)),
            BuiltInType.UInt32 => Variant.From(ReadUInt32(null)),
            BuiltInType.Int64 => Variant.From(ReadInt64(null)),
            BuiltInType.UInt64 => Variant.From(ReadUInt64(null)),
            BuiltInType.Float => Variant.From(ReadFloat(null)),
            BuiltInType.Double => Variant.From(ReadDouble(null)),
            BuiltInType.String => Variant.From(ReadString(null)!),
            BuiltInType.DateTime => Variant.From(ReadDateTime(null)),
            BuiltInType.Guid => Variant.From(ReadGuid(null)),
            BuiltInType.ByteString => Variant.From(ReadByteString(null)),
            BuiltInType.XmlElement => Variant.From(ReadXmlElement(null)),
            BuiltInType.NodeId => Variant.From(ReadNodeId(null)),
            BuiltInType.ExpandedNodeId => Variant.From(ReadExpandedNodeId(null)),
            BuiltInType.StatusCode => Variant.From(ReadStatusCode(null)),
            BuiltInType.QualifiedName => Variant.From(ReadQualifiedName(null)),
            BuiltInType.LocalizedText => Variant.From(ReadLocalizedText(null)),
            BuiltInType.ExtensionObject => Variant.From(ReadExtensionObject(null)),
            BuiltInType.DataValue => Variant.From(ReadDataValue(null)),
            _ => throw new NotSupportedException($"Variant scalar {type} is not supported by the Avro decoder.")
        };

        private Variant ReadArrayVariant(BuiltInType type) => type switch
        {
            BuiltInType.Boolean => Variant.From(ReadBooleanArray(null)),
            BuiltInType.SByte => Variant.From(ReadSByteArray(null)),
            BuiltInType.Byte => Variant.From(ReadByteArray(null)),
            BuiltInType.Int16 => Variant.From(ReadInt16Array(null)),
            BuiltInType.UInt16 => Variant.From(ReadUInt16Array(null)),
            BuiltInType.Int32 => Variant.From(ReadInt32Array(null)),
            BuiltInType.Enumeration => Variant.From(ReadEnumeratedArray(null)),
            BuiltInType.UInt32 => Variant.From(ReadUInt32Array(null)),
            BuiltInType.Int64 => Variant.From(ReadInt64Array(null)),
            BuiltInType.UInt64 => Variant.From(ReadUInt64Array(null)),
            BuiltInType.Float => Variant.From(ReadFloatArray(null)),
            BuiltInType.Double => Variant.From(ReadDoubleArray(null)),
#pragma warning disable CS8620
            BuiltInType.String => Variant.From(ReadStringArray(null)),
#pragma warning restore CS8620
            BuiltInType.DateTime => Variant.From(ReadDateTimeArray(null)),
            BuiltInType.Guid => Variant.From(ReadGuidArray(null)),
            BuiltInType.ByteString => Variant.From(ReadByteStringArray(null)),
            BuiltInType.XmlElement => Variant.From(ReadXmlElementArray(null)),
            BuiltInType.NodeId => Variant.From(ReadNodeIdArray(null)),
            BuiltInType.ExpandedNodeId => Variant.From(ReadExpandedNodeIdArray(null)),
            BuiltInType.StatusCode => Variant.From(ReadStatusCodeArray(null)),
            BuiltInType.QualifiedName => Variant.From(ReadQualifiedNameArray(null)),
            BuiltInType.LocalizedText => Variant.From(ReadLocalizedTextArray(null)),
            BuiltInType.ExtensionObject => Variant.From(ReadExtensionObjectArray(null)),
#pragma warning disable CS8620
            BuiltInType.DataValue => Variant.From(ReadDataValueArray(null)),
#pragma warning restore CS8620
            BuiltInType.Variant => Variant.From(ReadVariantArray(null)),
            _ => throw new NotSupportedException($"Variant array {type} is not supported by the Avro decoder.")
        };

        private Variant ReadMatrixVariant(BuiltInType type) => type switch
        {
            BuiltInType.Boolean => Variant.From(ReadMatrix(() => ReadBooleanArray(null))),
            BuiltInType.SByte => Variant.From(ReadMatrix(() => ReadSByteArray(null))),
            BuiltInType.Byte => Variant.From(ReadMatrix(() => ReadByteArray(null))),
            BuiltInType.Int16 => Variant.From(ReadMatrix(() => ReadInt16Array(null))),
            BuiltInType.UInt16 => Variant.From(ReadMatrix(() => ReadUInt16Array(null))),
            BuiltInType.Int32 => Variant.From(ReadMatrix(() => ReadInt32Array(null))),
            BuiltInType.Enumeration => Variant.From(ReadMatrix(() => ReadEnumeratedArray(null))),
            BuiltInType.UInt32 => Variant.From(ReadMatrix(() => ReadUInt32Array(null))),
            BuiltInType.Int64 => Variant.From(ReadMatrix(() => ReadInt64Array(null))),
            BuiltInType.UInt64 => Variant.From(ReadMatrix(() => ReadUInt64Array(null))),
            BuiltInType.Float => Variant.From(ReadMatrix(() => ReadFloatArray(null))),
            BuiltInType.Double => Variant.From(ReadMatrix(() => ReadDoubleArray(null))),
#pragma warning disable CS8620
            BuiltInType.String => Variant.From(ReadMatrix(() => ReadStringArray(null))),
#pragma warning restore CS8620
            BuiltInType.DateTime => Variant.From(ReadMatrix(() => ReadDateTimeArray(null))),
            BuiltInType.Guid => Variant.From(ReadMatrix(() => ReadGuidArray(null))),
            BuiltInType.ByteString => Variant.From(ReadMatrix(() => ReadByteStringArray(null))),
            BuiltInType.XmlElement => Variant.From(ReadMatrix(() => ReadXmlElementArray(null))),
            BuiltInType.NodeId => Variant.From(ReadMatrix(() => ReadNodeIdArray(null))),
            BuiltInType.ExpandedNodeId => Variant.From(ReadMatrix(() => ReadExpandedNodeIdArray(null))),
            BuiltInType.StatusCode => Variant.From(ReadMatrix(() => ReadStatusCodeArray(null))),
            BuiltInType.QualifiedName => Variant.From(ReadMatrix(() => ReadQualifiedNameArray(null))),
            BuiltInType.LocalizedText => Variant.From(ReadMatrix(() => ReadLocalizedTextArray(null))),
            BuiltInType.ExtensionObject => Variant.From(ReadMatrix(() => ReadExtensionObjectArray(null))),
#pragma warning disable CS8620
            BuiltInType.DataValue => Variant.From(ReadMatrix(() => ReadDataValueArray(null))),
            BuiltInType.Variant => Variant.From(ReadMatrix(() => ReadVariantArray(null))),
#pragma warning restore CS8620
            _ => throw new NotSupportedException($"Variant matrix {type} is not supported by the Avro decoder.")
        };
    }
}


