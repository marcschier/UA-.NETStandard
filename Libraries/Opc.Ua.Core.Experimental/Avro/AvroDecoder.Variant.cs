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
using Opc.Ua;
using Opc.Ua.Types;

namespace Opc.Ua.Core.Experimental
{
    /// <summary>
    /// Decodes OPC UA values using the experimental Avro binary mapping.
    /// </summary>
    public sealed partial class AvroDecoder
    {
        /// <inheritdoc/>
        public Variant ReadVariant(string? fieldName)
        {
            BuiltInType type = (BuiltInType)ReadInt32(null);
            int? valueRank = ReadNullableValue<int?>(() => ReadInt32(null), null);
            int[]? dimensions = valueRank.HasValue && valueRank.Value >= 0 ? ReadInt32Array(null).ToArray() : null;
            return ReadVariantBody(type, valueRank, dimensions);
        }

        /// <inheritdoc/>
        public Variant ReadVariantValue(string? fieldName, TypeInfo typeInfo) =>
            ReadVariantBody(typeInfo.BuiltInType, typeInfo.ValueRank, null);

        private Variant ReadVariantBody(BuiltInType expectedType, int? valueRank, int[]? dimensions)
        {
            long branch = m_reader.ReadLong();

            if (branch == 0 || expectedType == BuiltInType.Null)
            {
                return Variant.Null;
            }

            if (branch != (int)expectedType)
            {
                throw new FormatException($"Unexpected Variant branch {branch}; expected {(int)expectedType}.");
            }

            if (!valueRank.HasValue || valueRank.Value < 0)
            {
                return ReadScalarVariant(expectedType);
            }

            if (dimensions == null || dimensions.Length <= 1)
            {
                return ReadArrayVariant(expectedType);
            }

            return ReadMatrixVariant(expectedType);
        }

        private Variant ReadScalarVariant(BuiltInType type) =>
            type switch
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
                _ => throw new NotSupportedException($"Variant scalar {type} is not supported by the Avro decoder."),
            };

        private Variant ReadArrayVariant(BuiltInType type) =>
            type switch
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
                BuiltInType.String => Variant.From(ReadStringArray(null).ConvertAll(value => value!)),
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
                BuiltInType.DataValue => Variant.From(ReadDataValueArray(null)),
                BuiltInType.Variant => Variant.From(ReadVariantArray(null)),
                _ => throw new NotSupportedException($"Variant array {type} is not supported by the Avro decoder."),
            };

        private Variant ReadMatrixVariant(BuiltInType type) =>
            type switch
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
                BuiltInType.String => Variant.From(ReadMatrix(() => ReadStringArray(null)).ConvertAll(value => value!)),
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
                BuiltInType.DataValue => Variant.From(ReadMatrix(() => ReadDataValueArray(null))),
                BuiltInType.Variant => Variant.From(ReadMatrix(() => ReadVariantArray(null))),
                _ => throw new NotSupportedException($"Variant matrix {type} is not supported by the Avro decoder."),
            };
    }
}
