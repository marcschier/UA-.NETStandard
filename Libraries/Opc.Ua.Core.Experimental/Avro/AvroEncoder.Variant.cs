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
    /// Encodes OPC UA values using the experimental Avro binary mapping.
    /// </summary>
    public sealed partial class AvroEncoder
    {
        /// <inheritdoc/>
        public void WriteVariant(string? fieldName, in Variant value)
        {
            WriteInt32(null, (int)value.TypeInfo.BuiltInType);
            WriteNullable(value.TypeInfo.ValueRank >= 0, value.TypeInfo.ValueRank, v => WriteInt32(null, v));
            if (value.TypeInfo.ValueRank >= 0)
            {
                WriteInt32Array(null, GetVariantDimensions(in value));
            }
            WriteVariantBody(in value);
        }

        private static ArrayOf<int> GetVariantDimensions(in Variant value)
        {
            if (value.TypeInfo.IsScalar || value.TypeInfo.IsArray)
            {
                return Array.Empty<int>();
            }
            return value.TypeInfo.BuiltInType switch
            {
                BuiltInType.Boolean => value.GetBooleanMatrix().Dimensions,
                BuiltInType.SByte => value.GetSByteMatrix().Dimensions,
                BuiltInType.Byte => value.GetByteMatrix().Dimensions,
                BuiltInType.Int16 => value.GetInt16Matrix().Dimensions,
                BuiltInType.UInt16 => value.GetUInt16Matrix().Dimensions,
                BuiltInType.Int32 => value.GetInt32Matrix().Dimensions,
                BuiltInType.Enumeration => value.GetEnumerationMatrix().Dimensions,
                BuiltInType.UInt32 => value.GetUInt32Matrix().Dimensions,
                BuiltInType.Int64 => value.GetInt64Matrix().Dimensions,
                BuiltInType.UInt64 => value.GetUInt64Matrix().Dimensions,
                BuiltInType.Float => value.GetFloatMatrix().Dimensions,
                BuiltInType.Double => value.GetDoubleMatrix().Dimensions,
                BuiltInType.String => value.GetStringMatrix().Dimensions,
                BuiltInType.DateTime => value.GetDateTimeMatrix().Dimensions,
                BuiltInType.Guid => value.GetGuidMatrix().Dimensions,
                BuiltInType.ByteString => value.GetByteStringMatrix().Dimensions,
                BuiltInType.XmlElement => value.GetXmlElementMatrix().Dimensions,
                BuiltInType.NodeId => value.GetNodeIdMatrix().Dimensions,
                BuiltInType.ExpandedNodeId => value.GetExpandedNodeIdMatrix().Dimensions,
                BuiltInType.StatusCode => value.GetStatusCodeMatrix().Dimensions,
                BuiltInType.QualifiedName => value.GetQualifiedNameMatrix().Dimensions,
                BuiltInType.LocalizedText => value.GetLocalizedTextMatrix().Dimensions,
                BuiltInType.ExtensionObject => value.GetExtensionObjectMatrix().Dimensions,
                BuiltInType.DataValue => value.GetDataValueMatrix().Dimensions,
                BuiltInType.Variant => value.GetVariantMatrix().Dimensions,
                _ => Array.Empty<int>(),
            };
        }

        /// <inheritdoc/>
        public void WriteVariantValue(string? fieldName, in Variant value) => WriteVariantBody(in value);

        private void WriteVariantBody(in Variant value)
        {
            TypeInfo typeInfo = value.TypeInfo;
            BuiltInType type = typeInfo.BuiltInType;
            if (value.IsNull || type == BuiltInType.Null || typeInfo.IsUnknown)
            {
                m_writer.WriteLong(0);
                return;
            }
            m_writer.WriteLong((int)type);
            if (typeInfo.IsScalar)
            {
                WriteScalarVariant(in value, type);
            }
            else if (typeInfo.IsArray)
            {
                WriteArrayVariant(in value, type);
            }
            else
            {
                WriteMatrixVariant(in value, type);
            }
        }

        private void WriteScalarVariant(in Variant value, BuiltInType type)
        {
            switch (type)
            {
                case BuiltInType.Boolean:
                    WriteBoolean(null, value.GetBoolean());
                    break;
                case BuiltInType.SByte:
                    WriteSByte(null, value.GetSByte());
                    break;
                case BuiltInType.Byte:
                    WriteByte(null, value.GetByte());
                    break;
                case BuiltInType.Int16:
                    WriteInt16(null, value.GetInt16());
                    break;
                case BuiltInType.UInt16:
                    WriteUInt16(null, value.GetUInt16());
                    break;
                case BuiltInType.Int32:
                    WriteInt32(null, value.GetInt32());
                    break;
                case BuiltInType.Enumeration:
                    WriteEnumerated(null, value.GetEnumeration());
                    break;
                case BuiltInType.UInt32:
                    WriteUInt32(null, value.GetUInt32());
                    break;
                case BuiltInType.Int64:
                    WriteInt64(null, value.GetInt64());
                    break;
                case BuiltInType.UInt64:
                    WriteUInt64(null, value.GetUInt64());
                    break;
                case BuiltInType.Float:
                    WriteFloat(null, value.GetFloat());
                    break;
                case BuiltInType.Double:
                    WriteDouble(null, value.GetDouble());
                    break;
                case BuiltInType.String:
                    WriteString(null, value.GetString());
                    break;
                case BuiltInType.DateTime:
                    WriteDateTime(null, value.GetDateTime());
                    break;
                case BuiltInType.Guid:
                    WriteGuid(null, value.GetGuid());
                    break;
                case BuiltInType.ByteString:
                    WriteByteString(null, value.GetByteString());
                    break;
                case BuiltInType.XmlElement:
                    WriteXmlElement(null, value.GetXmlElement());
                    break;
                case BuiltInType.NodeId:
                    WriteNodeId(null, value.GetNodeId());
                    break;
                case BuiltInType.ExpandedNodeId:
                    WriteExpandedNodeId(null, value.GetExpandedNodeId());
                    break;
                case BuiltInType.StatusCode:
                    WriteStatusCode(null, value.GetStatusCode());
                    break;
                case BuiltInType.QualifiedName:
                    WriteQualifiedName(null, value.GetQualifiedName());
                    break;
                case BuiltInType.LocalizedText:
                    WriteLocalizedText(null, value.GetLocalizedText());
                    break;
                case BuiltInType.ExtensionObject:
                    WriteExtensionObject(null, value.GetExtensionObject());
                    break;
                case BuiltInType.DataValue:
                    WriteDataValue(null, value.GetDataValue());
                    break;
                default:
                    throw new NotSupportedException($"Variant scalar {type} is not supported by the Avro encoder.");
            }
        }

        private void WriteArrayVariant(in Variant value, BuiltInType type)
        {
            switch (type)
            {
                case BuiltInType.Boolean:
                    WriteBooleanArray(null, value.GetBooleanArray());
                    break;
                case BuiltInType.SByte:
                    WriteSByteArray(null, value.GetSByteArray());
                    break;
                case BuiltInType.Byte:
                    WriteByteArray(null, value.GetByteArray());
                    break;
                case BuiltInType.Int16:
                    WriteInt16Array(null, value.GetInt16Array());
                    break;
                case BuiltInType.UInt16:
                    WriteUInt16Array(null, value.GetUInt16Array());
                    break;
                case BuiltInType.Int32:
                    WriteInt32Array(null, value.GetInt32Array());
                    break;
                case BuiltInType.Enumeration:
                    WriteEnumeratedArray(null, value.GetEnumerationArray());
                    break;
                case BuiltInType.UInt32:
                    WriteUInt32Array(null, value.GetUInt32Array());
                    break;
                case BuiltInType.Int64:
                    WriteInt64Array(null, value.GetInt64Array());
                    break;
                case BuiltInType.UInt64:
                    WriteUInt64Array(null, value.GetUInt64Array());
                    break;
                case BuiltInType.Float:
                    WriteFloatArray(null, value.GetFloatArray());
                    break;
                case BuiltInType.Double:
                    WriteDoubleArray(null, value.GetDoubleArray());
                    break;
                case BuiltInType.String:
                    WriteStringArray(null, value.GetStringArray());
                    break;
                case BuiltInType.DateTime:
                    WriteDateTimeArray(null, value.GetDateTimeArray());
                    break;
                case BuiltInType.Guid:
                    WriteGuidArray(null, value.GetGuidArray());
                    break;
                case BuiltInType.ByteString:
                    WriteByteStringArray(null, value.GetByteStringArray());
                    break;
                case BuiltInType.XmlElement:
                    WriteXmlElementArray(null, value.GetXmlElementArray());
                    break;
                case BuiltInType.NodeId:
                    WriteNodeIdArray(null, value.GetNodeIdArray());
                    break;
                case BuiltInType.ExpandedNodeId:
                    WriteExpandedNodeIdArray(null, value.GetExpandedNodeIdArray());
                    break;
                case BuiltInType.StatusCode:
                    WriteStatusCodeArray(null, value.GetStatusCodeArray());
                    break;
                case BuiltInType.QualifiedName:
                    WriteQualifiedNameArray(null, value.GetQualifiedNameArray());
                    break;
                case BuiltInType.LocalizedText:
                    WriteLocalizedTextArray(null, value.GetLocalizedTextArray());
                    break;
                case BuiltInType.ExtensionObject:
                    WriteExtensionObjectArray(null, value.GetExtensionObjectArray());
                    break;
                case BuiltInType.DataValue:
                    WriteDataValueArray(null, value.GetDataValueArray());
                    break;
                case BuiltInType.Variant:
                    WriteVariantArray(null, value.GetVariantArray());
                    break;
                default:
                    throw new NotSupportedException($"Variant array {type} is not supported by the Avro encoder.");
            }
        }

        private void WriteMatrixVariant(in Variant value, BuiltInType type)
        {
            switch (type)
            {
                case BuiltInType.Boolean:
                    WriteMatrix(value.GetBooleanMatrix(), a => WriteBooleanArray(null, a));
                    break;
                case BuiltInType.SByte:
                    WriteMatrix(value.GetSByteMatrix(), a => WriteSByteArray(null, a));
                    break;
                case BuiltInType.Byte:
                    WriteMatrix(value.GetByteMatrix(), a => WriteByteArray(null, a));
                    break;
                case BuiltInType.Int16:
                    WriteMatrix(value.GetInt16Matrix(), a => WriteInt16Array(null, a));
                    break;
                case BuiltInType.UInt16:
                    WriteMatrix(value.GetUInt16Matrix(), a => WriteUInt16Array(null, a));
                    break;
                case BuiltInType.Int32:
                    WriteMatrix(value.GetInt32Matrix(), a => WriteInt32Array(null, a));
                    break;
                case BuiltInType.Enumeration:
                    WriteMatrix(value.GetEnumerationMatrix(), a => WriteEnumeratedArray(null, a));
                    break;
                case BuiltInType.UInt32:
                    WriteMatrix(value.GetUInt32Matrix(), a => WriteUInt32Array(null, a));
                    break;
                case BuiltInType.Int64:
                    WriteMatrix(value.GetInt64Matrix(), a => WriteInt64Array(null, a));
                    break;
                case BuiltInType.UInt64:
                    WriteMatrix(value.GetUInt64Matrix(), a => WriteUInt64Array(null, a));
                    break;
                case BuiltInType.Float:
                    WriteMatrix(value.GetFloatMatrix(), a => WriteFloatArray(null, a));
                    break;
                case BuiltInType.Double:
                    WriteMatrix(value.GetDoubleMatrix(), a => WriteDoubleArray(null, a));
                    break;
                case BuiltInType.String:
                    WriteMatrix(value.GetStringMatrix(), a => WriteStringArray(null, a));
                    break;
                case BuiltInType.DateTime:
                    WriteMatrix(value.GetDateTimeMatrix(), a => WriteDateTimeArray(null, a));
                    break;
                case BuiltInType.Guid:
                    WriteMatrix(value.GetGuidMatrix(), a => WriteGuidArray(null, a));
                    break;
                case BuiltInType.ByteString:
                    WriteMatrix(value.GetByteStringMatrix(), a => WriteByteStringArray(null, a));
                    break;
                case BuiltInType.XmlElement:
                    WriteMatrix(value.GetXmlElementMatrix(), a => WriteXmlElementArray(null, a));
                    break;
                case BuiltInType.NodeId:
                    WriteMatrix(value.GetNodeIdMatrix(), a => WriteNodeIdArray(null, a));
                    break;
                case BuiltInType.ExpandedNodeId:
                    WriteMatrix(value.GetExpandedNodeIdMatrix(), a => WriteExpandedNodeIdArray(null, a));
                    break;
                case BuiltInType.StatusCode:
                    WriteMatrix(value.GetStatusCodeMatrix(), a => WriteStatusCodeArray(null, a));
                    break;
                case BuiltInType.QualifiedName:
                    WriteMatrix(value.GetQualifiedNameMatrix(), a => WriteQualifiedNameArray(null, a));
                    break;
                case BuiltInType.LocalizedText:
                    WriteMatrix(value.GetLocalizedTextMatrix(), a => WriteLocalizedTextArray(null, a));
                    break;
                case BuiltInType.ExtensionObject:
                    WriteMatrix(value.GetExtensionObjectMatrix(), a => WriteExtensionObjectArray(null, a));
                    break;
                case BuiltInType.DataValue:
                    WriteMatrix(value.GetDataValueMatrix(), a => WriteDataValueArray(null, a));
                    break;
                case BuiltInType.Variant:
                    WriteMatrix(value.GetVariantMatrix(), a => WriteVariantArray(null, a));
                    break;
                default:
                    throw new NotSupportedException($"Variant matrix {type} is not supported by the Avro encoder.");
            }
        }
    }
}
