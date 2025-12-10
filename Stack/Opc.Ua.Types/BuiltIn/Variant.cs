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
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text;
using System.Text.Json.Serialization;
using System.Xml;
using Opc.Ua.Schema.Model;
using Opc.Ua.Types;

namespace Opc.Ua
{
    /// <summary>
    /// A structure that could contain value with any of the UA built-in
    /// data types.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The Variant is described in <b>Part 6 - Mappings, Section 6.2.2.15</b>,
    /// titled <b>Variant</b>
    /// <br/></para>
    /// <para>
    /// Variant is a data type in COM, but not within the .NET Framework.
    /// Therefore OPC UA has its own Variant type that supports all of the
    /// OPC UA data-types.
    /// <br/></para>
    /// </remarks>
    public readonly struct Variant :
        IFormattable,
        IEquatable<Variant>,
        IEquatable<bool>,
        IEquatable<sbyte>,
        IEquatable<byte>,
        IEquatable<short>,
        IEquatable<ushort>,
        IEquatable<int>,
        IEquatable<uint>,
        IEquatable<long>,
        IEquatable<ulong>,
        IEquatable<float>,
        IEquatable<double>,
        IEquatable<string>,
        IEquatable<DateTime>,
        IEquatable<Uuid>,
        IEquatable<byte[]>,
        IEquatable<XmlElement>,
        IEquatable<NodeId>,
        IEquatable<ExpandedNodeId>,
        IEquatable<StatusCode>,
        IEquatable<QualifiedName>,
        IEquatable<LocalizedText>,
        IEquatable<ExtensionObject>,
        IEquatable<DataValue>,
        IEquatable<bool[]>,
        IEquatable<sbyte[]>,
        IEquatable<short[]>,
        IEquatable<ushort[]>,
        IEquatable<int[]>,
        IEquatable<uint[]>,
        IEquatable<long[]>,
        IEquatable<ulong[]>,
        IEquatable<float[]>,
        IEquatable<double[]>,
        IEquatable<string[]>,
        IEquatable<DateTime[]>,
        IEquatable<Uuid[]>,
        IEquatable<byte[][]>,
        IEquatable<XmlElement[]>,
        IEquatable<NodeId[]>,
        IEquatable<ExpandedNodeId[]>,
        IEquatable<StatusCode[]>,
        IEquatable<QualifiedName[]>,
        IEquatable<LocalizedText[]>,
        IEquatable<ExtensionObject[]>,
        IEquatable<DataValue[]>,
        IEquatable<Variant[]>
    {
        /// <summary>
        /// Creates a new variant instance while specifying the value.
        /// </summary>
        /// <param name="value">The value to encode within the variant</param>
        public Variant(object value)
        {
            this = new Variant(value, TypeInfo.Construct(value));
        }

        /// <summary>
        /// Initializes the variant with an Array value and the type information.
        /// </summary>
        /// <param name="value">The value to store within the variant</param>
        public Variant(Array value)
        {
            this = new Variant(value, TypeInfo.Construct(value));
        }

        /// <summary>
        /// Initializes the variant with matrix.
        /// </summary>
        /// <param name="value">The value to store within the variant</param>
        public Variant(Matrix value)
        {
            m_value = value;
            TypeInfo = value.TypeInfo;
        }

        /// <summary>
        /// Creates a new Variant with a Boolean value.
        /// </summary>
        /// <param name="value">The value of the variant</param>
        public Variant(bool value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.Boolean;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="sbyte"/> value
        /// </summary>
        /// <param name="value">The <see cref="sbyte"/> value of the Variant</param>
        public Variant(sbyte value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.SByte;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="byte"/> value
        /// </summary>
        /// <param name="value">The <see cref="byte"/> value of the Variant</param>
        public Variant(byte value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.Byte;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="short"/> value
        /// </summary>
        /// <param name="value">The <see cref="short"/> value of the Variant</param>
        public Variant(short value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.Int16;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="ushort"/> value
        /// </summary>
        /// <param name="value">The <see cref="ushort"/> value of the Variant</param>
        public Variant(ushort value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.UInt16;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="int"/> value
        /// </summary>
        /// <param name="value">The <see cref="int"/> value of the Variant</param>
        public Variant(int value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.Int32;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="uint"/> value
        /// </summary>
        /// <param name="value">The <see cref="uint"/> value of the Variant</param>
        public Variant(uint value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.UInt32;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="long"/> value
        /// </summary>
        /// <param name="value">The <see cref="long"/> value of the Variant</param>
        public Variant(long value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.Int64;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="ulong"/> value
        /// </summary>
        /// <param name="value">The <see cref="ulong"/> value of the Variant</param>
        public Variant(ulong value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.UInt64;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="float"/> value
        /// </summary>
        /// <param name="value">The <see cref="float"/> value of the Variant</param>
        public Variant(float value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.Float;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="double"/> value
        /// </summary>
        /// <param name="value">The <see cref="double"/> value of the Variant</param>
        public Variant(double value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.Double;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="string"/> value
        /// </summary>
        /// <param name="value">The <see cref="string"/> value of the Variant</param>
        public Variant(string value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.String;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="DateTime"/> value
        /// </summary>
        /// <param name="value">The <see cref="DateTime"/> value of the Variant</param>
        public Variant(DateTime value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.DateTime;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="Uuid"/> value
        /// </summary>
        /// <param name="value">The <see cref="Uuid"/> value of the Variant</param>
        public Variant(Uuid value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.Guid;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="byte"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="byte"/>-array value of the Variant</param>
        public Variant(byte[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.ByteString;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="XmlElement"/> value
        /// </summary>
        /// <param name="value">The <see cref="XmlElement"/> value of the Variant</param>
        public Variant(XmlElement value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.XmlElement;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="NodeId"/> value
        /// </summary>
        /// <param name="value">The <see cref="NodeId"/> value of the Variant</param>
        public Variant(NodeId value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.NodeId;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="ExpandedNodeId"/> value
        /// </summary>
        /// <param name="value">The <see cref="ExpandedNodeId"/> value of the Variant</param>
        public Variant(ExpandedNodeId value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.ExpandedNodeId;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="StatusCode"/> value
        /// </summary>
        /// <param name="value">The <see cref="StatusCode"/> value of the Variant</param>
        public Variant(StatusCode value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.StatusCode;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="QualifiedName"/> value
        /// </summary>
        /// <param name="value">The <see cref="QualifiedName"/> value of the Variant</param>
        public Variant(QualifiedName value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.QualifiedName;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="LocalizedText"/> value
        /// </summary>
        /// <param name="value">The <see cref="LocalizedText"/> value of the Variant</param>
        public Variant(LocalizedText value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.LocalizedText;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="ExtensionObject"/> value
        /// </summary>
        /// <param name="value">The <see cref="ExtensionObject"/> value of the Variant</param>
        public Variant(ExtensionObject value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.ExtensionObject;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="DataValue"/> value
        /// </summary>
        /// <param name="value">The <see cref="DataValue"/> value of the Variant</param>
        public Variant(DataValue value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Scalars.DataValue;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="bool"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="bool"/>-array value of the Variant</param>
        public Variant(bool[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.Boolean;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="sbyte"/>-arrat value
        /// </summary>
        /// <param name="value">The <see cref="sbyte"/>-array value of the Variant</param>
        public Variant(sbyte[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.SByte;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="short"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="short"/>-array value of the Variant</param>
        public Variant(short[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.Int16;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="ushort"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="ushort"/>-array value of the Variant</param>
        public Variant(ushort[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.UInt16;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="int"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="int"/>-array value of the Variant</param>
        public Variant(int[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.Int32;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="uint"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="uint"/>-array value of the Variant</param>
        public Variant(uint[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.UInt32;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="long"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="long"/>-array value of the Variant</param>
        public Variant(long[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.Int64;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="ulong"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="ulong"/>-array value of the Variant</param>
        public Variant(ulong[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.UInt64;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="float"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="float"/>-array value of the Variant</param>
        public Variant(float[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.Float;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="double"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="double"/>-array value of the Variant</param>
        public Variant(double[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.Double;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="string"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="string"/>-array value of the Variant</param>
        public Variant(string[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.String;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="DateTime"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="DateTime"/>-array value of the Variant</param>
        public Variant(DateTime[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.DateTime;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="Uuid"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="Uuid"/>-array value of the Variant</param>
        public Variant(Uuid[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.Guid;
        }

        /// <summary>
        /// Creates a new variant with a 2-d <see cref="byte"/>-array value
        /// </summary>
        /// <param name="value">The 2-d <see cref="byte"/>-array value of the Variant</param>
        public Variant(byte[][] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.ByteString;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="XmlElement"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="XmlElement"/>-array value of the Variant</param>
        public Variant(XmlElement[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.XmlElement;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="NodeId"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="NodeId"/>-array value of the Variant</param>
        public Variant(NodeId[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.NodeId;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="ExpandedNodeId"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="ExpandedNodeId"/>-array value of the Variant</param>
        public Variant(ExpandedNodeId[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.ExpandedNodeId;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="StatusCode"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="StatusCode"/>-array value of the Variant</param>
        public Variant(StatusCode[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.StatusCode;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="QualifiedName"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="QualifiedName"/>-array value of the Variant</param>
        public Variant(QualifiedName[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.QualifiedName;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="LocalizedText"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="LocalizedText"/>-array value of the Variant</param>
        public Variant(LocalizedText[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.LocalizedText;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="ExtensionObject"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="ExtensionObject"/>-array value of the Variant</param>
        public Variant(ExtensionObject[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.ExtensionObject;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="DataValue"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="DataValue"/>-array value of the Variant</param>
        public Variant(DataValue[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.DataValue;
        }

        /// <summary>
        /// Creates a new variant with a <see cref="Variant"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="Variant"/>-array value of the Variant</param>
        public Variant(Variant[] value)
        {
            m_value = value;
            TypeInfo = TypeInfo.Arrays.Variant;
        }

        /// <summary>
        /// Constructs a Variant
        /// </summary>
        /// <param name="value">The value to store.</param>
        /// <param name="typeInfo">The type information for the value.</param>
        [JsonConstructor]
        public Variant(object value, TypeInfo typeInfo)
        {
            m_value = value is ICloneable clonable ? clonable.Clone() : value;
            TypeInfo = typeInfo;

            // check for null values.
            if (m_value == null)
            {
                // m_value = typeInfo.ValueRank < 0 ?
                //      TypeInfo.GetDefaultValue(typeInfo.BuiltInType) :
                //      null;
                return;
            }

            // handle scalar values.
            if (typeInfo.ValueRank < 0)
            {
                switch (typeInfo.BuiltInType)
                {
                    // handle special types that can be converted to something the variant supports.
                    case BuiltInType.Null:
                        // check for enumerated value.
                        if (m_value.GetType().GetTypeInfo().IsEnum)
                        {
                            this = From(Convert.ToInt32(m_value, CultureInfo.InvariantCulture));
                            break;
                        }

                        // check for matrix
                        if (m_value is Matrix m)
                        {
                            TypeInfo = m.TypeInfo;
                            break;
                        }
                        // not supported.
                        throw new ServiceResultException(
                            StatusCodes.BadNotSupported,
                            CoreUtils.Format(
                                "The type '{0}' cannot be stored in a Variant object.",
                                m_value.GetType().FullName));
                    // convert encodeables to extension objects.
                    case BuiltInType.ExtensionObject:
                        if (m_value is IEncodeable encodeable)
                        {
                            m_value = new ExtensionObject(encodeable);
                            break;
                        }
                        break;
                    case BuiltInType.Guid:
                        if (m_value is Guid guid)
                        {
                            m_value = new Uuid(guid);
                            break;
                        }
                        break;
                    case BuiltInType.Variant:
                        m_value = ((Variant)m_value).Value;
                        TypeInfo = TypeInfo.Construct(m_value);
                        break;
                    // just save the value.
                    case > BuiltInType.Null and <= BuiltInType.Enumeration:
                        break;
                    default:
                        throw ServiceResultException.Unexpected(
                            $"Unexpected BuiltInType {typeInfo.BuiltInType}");
                }
                DebugCheck(m_value, TypeInfo);
                return;
            }

            // Convert list types to arrays
            if (m_value is not Array)
            {
                // Convert enumerable types to arrays
                switch (m_value)
                {
                    case ICollection collection when collection.Count == 0:
                        // Fast path for empty arrays
                        m_value = TypeInfo.CreateArray(typeInfo.BuiltInType, 0);
                        DebugCheck(m_value, TypeInfo);
                        return;
                    case IEnumerable enumerable:
                        if (enumerable is not IList list)
                        {
                            list = new List<object>(enumerable.Cast<object>());
                        }
                        var items = Array.CreateInstance(list[0].GetType(), list.Count);
                        for (int i = 0; i < list.Count; i++)
                        {
                            items.SetValue(list[i], i);
                        }
                        m_value = items;
                        break;
                }
            }

            // handle one dimensional arrays.
            if (typeInfo.ValueRank <= 1)
            {
                if (m_value is Matrix matrix)
                {
                    m_value = matrix.ToArray();
                }
                if (m_value is not Array array)
                {
                    // not supported.
                    throw new ServiceResultException(
                        StatusCodes.BadNotSupported,
                        CoreUtils.Format(
                            "The type '{0}' cannot be stored as Array in a Variant object.",
                            m_value.GetType().FullName));
                }
                switch (typeInfo.BuiltInType)
                {
                    // handle special types that can be converted to something the variant supports.
                    case BuiltInType.Null:
                        // check for enumerated value.
                        if (!array.GetType().GetElementType().GetTypeInfo().IsEnum)
                        {
                            // not supported.
                            throw new ServiceResultException(
                                StatusCodes.BadNotSupported,
                                CoreUtils.Format(
                                    "The type '{0}' cannot be stored in a Variant object.",
                                    array.GetType().FullName));
                        }
                        int[] values = new int[array.Length];
                        for (int ii = 0; ii < array.Length; ii++)
                        {
                            values[ii] = Convert.ToInt32(
                                array.GetValue(ii),
                                CultureInfo.InvariantCulture);
                        }
                        m_value = values;
                        break;
                    // convert encodeables to extension objects.
                    case BuiltInType.ExtensionObject:
                        if (array is IEncodeable[] encodeables)
                        {
                            var extensions = new ExtensionObject[encodeables.Length];
                            for (int ii = 0; ii < encodeables.Length; ii++)
                            {
                                extensions[ii] = new ExtensionObject(encodeables[ii]);
                            }
                            m_value = extensions;
                        }
                        break;
                    // convert objects to variants objects.
                    case BuiltInType.Variant:
                        if (array is object[] objects)
                        {
                            var variants = new Variant[objects.Length];
                            for (int ii = 0; ii < objects.Length; ii++)
                            {
                                variants[ii] = new Variant(objects[ii]);
                            }
                            m_value = variants;
                        }
                        break;
                    case BuiltInType.Guid:
                        if (array is Guid[] guids)
                        {
                            m_value = ((UuidCollection)guids).ToArray();
                        }
                        break;
                    // just save the value.
                    case >= BuiltInType.Null and <= BuiltInType.Enumeration:
                        break;
                    default:
                        throw ServiceResultException.Unexpected(
                            $"Unexpected BuiltInType {typeInfo.BuiltInType}");
                }
            }
            else // handle multidimensional array.
            {
                if (m_value is Array array)
                {
                    m_value = new Matrix(array, typeInfo.BuiltInType);
                }
                // handle matrix.
                if (m_value is not Matrix matrix)
                {
                    // not supported.
                    throw new ServiceResultException(
                        StatusCodes.BadNotSupported,
                        CoreUtils.Format(
                            "Arrays of the type '{0}' cannot be stored in a Variant object.",
                            m_value.GetType().FullName));
                }
                TypeInfo = matrix.TypeInfo;
            }
            DebugCheck(m_value, TypeInfo);
        }

        /// <summary>
        /// Constructs a Variant
        /// </summary>
        /// <param name="array">The value to store.</param>
        /// <param name="typeInfo">The type information for the value.</param>
        public Variant(Array array, TypeInfo typeInfo)
        {
            m_value = array;
            TypeInfo = typeInfo;

            if (typeInfo.ValueRank > 1)
            {
                this = new Variant(new Matrix(array, typeInfo.BuiltInType));
                return;
            }

            switch (typeInfo.BuiltInType)
            {
                // handle special types that can be converted to something the variant supports.
                case BuiltInType.Null:
                    // check for enumerated value.
                    if (!array.GetType().GetElementType().GetTypeInfo().IsEnum)
                    {
                        // not supported.
                        throw new ServiceResultException(
                            StatusCodes.BadNotSupported,
                            CoreUtils.Format(
                                "The type '{0}' cannot be stored in a Variant object.",
                                array.GetType().FullName));
                    }
                    int[] values = new int[array.Length];
                    for (int ii = 0; ii < array.Length; ii++)
                    {
                        values[ii] = Convert.ToInt32(
                            array.GetValue(ii),
                            CultureInfo.InvariantCulture);
                    }
                    m_value = values;
                    break;
                // convert encodeables to extension objects.
                case BuiltInType.ExtensionObject:
                    if (array is IEncodeable[] encodeables)
                    {
                        var extensions = new ExtensionObject[encodeables.Length];
                        for (int ii = 0; ii < encodeables.Length; ii++)
                        {
                            extensions[ii] = new ExtensionObject(encodeables[ii]);
                        }
                        m_value = extensions;
                    }
                    break;
                case BuiltInType.Guid:
                    if (array is Guid[] guids)
                    {
                        m_value = ((UuidCollection)guids).ToArray();
                    }
                    break;
                // convert objects to variants objects.
                case BuiltInType.Variant:
                    if (array is object[] objects)
                    {
                        var variants = new Variant[objects.Length];
                        for (int ii = 0; ii < objects.Length; ii++)
                        {
                            variants[ii] = new Variant(objects[ii]);
                        }
                        m_value = variants;
                    }
                    break;
                // just save the value.
                case >= BuiltInType.Null and <= BuiltInType.Enumeration:
                    m_value = CoreUtils.Clone(array);
                    break;
                default:
                    throw ServiceResultException.Unexpected(
                        $"Unexpected BuiltInType {typeInfo.BuiltInType}");
            }
        }

        /// <summary>
        /// Initializes the object with an object array value.
        /// </summary>
        /// <summary>
        /// Creates a new variant with a <see cref="object"/>-array value
        /// </summary>
        /// <param name="value">The <see cref="object"/>-array value
        /// of the Variant</param>
        public Variant(object[] value)
        {
            m_value = null;
            TypeInfo = TypeInfo.Arrays.Variant;
            if (value != null)
            {
                var anyValues = new Variant[value.Length];
                for (int ii = 0; ii < value.Length; ii++)
                {
                    anyValues[ii] = new Variant(value[ii]);
                }
                m_value = anyValues;
            }
        }

        /// <summary>
        /// Box the value stored in the Variant as object
        /// </summary>
        /// <returns></returns>
        public object AsBoxedObject()
        {
            if (TypeInfo.IsUnknown)
            {
                return m_value;
            }
            if (TypeInfo.ValueRank < 0)
            {
                // Handle built-in value type null values
                switch (TypeInfo.BuiltInType)
                {
                    case BuiltInType.NodeId:
                        return m_value is NodeId v ? v : default;
                    case BuiltInType.ExpandedNodeId:
                        return m_value is ExpandedNodeId e ? e : default;
                    case BuiltInType.LocalizedText:
                        return m_value is LocalizedText l ? l : default;
                    case BuiltInType.QualifiedName:
                        return m_value is QualifiedName q ? q : default;
                    case BuiltInType.StatusCode:
                        return m_value is StatusCode s ? s : default;
                }
            }
            return m_value;
        }

        /// <summary>
        /// An constant containing a null Variant structure.
        /// </summary>
        public static readonly Variant Null;

        /// <summary>
        /// Returns if the Variant is a Null value.
        /// </summary>
        [JsonIgnore]
        public bool IsNull => m_value == null;

        /// <summary>
        /// The value stored -as <see cref="object"/>- within
        /// the Variant object.
        /// </summary>
        [JsonPropertyName("Value")]
        public object Value => AsBoxedObject();

        /// <summary>
        /// The type information for the matrix.
        /// </summary>
        [JsonPropertyName("TypeInfo")]
        public TypeInfo TypeInfo { get; }

        /// <summary>
        /// Returns a unique hashcode for the object.
        /// </summary>
        public override int GetHashCode()
        {
            if (!IsNull)
            {
                return AsBoxedObject().GetHashCode();
            }
            return 0;
        }

        /// <summary>
        /// Converts the value to a human readable string.
        /// </summary>
        public override string ToString()
        {
            return ToString(null, null);
        }

        /// <summary>
        /// Returns the string representation of the object.
        /// </summary>
        /// <exception cref="FormatException">Thrown when the
        /// 'format' argument is NOT null.</exception>
        /// <param name="format">(Unused) Always pass a NULL value</param>
        /// <param name="formatProvider">The format-provider to
        /// use. If unsure, pass an empty string or null</param>
        public string ToString(string format, IFormatProvider formatProvider)
        {
            if (format == null)
            {
                var buffer = new StringBuilder();
                AppendFormat(buffer, m_value, formatProvider);
                return buffer.ToString();
            }

            throw new FormatException(
                CoreUtils.Format("Invalid format string: '{0}'.", format));
        }

        /// <summary>
        /// Converts a bool value to an Variant object.
        /// </summary>
        public bool GetBoolean(bool defaultValue = default)
        {
            return TryGet(out bool v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a sbyte value to an Variant object.
        /// </summary>
        public sbyte GetSByte(sbyte defaultValue = default)
        {
            return TryGet(out sbyte v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a byte value to an Variant object.
        /// </summary>
        public byte GetByte(byte defaultValue = default)
        {
            return TryGet(out byte v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a short value to an Variant object.
        /// </summary>
        public short GetInt16(short defaultValue = default)
        {
            return TryGet(out short v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a ushort value to an Variant object.
        /// </summary>
        public ushort GetUInt16(ushort defaultValue = default)
        {
            return TryGet(out ushort v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a int value to an Variant object.
        /// </summary>
        public int GetInt32(int defaultValue = default)
        {
            return TryGet(out int v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a uint value to an Variant object.
        /// </summary>
        public uint GetUInt32(uint defaultValue = default)
        {
            return TryGet(out uint v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a long value to an Variant object.
        /// </summary>
        public long GetInt64(long defaultValue = default)
        {
            return TryGet(out long v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a ulong value to an Variant object.
        /// </summary>
        public ulong GetUInt64(ulong defaultValue = default)
        {
            return TryGet(out ulong v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a float value to an Variant object.
        /// </summary>
        public float GetFloat(float defaultValue = default)
        {
            return TryGet(out float v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a double value to an Variant object.
        /// </summary>
        public double GetDouble(double defaultValue = default)
        {
            return TryGet(out double v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a string value to an Variant object.
        /// </summary>
        public string GetString(string defaultValue = default)
        {
            return TryGet(out string v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a DateTime value to an Variant object.
        /// </summary>
        public DateTime GetDateTime(DateTime defaultValue = default)
        {
            return TryGet(out DateTime v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a Uuid value to an Variant object.
        /// </summary>
        public Uuid GetGuid(Uuid defaultValue = default)
        {
            return TryGet(out Uuid v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a byte[] value to an Variant object.
        /// </summary>
        public byte[] GetByteString(byte[] defaultValue = default)
        {
            return TryGet(out byte[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a XmlElement value to an Variant object.
        /// </summary>
        public XmlElement GetXmlElement(XmlElement defaultValue = default)
        {
            return TryGet(out XmlElement v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a NodeId value to an Variant object.
        /// </summary>
        public NodeId GetNodeId(NodeId defaultValue = default)
        {
            return TryGet(out NodeId v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a ExpandedNodeId value to an Variant object.
        /// </summary>
        public ExpandedNodeId GetExpandedNodeId(ExpandedNodeId defaultValue = default)
        {
            return TryGet(out ExpandedNodeId v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a StatusCode value to an Variant object.
        /// </summary>
        public StatusCode GetStatusCode(StatusCode defaultValue = default)
        {
            return TryGet(out StatusCode v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a QualifiedName value to an Variant object.
        /// </summary>
        public QualifiedName GetQualifiedName(QualifiedName defaultValue = default)
        {
            return TryGet(out QualifiedName v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a LocalizedText value to an Variant object.
        /// </summary>
        public LocalizedText GetLocalizedText(LocalizedText defaultValue = default)
        {
            return TryGet(out LocalizedText v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a ExtensionObject value to an Variant object.
        /// </summary>
        public ExtensionObject GetExtensionObject(ExtensionObject defaultValue = default)
        {
            return TryGet(out ExtensionObject v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a DataValue value to an Variant object.
        /// </summary>
        public DataValue GetDataValue(DataValue defaultValue = default)
        {
            return TryGet(out DataValue v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a bool[] value to an Variant object.
        /// </summary>
        public bool[] GetBooleanArray(bool[] defaultValue = default)
        {
            return TryGet(out bool[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a sbyte[] value to an Variant object.
        /// </summary>
        public sbyte[] GetSByteArray(sbyte[] defaultValue = default)
        {
            return TryGet(out sbyte[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a short[] value to an Variant object.
        /// </summary>
        public short[] GetInt16Array(short[] defaultValue = default)
        {
            return TryGet(out short[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a ushort[] value to an Variant object.
        /// </summary>
        public ushort[] GetUInt16Array(ushort[] defaultValue = default)
        {
            return TryGet(out ushort[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a int[] value to an Variant object.
        /// </summary>
        public int[] GetInt32Array(int[] defaultValue = default)
        {
            return TryGet(out int[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a uint[] value to an Variant object.
        /// </summary>
        public uint[] GetUInt32Array(uint[] defaultValue = default)
        {
            return TryGet(out uint[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a long[] value to an Variant object.
        /// </summary>
        public long[] GetInt64Array(long[] defaultValue = default)
        {
            return TryGet(out long[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a ulong[] value to an Variant object.
        /// </summary>
        public ulong[] GetUInt64Array(ulong[] defaultValue = default)
        {
            return TryGet(out ulong[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a float[] value to an Variant object.
        /// </summary>
        public float[] GetFloatArray(float[] defaultValue = default)
        {
            return TryGet(out float[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a double[] value to an Variant object.
        /// </summary>
        public double[] GetDoubleArray(double[] defaultValue = default)
        {
            return TryGet(out double[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a string []value to an Variant object.
        /// </summary>
        public string[] GetStringArray(string[] defaultValue = default)
        {
            return TryGet(out string[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a DateTime[] value to an Variant object.
        /// </summary>
        public DateTime[] GetDateTimeArray(DateTime[] defaultValue = default)
        {
            return TryGet(out DateTime[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a Uuid[] value to an Variant object.
        /// </summary>
        public Uuid[] GetGuidArray(Uuid[] defaultValue = default)
        {
            return TryGet(out Uuid[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a byte[][] value to an Variant object.
        /// </summary>
        public byte[][] GetByteStringArray(byte[][] defaultValue = default)
        {
            return TryGet(out byte[][] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a XmlElement[] value to an Variant object.
        /// </summary>
        public XmlElement[] GetXmlElementArray(XmlElement[] defaultValue = default)
        {
            return TryGet(out XmlElement[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a NodeId[] value to an Variant object.
        /// </summary>
        public NodeId[] GetNodeIdArray(NodeId[] defaultValue = default)
        {
            return TryGet(out NodeId[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a ExpandedNodeId[] value to an Variant object.
        /// </summary>
        public ExpandedNodeId[] GetExpandedNodeIdArray(ExpandedNodeId[] defaultValue = default)
        {
            return TryGet(out ExpandedNodeId[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a StatusCode[] value to an Variant object.
        /// </summary>
        public StatusCode[] GetStatusCodeArray(StatusCode[] defaultValue = default)
        {
            return TryGet(out StatusCode[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a QualifiedName[] value to an Variant object.
        /// </summary>
        public QualifiedName[] GetQualifiedNameArray(QualifiedName[] defaultValue = default)
        {
            return TryGet(out QualifiedName[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a LocalizedText[] value to an Variant object.
        /// </summary>
        public LocalizedText[] GetLocalizedTextArray(LocalizedText[] defaultValue = default)
        {
            return TryGet(out LocalizedText[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a ExtensionObject[] value to an Variant object.
        /// </summary>
        public ExtensionObject[] GetExtensionObjectArray(ExtensionObject[] defaultValue = default)
        {
            return TryGet(out ExtensionObject[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a DataValue[] value to an Variant object.
        /// </summary>
        public DataValue[] GetDataValueArray(DataValue[] defaultValue = default)
        {
            return TryGet(out DataValue[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Converts a Variant[] value to an Variant object.
        /// </summary>
        public Variant[] GetVariantArray(Variant[] defaultValue = default)
        {
            return TryGet(out Variant[] v) ? v : defaultValue;
        }

        /// <summary>
        /// Initializes the object with a <see cref="bool"/> value.
        /// </summary>
        /// <param name="value">The <see cref="bool"/> value to set
        /// this Variant to</param>
        public bool TryGet(out bool value)
        {
            return TryGetScalar(out value, BuiltInType.Boolean);
        }

        /// <summary>
        /// Initializes the object with a <see cref="sbyte"/> value.
        /// </summary>
        /// <param name="value">The <see cref="sbyte"/> value to set
        /// this Variant to</param>
        public bool TryGet(out sbyte value)
        {
            return TryGetScalar(out value, BuiltInType.SByte);
        }

        /// <summary>
        /// Initializes the object with a <see cref="byte"/> value.
        /// </summary>
        /// <param name="value">The <see cref="byte"/> value to set
        /// this Variant to</param>
        public bool TryGet(out byte value)
        {
            return TryGetScalar(out value, BuiltInType.Byte);
        }

        /// <summary>
        /// Initializes the object with a <see cref="short"/> value.
        /// </summary>
        /// <param name="value">The <see cref="short"/> value to set
        /// this Variant to</param>
        public bool TryGet(out short value)
        {
            return TryGetScalar(out value, BuiltInType.Int16);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ushort"/> value.
        /// </summary>
        /// <param name="value">The <see cref="ushort"/> value to set
        /// this Variant to</param>
        public bool TryGet(out ushort value)
        {
            return TryGetScalar(out value, BuiltInType.UInt16);
        }

        /// <summary>
        /// Initializes the object with a <see cref="int"/> value.
        /// </summary>
        /// <param name="value">The <see cref="int"/> value to set
        /// this Variant to</param>
        public bool TryGet(out int value)
        {
            return TryGetScalar(out value, BuiltInType.Int32);
        }

        /// <summary>
        /// Initializes the object with a <see cref="uint"/> value.
        /// </summary>
        /// <param name="value">The <see cref="uint"/> value to set
        /// this Variant to</param>
        public bool TryGet(out uint value)
        {
            return TryGetScalar(out value, BuiltInType.UInt32);
        }

        /// <summary>
        /// Initializes the object with a <see cref="long"/> value.
        /// </summary>
        /// <param name="value">The <see cref="long"/> value to set
        /// this Variant to</param>
        public bool TryGet(out long value)
        {
            return TryGetScalar(out value, BuiltInType.Int64);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ulong"/> value.
        /// </summary>
        /// <param name="value">The <see cref="ulong"/> value to set
        /// this Variant to</param>
        public bool TryGet(out ulong value)
        {
            return TryGetScalar(out value, BuiltInType.UInt64);
        }

        /// <summary>
        /// Initializes the object with a <see cref="float"/> value.
        /// </summary>
        /// <param name="value">The <see cref="float"/> value to set
        /// this Variant to</param>
        public bool TryGet(out float value)
        {
            return TryGetScalar(out value, BuiltInType.Float);
        }

        /// <summary>
        /// Initializes the object with a <see cref="double"/> value.
        /// </summary>
        /// <param name="value">The <see cref="double"/> value to set
        /// this Variant to</param>
        public bool TryGet(out double value)
        {
            return TryGetScalar(out value, BuiltInType.Double);
        }

        /// <summary>
        /// Initializes the object with a <see cref="string"/> value.
        /// </summary>
        /// <param name="value">The <see cref="string"/> value to set
        /// this Variant to</param>
        public bool TryGet(out string value)
        {
            return TryGetScalar(out value, BuiltInType.String);
        }

        /// <summary>
        /// Initializes the object with a <see cref="DateTime"/> value.
        /// </summary>
        /// <param name="value">The <see cref="DateTime"/> value to set
        /// this Variant to</param>
        public bool TryGet(out DateTime value)
        {
            return TryGetScalar(out value, BuiltInType.DateTime);
        }

        /// <summary>
        /// Initializes the object with a <see cref="Uuid"/> value.
        /// </summary>
        /// <param name="value">The <see cref="Uuid"/> value to set
        /// this Variant to</param>
        public bool TryGet(out Uuid value)
        {
            return TryGetScalar(out value, BuiltInType.Guid);
        }

        /// <summary>
        /// Initializes the object with a <see cref="byte"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="byte"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out byte[] value)
        {
            return TryGetScalar(out value, BuiltInType.ByteString);
        }

        /// <summary>
        /// Initializes the object with a <see cref="XmlElement"/> value.
        /// </summary>
        /// <param name="value">The <see cref="XmlElement"/> value to set
        /// this Variant to</param>
        public bool TryGet(out XmlElement value)
        {
            return TryGetScalar(out value, BuiltInType.XmlElement);
        }

        /// <summary>
        /// Initializes the object with a <see cref="NodeId"/> value.
        /// </summary>
        /// <param name="value">The <see cref="NodeId"/> value to set
        /// this Variant to</param>
        public bool TryGet(out NodeId value)
        {
            return TryGetScalar(out value, BuiltInType.NodeId);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ExpandedNodeId"/> value.
        /// </summary>
        /// <param name="value">The <see cref="ExpandedNodeId"/> value to
        /// set this Variant to</param>
        public bool TryGet(out ExpandedNodeId value)
        {
            return TryGetScalar(out value, BuiltInType.ExpandedNodeId);
        }

        /// <summary>
        /// Initializes the object with a <see cref="StatusCode"/> value.
        /// </summary>
        /// <param name="value">The <see cref="StatusCode"/> value to set
        /// this Variant to</param>
        public bool TryGet(out StatusCode value)
        {
            if (TryGetScalar(out value, BuiltInType.StatusCode))
            {
                return true;
            }
            if (TryGetScalar(out uint uintValue, BuiltInType.UInt32))
            {
                value = new StatusCode(uintValue);
                return true;
            }
            return false;
        }

        /// <summary>
        /// Initializes the object with a <see cref="QualifiedName"/> value.
        /// </summary>
        /// <param name="value">The <see cref="QualifiedName"/> value to set
        /// this Variant to</param>
        public bool TryGet(out QualifiedName value)
        {
            return TryGetScalar(out value, BuiltInType.QualifiedName);
        }

        /// <summary>
        /// Initializes the object with a <see cref="LocalizedText"/> value.
        /// </summary>
        /// <param name="value">The <see cref="LocalizedText"/> value to set
        /// this Variant to</param>
        public bool TryGet(out LocalizedText value)
        {
            return TryGetScalar(out value, BuiltInType.LocalizedText);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ExtensionObject"/> value.
        /// </summary>
        /// <param name="value">The <see cref="ExtensionObject"/> value to set
        /// this Variant to</param>
        public bool TryGet(out ExtensionObject value)
        {
            return TryGetScalar(out value, BuiltInType.ExtensionObject);
        }

        /// <summary>
        /// Initializes the object with a <see cref="DataValue"/> value.
        /// </summary>
        /// <param name="value">The <see cref="DataValue"/> value to set
        /// this Variant to</param>
        public bool TryGet(out DataValue value)
        {
            return TryGetScalar(out value, BuiltInType.DataValue);
        }

        /// <summary>
        /// Initializes the object with a <see cref="bool"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="bool"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out bool[] value)
        {
            return TryGetArray(out value, BuiltInType.Boolean);
        }

        /// <summary>
        /// Initializes the object with a <see cref="sbyte"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="sbyte"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out sbyte[] value)
        {
            return TryGetArray(out value, BuiltInType.SByte);
        }

        /// <summary>
        /// Initializes the object with a <see cref="short"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="short"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out short[] value)
        {
            return TryGetArray(out value, BuiltInType.Int16);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ushort"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="ushort"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out ushort[] value)
        {
            return TryGetArray(out value, BuiltInType.UInt16);
        }

        /// <summary>
        /// Initializes the object with a <see cref="int"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="int"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out int[] value)
        {
            return TryGetArray(out value, BuiltInType.Int32);
        }

        /// <summary>
        /// Initializes the object with a <see cref="uint"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="uint"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out uint[] value)
        {
            return TryGetArray(out value, BuiltInType.UInt32);
        }

        /// <summary>
        /// Initializes the object with a <see cref="long"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="long"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out long[] value)
        {
            return TryGetArray(out value, BuiltInType.Int64);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ulong"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="ulong"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out ulong[] value)
        {
            return TryGetArray(out value, BuiltInType.UInt64);
        }

        /// <summary>
        /// Initializes the object with a <see cref="float"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="float"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out float[] value)
        {
            return TryGetArray(out value, BuiltInType.Float);
        }

        /// <summary>
        /// Initializes the object with a <see cref="double"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="double"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out double[] value)
        {
            return TryGetArray(out value, BuiltInType.Double);
        }

        /// <summary>
        /// Initializes the object with a <see cref="string"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="string"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out string[] value)
        {
            return TryGetArray(out value, BuiltInType.String);
        }

        /// <summary>
        /// Initializes the object with a <see cref="DateTime"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="DateTime"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out DateTime[] value)
        {
            return TryGetArray(out value, BuiltInType.DateTime);
        }

        /// <summary>
        /// Initializes the object with a <see cref="Uuid"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="Uuid"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out Uuid[] value)
        {
            return TryGetArray(out value, BuiltInType.Guid);
        }

        /// <summary>
        /// Initializes the object with a 2-d <see cref="byte"/>-array value.
        /// </summary>
        /// <param name="value">The 2-d <see cref="byte"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out byte[][] value)
        {
            return TryGetArray(out value, BuiltInType.ByteString);
        }

        /// <summary>
        /// Initializes the object with a <see cref="XmlElement"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="XmlElement"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out XmlElement[] value)
        {
            return TryGetArray(out value, BuiltInType.XmlElement);
        }

        /// <summary>
        /// Initializes the object with a <see cref="NodeId"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="NodeId"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out NodeId[] value)
        {
            return TryGetArray(out value, BuiltInType.NodeId);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ExpandedNodeId"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="ExpandedNodeId"/>-array value to
        /// set this Variant to</param>
        public bool TryGet(out ExpandedNodeId[] value)
        {
            return TryGetArray(out value, BuiltInType.ExpandedNodeId);
        }

        /// <summary>
        /// Initializes the object with a <see cref="StatusCode"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="StatusCode"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out StatusCode[] value)
        {
            return TryGetArray(out value, BuiltInType.StatusCode);
        }

        /// <summary>
        /// Initializes the object with a <see cref="QualifiedName"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="QualifiedName"/>-array value to
        /// set this Variant to</param>
        public bool TryGet(out QualifiedName[] value)
        {
            return TryGetArray(out value, BuiltInType.QualifiedName);
        }

        /// <summary>
        /// Initializes the object with a <see cref="LocalizedText"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="LocalizedText"/>-array value to
        /// set this Variant to</param>
        public bool TryGet(out LocalizedText[] value)
        {
            return TryGetArray(out value, BuiltInType.LocalizedText);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ExtensionObject"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="ExtensionObject"/>-array value to
        /// set this Variant to</param>
        public bool TryGet(out ExtensionObject[] value)
        {
            return TryGetArray(out value, BuiltInType.ExtensionObject);
        }

        /// <summary>
        /// Initializes the object with a <see cref="DataValue"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="DataValue"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out DataValue[] value)
        {
            return TryGetArray(out value, BuiltInType.DataValue);
        }

        /// <summary>
        /// Initializes the object with a <see cref="Variant"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="Variant"/>-array value to set
        /// this Variant to</param>
        public bool TryGet(out Variant[] value)
        {
            return TryGetArray(out value, BuiltInType.Variant);
        }

        /// <summary>
        /// Try get array of specified type.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        public bool TryGetArray<T>(out T[] value, BuiltInType expectedType)
        {
            if (m_value == null ||
                TypeInfo.BuiltInType != expectedType ||
                TypeInfo.ValueRank < 0)
            {
                value = default;
                return false;
            }
            if (m_value is T[] variable)
            {
                value = variable;
                return true;
            }
            if (m_value is not Array array)
            {
                //if (m_value is not Matrix matrix ||
                //    expectedType != matrix.TypeInfo.BuiltInType)
                //{
                    value = default;
                    return false;
                // }
                // array = matrix.Elements;
            }
            try
            {
                value = (T[])Array.CreateInstance(typeof(T), array.Length);
                for (int ii = 0; ii < array.Length; ii++)
                {
                    value[ii] = (T)Convert.ChangeType(
                        array.GetValue(ii),
                        typeof(T),
                        CultureInfo.InvariantCulture);
                }
                return true;
            }
            catch
            {
                value = default;
                return false;
            }
        }

        /// <summary>
        /// Try get scalar value
        /// </summary>
        /// <typeparam name="T"></typeparam>
        public bool TryGetScalar<T>(out T value, BuiltInType expectedType)
        {
            if (m_value == null ||
                TypeInfo.BuiltInType != expectedType ||
                TypeInfo.ValueRank >= 0)
            {
                value = default;
                return false;
            }
            if (m_value is T variable)
            {
                value = variable;
                return true;
            }
            try
            {
                value = (T)Convert.ChangeType(m_value, typeof(T), CultureInfo.InvariantCulture);
                return true;
            }
            catch
            {
                value = default;
                return false;
            }
        }

        /// <summary>
        /// Try get matrix of type
        /// </summary>
        /// <typeparam name="T"></typeparam>
        public bool TryGetMatrix<T>(out Matrix matrix, BuiltInType expectedType)
        {
            if (m_value is Matrix mat && mat.TypeInfo.BuiltInType == expectedType)
            {
                matrix = mat;
                return true;
            }

            if (TryGetArray<T>(out T[] array, expectedType))
            {
                matrix = new Matrix(array, TypeInfo.BuiltInType);
                return true;
            }

            matrix = null;
            return false;
        }

        /// <summary>
        /// Initializes the object with a <see cref="bool"/> value.
        /// </summary>
        /// <param name="value">The <see cref="bool"/> value to set
        /// this Variant to</param>
        public static Variant From(bool value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="sbyte"/> value.
        /// </summary>
        /// <param name="value">The <see cref="sbyte"/> value to set
        /// this Variant to</param>
        public static Variant From(sbyte value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="byte"/> value.
        /// </summary>
        /// <param name="value">The <see cref="byte"/> value to set
        /// this Variant to</param>
        public static Variant From(byte value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="short"/> value.
        /// </summary>
        /// <param name="value">The <see cref="short"/> value to set
        /// this Variant to</param>
        public static Variant From(short value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ushort"/> value.
        /// </summary>
        /// <param name="value">The <see cref="ushort"/> value to set
        /// this Variant to</param>
        public static Variant From(ushort value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="int"/> value.
        /// </summary>
        /// <param name="value">The <see cref="int"/> value to set
        /// this Variant to</param>
        public static Variant From(int value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="uint"/> value.
        /// </summary>
        /// <param name="value">The <see cref="uint"/> value to set
        /// this Variant to</param>
        public static Variant From(uint value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="long"/> value.
        /// </summary>
        /// <param name="value">The <see cref="long"/> value to set
        /// this Variant to</param>
        public static Variant From(long value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ulong"/> value.
        /// </summary>
        /// <param name="value">The <see cref="ulong"/> value to set
        /// this Variant to</param>
        public static Variant From(ulong value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="float"/> value.
        /// </summary>
        /// <param name="value">The <see cref="float"/> value to set
        /// this Variant to</param>
        public static Variant From(float value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="double"/> value.
        /// </summary>
        /// <param name="value">The <see cref="double"/> value to set
        /// this Variant to</param>
        public static Variant From(double value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="string"/> value.
        /// </summary>
        /// <param name="value">The <see cref="string"/> value to set
        /// this Variant to</param>
        public static Variant From(string value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="DateTime"/> value.
        /// </summary>
        /// <param name="value">The <see cref="DateTime"/> value to set
        /// this Variant to</param>
        public static Variant From(DateTime value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="Uuid"/> value.
        /// </summary>
        /// <param name="value">The <see cref="Uuid"/> value to set
        /// this Variant to</param>
        public static Variant From(Uuid value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="byte"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="byte"/>-array value to set
        /// this Variant to</param>
        public static Variant From(byte[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="XmlElement"/> value.
        /// </summary>
        /// <param name="value">The <see cref="XmlElement"/> value to set
        /// this Variant to</param>
        public static Variant From(XmlElement value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="NodeId"/> value.
        /// </summary>
        /// <param name="value">The <see cref="NodeId"/> value to set
        /// this Variant to</param>
        public static Variant From(NodeId value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ExpandedNodeId"/> value.
        /// </summary>
        /// <param name="value">The <see cref="ExpandedNodeId"/> value to
        /// set this Variant to</param>
        public static Variant From(ExpandedNodeId value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="StatusCode"/> value.
        /// </summary>
        /// <param name="value">The <see cref="StatusCode"/> value to set
        /// this Variant to</param>
        public static Variant From(StatusCode value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="QualifiedName"/> value.
        /// </summary>
        /// <param name="value">The <see cref="QualifiedName"/> value to set
        /// this Variant to</param>
        public static Variant From(QualifiedName value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="LocalizedText"/> value.
        /// </summary>
        /// <param name="value">The <see cref="LocalizedText"/> value to set
        /// this Variant to</param>
        public static Variant From(LocalizedText value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ExtensionObject"/> value.
        /// </summary>
        /// <param name="value">The <see cref="ExtensionObject"/> value to set
        /// this Variant to</param>
        public static Variant From(ExtensionObject value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="DataValue"/> value.
        /// </summary>
        /// <param name="value">The <see cref="DataValue"/> value to set
        /// this Variant to</param>
        public static Variant From(DataValue value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="bool"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="bool"/>-array value to set
        /// this Variant to</param>
        public static Variant From(bool[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="sbyte"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="sbyte"/>-array value to set
        /// this Variant to</param>
        public static Variant From(sbyte[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="short"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="short"/>-array value to set
        /// this Variant to</param>
        public static Variant From(short[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ushort"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="ushort"/>-array value to set
        /// this Variant to</param>
        public static Variant From(ushort[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="int"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="int"/>-array value to set
        /// this Variant to</param>
        public static Variant From(int[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="uint"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="uint"/>-array value to set
        /// this Variant to</param>
        public static Variant From(uint[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="long"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="long"/>-array value to set
        /// this Variant to</param>
        public static Variant From(long[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ulong"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="ulong"/>-array value to set
        /// this Variant to</param>
        public static Variant From(ulong[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="float"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="float"/>-array value to set
        /// this Variant to</param>
        public static Variant From(float[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="double"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="double"/>-array value to set
        /// this Variant to</param>
        public static Variant From(double[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="string"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="string"/>-array value to set
        /// this Variant to</param>
        public static Variant From(string[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="DateTime"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="DateTime"/>-array value to set
        /// this Variant to</param>
        public static Variant From(DateTime[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="Uuid"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="Uuid"/>-array value to set
        /// this Variant to</param>
        public static Variant From(Uuid[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a 2-d <see cref="byte"/>-array value.
        /// </summary>
        /// <param name="value">The 2-d <see cref="byte"/>-array value to set
        /// this Variant to</param>
        public static Variant From(byte[][] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="XmlElement"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="XmlElement"/>-array value to set
        /// this Variant to</param>
        public static Variant From(XmlElement[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="NodeId"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="NodeId"/>-array value to set
        /// this Variant to</param>
        public static Variant From(NodeId[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ExpandedNodeId"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="ExpandedNodeId"/>-array value to
        /// set this Variant to</param>
        public static Variant From(ExpandedNodeId[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="StatusCode"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="StatusCode"/>-array value to set
        /// this Variant to</param>
        public static Variant From(StatusCode[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="QualifiedName"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="QualifiedName"/>-array value to
        /// set this Variant to</param>
        public static Variant From(QualifiedName[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="LocalizedText"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="LocalizedText"/>-array value to
        /// set this Variant to</param>
        public static Variant From(LocalizedText[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="ExtensionObject"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="ExtensionObject"/>-array value to
        /// set this Variant to</param>
        public static Variant From(ExtensionObject[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="DataValue"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="DataValue"/>-array value to set
        /// this Variant to</param>
        public static Variant From(DataValue[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with a <see cref="Variant"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="Variant"/>-array value to set
        /// this Variant to</param>
        public static Variant From(Variant[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Initializes the object with an <see cref="object"/>-array value.
        /// </summary>
        /// <param name="value">The <see cref="object"/>-array value to set
        /// this Variant to</param>
        public static Variant From(object[] value)
        {
            return new Variant(value);
        }

        /// <summary>
        /// Converts a bool value to an Variant object.
        /// </summary>
        public static implicit operator Variant(bool value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a sbyte value to an Variant object.
        /// </summary>
        public static implicit operator Variant(sbyte value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a byte value to an Variant object.
        /// </summary>
        public static implicit operator Variant(byte value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a short value to an Variant object.
        /// </summary>
        public static implicit operator Variant(short value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a ushort value to an Variant object.
        /// </summary>
        public static implicit operator Variant(ushort value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a int value to an Variant object.
        /// </summary>
        public static implicit operator Variant(int value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a uint value to an Variant object.
        /// </summary>
        public static implicit operator Variant(uint value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a long value to an Variant object.
        /// </summary>
        public static implicit operator Variant(long value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a ulong value to an Variant object.
        /// </summary>
        public static implicit operator Variant(ulong value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a float value to an Variant object.
        /// </summary>
        public static implicit operator Variant(float value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a double value to an Variant object.
        /// </summary>
        public static implicit operator Variant(double value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a string value to an Variant object.
        /// </summary>
        public static implicit operator Variant(string value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a DateTime value to an Variant object.
        /// </summary>
        public static implicit operator Variant(DateTime value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a Uuid value to an Variant object.
        /// </summary>
        public static implicit operator Variant(Uuid value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a byte[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(byte[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a XmlElement value to an Variant object.
        /// </summary>
        public static implicit operator Variant(XmlElement value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a NodeId value to an Variant object.
        /// </summary>
        public static implicit operator Variant(NodeId value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a ExpandedNodeId value to an Variant object.
        /// </summary>
        public static implicit operator Variant(ExpandedNodeId value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a StatusCode value to an Variant object.
        /// </summary>
        public static implicit operator Variant(StatusCode value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a QualifiedName value to an Variant object.
        /// </summary>
        public static implicit operator Variant(QualifiedName value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a LocalizedText value to an Variant object.
        /// </summary>
        public static implicit operator Variant(LocalizedText value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a ExtensionObject value to an Variant object.
        /// </summary>
        public static implicit operator Variant(ExtensionObject value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a DataValue value to an Variant object.
        /// </summary>
        public static implicit operator Variant(DataValue value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a bool[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(bool[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a sbyte[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(sbyte[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a short[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(short[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a ushort[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(ushort[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a int[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(int[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a uint[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(uint[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a long[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(long[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a ulong[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(ulong[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a float[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(float[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a double[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(double[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a string []value to an Variant object.
        /// </summary>
        public static implicit operator Variant(string[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a DateTime[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(DateTime[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a Uuid[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(Uuid[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a byte[][] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(byte[][] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a XmlElement[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(XmlElement[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a NodeId[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(NodeId[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a ExpandedNodeId[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(ExpandedNodeId[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a StatusCode[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(StatusCode[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a QualifiedName[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(QualifiedName[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a LocalizedText[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(LocalizedText[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a ExtensionObject[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(ExtensionObject[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a DataValue[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(DataValue[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a Variant[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(Variant[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts an object[] value to an Variant object.
        /// </summary>
        public static implicit operator Variant(object[] value)
        {
            return From(value);
        }

        /// <summary>
        /// Converts a bool value to an Variant object.
        /// </summary>
        public static explicit operator bool(Variant value)
        {
            return value.TryGet(out bool v) ? v : throw CannotCast<bool>();
        }

        /// <summary>
        /// Converts a sbyte value to an Variant object.
        /// </summary>
        public static explicit operator sbyte(Variant value)
        {
            return value.TryGet(out sbyte v) ? v : throw CannotCast<sbyte>();
        }

        /// <summary>
        /// Converts a byte value to an Variant object.
        /// </summary>
        public static explicit operator byte(Variant value)
        {
            return value.TryGet(out byte v) ? v : throw CannotCast<byte>();
        }

        /// <summary>
        /// Converts a short value to an Variant object.
        /// </summary>
        public static explicit operator short(Variant value)
        {
            return value.TryGet(out short v) ? v : throw CannotCast<short>();
        }

        /// <summary>
        /// Converts a ushort value to an Variant object.
        /// </summary>
        public static explicit operator ushort(Variant value)
        {
            return value.TryGet(out ushort v) ? v : throw CannotCast<ushort>();
        }

        /// <summary>
        /// Converts a int value to an Variant object.
        /// </summary>
        public static explicit operator int(Variant value)
        {
            return value.TryGet(out int v) ? v : throw CannotCast<int>();
        }

        /// <summary>
        /// Converts a uint value to an Variant object.
        /// </summary>
        public static explicit operator uint(Variant value)
        {
            return value.TryGet(out uint v) ? v : throw CannotCast<uint>();
        }

        /// <summary>
        /// Converts a long value to an Variant object.
        /// </summary>
        public static explicit operator long(Variant value)
        {
            return value.TryGet(out long v) ? v : throw CannotCast<long>();
        }

        /// <summary>
        /// Converts a ulong value to an Variant object.
        /// </summary>
        public static explicit operator ulong(Variant value)
        {
            return value.TryGet(out ulong v) ? v : throw CannotCast<ulong>();
        }

        /// <summary>
        /// Converts a float value to an Variant object.
        /// </summary>
        public static explicit operator float(Variant value)
        {
            return value.TryGet(out float v) ? v : throw CannotCast<float>();
        }

        /// <summary>
        /// Converts a double value to an Variant object.
        /// </summary>
        public static explicit operator double(Variant value)
        {
            return value.TryGet(out double v) ? v : throw CannotCast<double>();
        }

        /// <summary>
        /// Converts a string value to an Variant object.
        /// </summary>
        public static explicit operator string(Variant value)
        {
            return value.TryGet(out string v) ? v : throw CannotCast<string>();
        }

        /// <summary>
        /// Converts a DateTime value to an Variant object.
        /// </summary>
        public static explicit operator DateTime(Variant value)
        {
            return value.TryGet(out DateTime v) ? v : throw CannotCast<DateTime>();
        }

        /// <summary>
        /// Converts a Uuid value to an Variant object.
        /// </summary>
        public static explicit operator Uuid(Variant value)
        {
            return value.TryGet(out Uuid v) ? v : throw CannotCast<Uuid>();
        }

        /// <summary>
        /// Converts a byte[] value to an Variant object.
        /// </summary>
        public static explicit operator byte[](Variant value)
        {
            return value.TryGet(out byte[] v) ? v : throw CannotCast<byte[]>();
        }

        /// <summary>
        /// Converts a XmlElement value to an Variant object.
        /// </summary>
        public static explicit operator XmlElement(Variant value)
        {
            return value.TryGet(out XmlElement v) ? v : throw CannotCast<XmlElement>();
        }

        /// <summary>
        /// Converts a NodeId value to an Variant object.
        /// </summary>
        public static explicit operator NodeId(Variant value)
        {
            return value.TryGet(out NodeId v) ? v : throw CannotCast<NodeId>();
        }

        /// <summary>
        /// Converts a ExpandedNodeId value to an Variant object.
        /// </summary>
        public static explicit operator ExpandedNodeId(Variant value)
        {
            return value.TryGet(out ExpandedNodeId v) ? v : throw CannotCast<ExpandedNodeId>();
        }

        /// <summary>
        /// Converts a StatusCode value to an Variant object.
        /// </summary>
        public static explicit operator StatusCode(Variant value)
        {
            return value.TryGet(out StatusCode v) ? v : throw CannotCast<StatusCode>();
        }

        /// <summary>
        /// Converts a QualifiedName value to an Variant object.
        /// </summary>
        public static explicit operator QualifiedName(Variant value)
        {
            return value.TryGet(out QualifiedName v) ? v : throw CannotCast<QualifiedName>();
        }

        /// <summary>
        /// Converts a LocalizedText value to an Variant object.
        /// </summary>
        public static explicit operator LocalizedText(Variant value)
        {
            return value.TryGet(out LocalizedText v) ? v : throw CannotCast<LocalizedText>();
        }

        /// <summary>
        /// Converts a ExtensionObject value to an Variant object.
        /// </summary>
        public static explicit operator ExtensionObject(Variant value)
        {
            return value.TryGet(out ExtensionObject v) ? v : throw CannotCast<ExtensionObject>();
        }

        /// <summary>
        /// Converts a DataValue value to an Variant object.
        /// </summary>
        public static explicit operator DataValue(Variant value)
        {
            return value.TryGet(out DataValue v) ? v : throw CannotCast<DataValue>();
        }

        /// <summary>
        /// Converts a bool[] value to an Variant object.
        /// </summary>
        public static explicit operator bool[](Variant value)
        {
            return value.TryGet(out bool[] v) ? v : throw CannotCast<bool[]>();
        }

        /// <summary>
        /// Converts a sbyte[] value to an Variant object.
        /// </summary>
        public static explicit operator sbyte[](Variant value)
        {
            return value.TryGet(out sbyte[] v) ? v : throw CannotCast<sbyte[]>();
        }

        /// <summary>
        /// Converts a short[] value to an Variant object.
        /// </summary>
        public static explicit operator short[](Variant value)
        {
            return value.TryGet(out short[] v) ? v : throw CannotCast<short[]>();
        }

        /// <summary>
        /// Converts a ushort[] value to an Variant object.
        /// </summary>
        public static explicit operator ushort[](Variant value)
        {
            return value.TryGet(out ushort[] v) ? v : throw CannotCast<ushort[]>();
        }

        /// <summary>
        /// Converts a int[] value to an Variant object.
        /// </summary>
        public static explicit operator int[](Variant value)
        {
            return value.TryGet(out int[] v) ? v : throw CannotCast<int[]>();
        }

        /// <summary>
        /// Converts a uint[] value to an Variant object.
        /// </summary>
        public static explicit operator uint[](Variant value)
        {
            return value.TryGet(out uint[] v) ? v : throw CannotCast<uint[]>();
        }

        /// <summary>
        /// Converts a long[] value to an Variant object.
        /// </summary>
        public static explicit operator long[](Variant value)
        {
            return value.TryGet(out long[] v) ? v : throw CannotCast<long[]>();
        }

        /// <summary>
        /// Converts a ulong[] value to an Variant object.
        /// </summary>
        public static explicit operator ulong[](Variant value)
        {
            return value.TryGet(out ulong[] v) ? v : throw CannotCast<ulong[]>();
        }

        /// <summary>
        /// Converts a float[] value to an Variant object.
        /// </summary>
        public static explicit operator float[](Variant value)
        {
            return value.TryGet(out float[] v) ? v : throw CannotCast<float[]>();
        }

        /// <summary>
        /// Converts a double[] value to an Variant object.
        /// </summary>
        public static explicit operator double[](Variant value)
        {
            return value.TryGet(out double[] v) ? v : throw CannotCast<double[]>();
        }

        /// <summary>
        /// Converts a string []value to an Variant object.
        /// </summary>
        public static explicit operator string[](Variant value)
        {
            return value.TryGet(out string[] v) ? v : throw CannotCast<string[]>();
        }

        /// <summary>
        /// Converts a DateTime[] value to an Variant object.
        /// </summary>
        public static explicit operator DateTime[](Variant value)
        {
            return value.TryGet(out DateTime[] v) ? v : throw CannotCast<DateTime[]>();
        }

        /// <summary>
        /// Converts a Uuid[] value to an Variant object.
        /// </summary>
        public static explicit operator Uuid[](Variant value)
        {
            return value.TryGet(out Uuid[] v) ? v : throw CannotCast<Uuid[]>();
        }

        /// <summary>
        /// Converts a byte[][] value to an Variant object.
        /// </summary>
        public static explicit operator byte[][](Variant value)
        {
            return value.TryGet(out byte[][] v) ? v : throw CannotCast<byte[][]>();
        }

        /// <summary>
        /// Converts a XmlElement[] value to an Variant object.
        /// </summary>
        public static explicit operator XmlElement[](Variant value)
        {
            return value.TryGet(out XmlElement[] v) ? v : throw CannotCast<XmlElement[]>();
        }

        /// <summary>
        /// Converts a NodeId[] value to an Variant object.
        /// </summary>
        public static explicit operator NodeId[](Variant value)
        {
            return value.TryGet(out NodeId[] v) ? v : throw CannotCast<NodeId[]>();
        }

        /// <summary>
        /// Converts a ExpandedNodeId[] value to an Variant object.
        /// </summary>
        public static explicit operator ExpandedNodeId[](Variant value)
        {
            return value.TryGet(out ExpandedNodeId[] v) ? v : throw CannotCast<ExpandedNodeId[]>();
        }

        /// <summary>
        /// Converts a StatusCode[] value to an Variant object.
        /// </summary>
        public static explicit operator StatusCode[](Variant value)
        {
            return value.TryGet(out StatusCode[] v) ? v : throw CannotCast<StatusCode[]>();
        }

        /// <summary>
        /// Converts a QualifiedName[] value to an Variant object.
        /// </summary>
        public static explicit operator QualifiedName[](Variant value)
        {
            return value.TryGet(out QualifiedName[] v) ? v : throw CannotCast<QualifiedName[]>();
        }

        /// <summary>
        /// Converts a LocalizedText[] value to an Variant object.
        /// </summary>
        public static explicit operator LocalizedText[](Variant value)
        {
            return value.TryGet(out LocalizedText[] v) ? v : throw CannotCast<LocalizedText[]>();
        }

        /// <summary>
        /// Converts a ExtensionObject[] value to an Variant object.
        /// </summary>
        public static explicit operator ExtensionObject[](Variant value)
        {
            return value.TryGet(out ExtensionObject[] v) ? v : throw CannotCast<ExtensionObject[]>();
        }

        /// <summary>
        /// Converts a DataValue[] value to an Variant object.
        /// </summary>
        public static explicit operator DataValue[](Variant value)
        {
            return value.TryGet(out DataValue[] v) ? v : throw CannotCast<DataValue[]>();
        }

        /// <summary>
        /// Converts a Variant[] value to an Variant object.
        /// </summary>
        public static explicit operator Variant[](Variant value)
        {
            return value.TryGet(out Variant[] v) ? v : throw CannotCast<Variant[]>();
        }

        /// <inheritdoc/>
        public bool Equals(bool value)
        {
            return TryGet(out bool v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(sbyte value)
        {
            return TryGet(out sbyte v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(byte value)
        {
            return TryGet(out byte v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(short value)
        {
            return TryGet(out short v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(ushort value)
        {
            return TryGet(out ushort v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(int value)
        {
            return TryGet(out int v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(uint value)
        {
            return TryGet(out uint v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(long value)
        {
            return TryGet(out long v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(ulong value)
        {
            return TryGet(out ulong v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(float value)
        {
            return TryGet(out float v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(double value)
        {
            return TryGet(out double v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(string value)
        {
            return TryGet(out string v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(DateTime value)
        {
            return TryGet(out DateTime v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(Uuid value)
        {
            return TryGet(out Uuid v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(byte[] value)
        {
            return TryGet(out byte[] v) && SequenceEqualityComparer<byte>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(XmlElement value)
        {
            return TryGet(out XmlElement v) && XmlElementStringEqualityComparer.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(NodeId value)
        {
            return TryGet(out NodeId v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(ExpandedNodeId value)
        {
            return TryGet(out ExpandedNodeId v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(StatusCode value)
        {
            return TryGet(out StatusCode v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(QualifiedName value)
        {
            return TryGet(out QualifiedName v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(LocalizedText value)
        {
            return TryGet(out LocalizedText v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(ExtensionObject value)
        {
            return TryGet(out ExtensionObject v) && CoreUtils.IsEqual(v.Body, value.Body);
        }

        /// <inheritdoc/>
        public bool Equals(DataValue value)
        {
            return TryGet(out DataValue v) && v == value;
        }

        /// <inheritdoc/>
        public bool Equals(bool[] value)
        {
            return TryGet(out bool[] v) &&
                SequenceEqualityComparer<bool>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(sbyte[] value)
        {
            return TryGet(out sbyte[] v) &&
                SequenceEqualityComparer<sbyte>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(short[] value)
        {
            return TryGet(out short[] v) &&
                SequenceEqualityComparer<short>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(ushort[] value)
        {
            return TryGet(out ushort[] v) &&
                SequenceEqualityComparer<ushort>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(int[] value)
        {
            return TryGet(out int[] v) &&
                SequenceEqualityComparer<int>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(uint[] value)
        {
            return TryGet(out uint[] v) &&
                SequenceEqualityComparer<uint>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(long[] value)
        {
            return TryGet(out long[] v) &&
                SequenceEqualityComparer<long>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(ulong[] value)
        {
            return TryGet(out ulong[] v) &&
                SequenceEqualityComparer<ulong>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(float[] value)
        {
            return TryGet(out float[] v) &&
                SequenceEqualityComparer<float>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(double[] value)
        {
            return TryGet(out double[] v) &&
                SequenceEqualityComparer<double>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(string[] value)
        {
            return TryGet(out string[] v) &&
                ArrayEqualityComparer<string>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(DateTime[] value)
        {
            return TryGet(out DateTime[] v) &&
                SequenceEqualityComparer<DateTime>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(Uuid[] value)
        {
            return TryGet(out Uuid[] v) &&
                SequenceEqualityComparer<Uuid>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(byte[][] value)
        {
            return TryGet(out byte[][] v) &&
                ByteStringArrayEqualityComparer.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(XmlElement[] value)
        {
            return TryGet(out XmlElement[] v) &&
                XmlElementArrayStringEqualityComparer.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(NodeId[] value)
        {
            return TryGet(out NodeId[] v) &&
                ArrayEqualityComparer<NodeId>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(ExpandedNodeId[] value)
        {
            return TryGet(out ExpandedNodeId[] v) &&
                ArrayEqualityComparer<ExpandedNodeId>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(StatusCode[] value)
        {
            return TryGet(out StatusCode[] v) &&
                ArrayEqualityComparer<StatusCode>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(QualifiedName[] value)
        {
            return TryGet(out QualifiedName[] v) &&
                ArrayEqualityComparer<QualifiedName>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(LocalizedText[] value)
        {
            return TryGet(out LocalizedText[] v) &&
                ArrayEqualityComparer<LocalizedText>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(ExtensionObject[] value)
        {
            return TryGet(out ExtensionObject[] v) &&
                ArrayEqualityComparer<ExtensionObject>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(DataValue[] value)
        {
            return TryGet(out DataValue[] v) &&
                ArrayEqualityComparer<DataValue>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public bool Equals(Variant[] value)
        {
            return TryGet(out Variant[] v) &&
                ArrayEqualityComparer<Variant>.Default.Equals(v, value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, Variant b)
        {
            return a.Equals(b);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, Variant b)
        {
            return !a.Equals(b);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, bool value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, bool value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, sbyte value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, sbyte value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, byte value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, byte value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, short value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, short value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, ushort value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, ushort value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, int value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, int value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, uint value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, uint value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, long value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, long value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, ulong value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, ulong value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, float value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, float value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, double value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, double value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, string value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, string value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, DateTime value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, DateTime value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, Uuid value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, Uuid value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, byte[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, byte[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, XmlElement value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, XmlElement value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, NodeId value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, NodeId value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, ExpandedNodeId value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, ExpandedNodeId value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, StatusCode value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, StatusCode value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, QualifiedName value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, QualifiedName value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, LocalizedText value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, LocalizedText value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, ExtensionObject value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, ExtensionObject value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, DataValue value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, DataValue value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, bool[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, bool[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, sbyte[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, sbyte[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, short[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, short[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, ushort[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, ushort[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, int[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, int[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, uint[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, uint[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, long[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, long[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, ulong[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, ulong[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, float[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, float[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, double[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, double[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, string[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, string[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, DateTime[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, DateTime[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, Uuid[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, Uuid[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, byte[][] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, byte[][] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, XmlElement[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, XmlElement[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, NodeId[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, NodeId[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, ExpandedNodeId[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, ExpandedNodeId[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, StatusCode[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, StatusCode[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, QualifiedName[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, QualifiedName[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, LocalizedText[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, LocalizedText[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, ExtensionObject[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, ExtensionObject[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, DataValue[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, DataValue[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator ==(Variant a, Variant[] value)
        {
            return a.Equals(value);
        }

        /// <inheritdoc/>
        public static bool operator !=(Variant a, Variant[] value)
        {
            return !a.Equals(value);
        }

        /// <inheritdoc/>
        public bool Equals(Variant other)
        {
            if (IsNull && other.IsNull)
            {
                return true;
            }
            if (TypeInfo.IsUnknown || other.TypeInfo.IsUnknown)
            {
                return TypeInfo.IsUnknown == other.TypeInfo.IsUnknown;
            }
            if (TypeInfo.ValueRank != other.TypeInfo.ValueRank)
            {
                return false;
            }
            if (TypeInfo.BuiltInType != other.TypeInfo.BuiltInType)
            {
                return false;
            }
            return Equals(other.Value); // TODO: No more Value use
        }

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            return obj switch
            {
                null => IsNull,
                Variant v => Equals(v),
                bool v => Equals(v),
                sbyte v => Equals(v),
                byte v => Equals(v),
                short v => Equals(v),
                ushort v => Equals(v),
                int v => Equals(v),
                uint v => Equals(v),
                long v => Equals(v),
                ulong v => Equals(v),
                float v => Equals(v),
                double v => Equals(v),
                string v => Equals(v),
                DateTime v => Equals(v),
                Uuid v => Equals(v),
                byte[] v => Equals(v),
                XmlElement v => Equals(v),
                NodeId v => Equals(v),
                ExpandedNodeId v => Equals(v),
                StatusCode v => Equals(v),
                QualifiedName v => Equals(v),
                LocalizedText v => Equals(v),
                ExtensionObject v => Equals(v),
                DataValue v => Equals(v),
                bool[] v => Equals(v),
                sbyte[] v => Equals(v),
                short[] v => Equals(v),
                ushort[] v => Equals(v),
                int[] v => Equals(v),
                uint[] v => Equals(v),
                long[] v => Equals(v),
                ulong[] v => Equals(v),
                float[] v => Equals(v),
                double[] v => Equals(v),
                string[] v => Equals(v),
                DateTime[] v => Equals(v),
                Uuid[] v => Equals(v),
                byte[][] v => Equals(v),
                XmlElement[] v => Equals(v),
                NodeId[] v => Equals(v),
                ExpandedNodeId[] v => Equals(v),
                StatusCode[] v => Equals(v),
                QualifiedName[] v => Equals(v),
                LocalizedText[] v => Equals(v),
                ExtensionObject[] v => Equals(v),
                DataValue[] v => Equals(v),
                Variant[] v => Equals(v),
                _ => CoreUtils.IsEqual(m_value, obj)
            };
        }

        /// <summary>
        /// Append a ByteString as a hex string.
        /// </summary>
        private static void AppendByteString(
            StringBuilder buffer,
            byte[] bytes,
            IFormatProvider formatProvider)
        {
            if (bytes != null)
            {
                for (int ii = 0; ii < bytes.Length; ii++)
                {
                    buffer.AppendFormat(formatProvider, "{0:X2}", bytes[ii]);
                }
            }
            else
            {
                buffer.Append("(null)");
            }
        }

        /// <summary>
        /// Formats a value as a string.
        /// </summary>
        private void AppendFormat(
            StringBuilder buffer,
            object value,
            IFormatProvider formatProvider)
        {
            // check for null.
            if (value == null || TypeInfo.IsUnknown)
            {
                buffer.Append("(null)");
                return;
            }

            // convert byte string to hexstring.
            if (TypeInfo.BuiltInType == BuiltInType.ByteString && TypeInfo.ValueRank < 0)
            {
                byte[] bytes = (byte[])value;
                AppendByteString(buffer, bytes, formatProvider);
                return;
            }

            // convert XML element to string.
            if (TypeInfo.BuiltInType == BuiltInType.XmlElement && TypeInfo.ValueRank < 0)
            {
                var xml = (XmlElement)value;
                buffer.AppendFormat(formatProvider, "{0}", xml.OuterXml);
                return;
            }

            // recusrively write individual elements of an array.

            if (value is Array array && TypeInfo.ValueRank <= 1)
            {
                buffer.Append('{');

                if (TypeInfo.BuiltInType == BuiltInType.ByteString)
                {
                    if (array.Length > 0)
                    {
                        byte[] bytes = (byte[])array.GetValue(0);
                        AppendByteString(buffer, bytes, formatProvider);
                    }

                    for (int ii = 1; ii < array.Length; ii++)
                    {
                        buffer.Append('|');
                        byte[] bytes = (byte[])array.GetValue(ii);
                        AppendByteString(buffer, bytes, formatProvider);
                    }
                }
                else
                {
                    if (array.Length > 0)
                    {
                        AppendFormat(buffer, array.GetValue(0), formatProvider);
                    }

                    for (int ii = 1; ii < array.Length; ii++)
                    {
                        buffer.Append('|');
                        AppendFormat(buffer, array.GetValue(ii), formatProvider);
                    }
                }
                buffer.Append('}');
                return;
            }

            // let the object format itself.
            buffer.AppendFormat(formatProvider, "{0}", value);
        }

        /// <summary>
        /// Helper to create a InvalidCastException for type T.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        private static InvalidCastException CannotCast<T>()
        {
            return new InvalidCastException(
                CoreUtils.Format(
                    "Cannot convert Variant to {1}.",
                    typeof(T).Name));
        }

        [Conditional("DEBUG")]
        private static void DebugCheck(object value, TypeInfo typeInfo)
        {
            // no sanity check possible for null values
            if (value == null)
            {
                return;
            }
            var sanityCheck = TypeInfo.Construct(value);

            // except special case byte array vs. bytestring
            if (sanityCheck.BuiltInType == BuiltInType.ByteString &&
                sanityCheck.ValueRank == ValueRanks.Scalar &&
                typeInfo.BuiltInType == BuiltInType.Byte &&
                typeInfo.ValueRank == ValueRanks.OneDimension)
            {
                return;
            }

            // An enumeration can contain Int32
            else if (sanityCheck.BuiltInType == BuiltInType.Int32 &&
                typeInfo.BuiltInType == BuiltInType.Enumeration)
            {
                return;
            }

            if (sanityCheck.BuiltInType != typeInfo.BuiltInType)
            {
                System.Diagnostics.Debug.Fail(
                    CoreUtils.Format(
                        "{0} != {1}",
                        sanityCheck.BuiltInType,
                        typeInfo.BuiltInType));
            }

            if (sanityCheck.ValueRank != typeInfo.ValueRank)
            {
                System.Diagnostics.Debug.Fail(
                    CoreUtils.Format(
                        "{0} != {1}",
                        sanityCheck.ValueRank,
                        typeInfo.ValueRank));
            }
        }

        private readonly object m_value;
    }

    /// <summary>
    /// A collection of Variant objects.
    /// </summary>
    [CollectionDataContract(
        Name = "ListOfVariant",
        Namespace = Namespaces.OpcUaXsd,
        ItemName = "Variant")]
    public class VariantCollection : List<Variant>, ICloneable
    {
        /// <inheritdoc/>
        public VariantCollection()
        {
        }

        /// <inheritdoc/>
        public VariantCollection(IEnumerable<Variant> collection)
            : base(collection)
        {
        }

        /// <inheritdoc/>
        public VariantCollection(int capacity)
            : base(capacity)
        {
        }

        /// <inheritdoc/>
        public static implicit operator VariantCollection(Variant[] values)
        {
            return values == null ? [] : [.. values];
        }

        /// <inheritdoc/>
        public virtual object Clone()
        {
            return MemberwiseClone();
        }

        /// <inheritdoc/>
        public new object MemberwiseClone()
        {
            var clone = new VariantCollection(Count);

            foreach (Variant element in this)
            {
                clone.Add((Variant)CoreUtils.Clone(element));
            }

            return clone;
        }
    }

    /// <summary>
    /// Helper to allow data contract serialization of Variant
    /// </summary>
    [DataContract(
        Name = "Variant",
        Namespace = Namespaces.OpcUaXsd)]
    public class SerializableVariant :
        ISurrogateFor<Variant>,
        IEquatable<Variant>,
        IEquatable<SerializableVariant>
    {
        /// <inheritdoc/>
        public SerializableVariant()
        {
            Value = default;
        }

        /// <inheritdoc/>
        public SerializableVariant(Variant value)
        {
            Value = value;
        }

        /// <inheritdoc/>
        public Variant Value { get; private set; }

        /// <inheritdoc/>
        public object GetValue()
        {
            return Value!;
        }

        /// <summary>
        /// The value stored within the Variant object.
        /// </summary>
        /// <exception cref="ServiceResultException"></exception>
        [DataMember(Name = "Value", Order = 1)]
        internal XmlElement XmlEncodedValue
        {
            get
            {
                // check for null.
                if (Value.Value == null)
                {
                    return null;
                }

                // create encoder.
                using var encoder = new XmlEncoder(
                    AmbientMessageContext.CurrentContext);
                // write value.
                encoder.WriteVariantContents(Value.Value, Value.TypeInfo);

                // create document from encoder.
                var document = new XmlDocument();
                document.LoadInnerXml(encoder.CloseAndReturnText());

                // return element.
                return document.DocumentElement;
            }
            set
            {
                // check for null values.
                if (value == null)
                {
                    Value = Variant.Null;
                    return;
                }

                // create decoder.
                using var decoder = new XmlDecoder(value,
                    AmbientMessageContext.CurrentContext);
                try
                {
                    // read value.
                    object body = decoder.ReadVariantContents(out TypeInfo typeInfo);
                    Value = new Variant(body, typeInfo);
                }
                catch (Exception e)
                {
                    throw ServiceResultException.Create(
                        StatusCodes.BadDecodingError,
                        e,
                        "Error decoding Variant value.");
                }
                finally
                {
                    // close decoder.
                    decoder.Close();
                }
            }
        }

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            return obj switch
            {
                SerializableVariant s => Equals(s),
                Variant n => Equals(n),
                _ => Value.Equals(obj)
            };
        }

        /// <inheritdoc/>
        public bool Equals(Variant obj)
        {
            return Value.Equals(obj);
        }

        /// <inheritdoc/>
        public bool Equals(SerializableVariant obj)
        {
            return Value.Equals(obj?.Value ?? default);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }

        /// <inheritdoc/>
        public static bool operator ==(
            SerializableVariant left,
            SerializableVariant right)
        {
            return EqualityComparer<SerializableVariant>.Default.Equals(left, right);
        }

        /// <inheritdoc/>
        public static bool operator !=(
            SerializableVariant left,
            SerializableVariant right)
        {
            return !(left == right);
        }

        /// <inheritdoc/>
        public static bool operator ==(
            SerializableVariant left,
            Variant right)
        {
            return EqualityComparer<SerializableVariant>.Default.Equals(left, right);
        }

        /// <inheritdoc/>
        public static bool operator !=(
            SerializableVariant left,
            Variant right)
        {
            return !(left == right);
        }

        /// <inheritdoc/>
        public static implicit operator SerializableVariant(Variant value)
        {
            return new SerializableVariant(value);
        }

        /// <inheritdoc/>
        public static implicit operator Variant(SerializableVariant value)
        {
            return value.Value;
        }

        /// <inheritdoc/>
        public static explicit operator XmlElement(SerializableVariant value)
        {
            return value.XmlEncodedValue;
        }

        /// <inheritdoc/>
        public static explicit operator SerializableVariant(XmlElement value)
        {
            return new SerializableVariant { XmlEncodedValue = value };
        }
    }
}
