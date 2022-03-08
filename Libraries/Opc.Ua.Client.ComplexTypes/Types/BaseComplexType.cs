/* ========================================================================
 * Copyright (c) 2005-2020 The OPC Foundation, Inc. All rights reserved.
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
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text;
using System.Xml;

namespace Opc.Ua.Client.ComplexTypes
{
    /// <summary>
    /// The base class for all complex types.
    /// </summary>
    [System.CodeDom.Compiler.GeneratedCode("Stack", "1.0.0.0")]
    public class BaseComplexType :
        IEncodeable, IFormattable,
        IComplexTypeProperties,
        IStructureTypeInfo
    {

        /// <summary>
        /// Initializes the object with default values.
        /// </summary>
        public BaseComplexType()
        {
            TypeId = ExpandedNodeId.Null;
            BinaryEncodingId = ExpandedNodeId.Null;
            XmlEncodingId = ExpandedNodeId.Null;
            m_context = MessageContextExtension.CurrentContext;
            InitializePropertyAttributes();
        }

        /// <summary>
        /// Initializes the object with a <paramref name="typeId"/>.
        /// </summary>
        /// <param name="typeId">The type to copy and create an instance from</param>
        public BaseComplexType(ExpandedNodeId typeId)
        {
            TypeId = typeId;
        }

        [OnSerializing()]
        private void UpdateContext(StreamingContext context)
        {
            m_context = MessageContextExtension.CurrentContext;
        }

        /// <summary>
        /// Initializes the object during deserialization.
        /// </summary>
        [OnDeserializing()]
        private void Initialize(StreamingContext context)
        {
            TypeId = ExpandedNodeId.Null;
            m_context = MessageContextExtension.CurrentContext;
        }

        /// <summary cref="IEncodeable.TypeId" />
        public ExpandedNodeId TypeId { get; set; }

        /// <summary cref="IEncodeable.BinaryEncodingId" />
        public ExpandedNodeId BinaryEncodingId { get; set; }

        /// <summary cref="IEncodeable.XmlEncodingId" />
        public ExpandedNodeId XmlEncodingId { get; set; }

        /// <summary cref="IStructureTypeInfo.StructureType" />
        public virtual StructureType StructureType => StructureType.Structure;

        /// <summary>
        /// Makes a deep copy of the object.
        /// </summary>
        /// <returns>
        /// A new object that is a copy of this instance.
        /// </returns>
        public new virtual object MemberwiseClone()
        {
            Type thisType = GetType();
            var clone = Activator.CreateInstance(thisType) as BaseComplexType;

            clone.TypeId = TypeId;
            clone.BinaryEncodingId = BinaryEncodingId;
            clone.XmlEncodingId = XmlEncodingId;

            // clone all properties of derived class
            foreach (ComplexTypePropertyAttribute property in GetPropertyEnumerator())
            {
                property.SetValue(clone, Utils.Clone(property.GetValue(this)));
            }

            return clone;
        }

        /// <summary cref="IEncodeable.Encode(IEncoder)" />
        public virtual void Encode(IEncoder encoder)
        {
            encoder.PushNamespace(XmlNamespace);

            foreach (ComplexTypePropertyAttribute property in GetPropertyEnumerator())
            {
                EncodeProperty(encoder, property.PropertyInfo, property.ValueRank);
            }

            encoder.PopNamespace();
        }

        /// <summary cref="IEncodeable.Decode(IDecoder)" />
        public virtual void Decode(IDecoder decoder)
        {
            decoder.PushNamespace(XmlNamespace);

            foreach (ComplexTypePropertyAttribute property in GetPropertyEnumerator())
            {
                DecodeProperty(decoder, property.PropertyInfo, property.ValueRank);
            }

            decoder.PopNamespace();
        }

        /// <summary cref="IEncodeable.IsEqual(IEncodeable)" />
        public virtual bool IsEqual(IEncodeable equalValue)
        {
            if (Object.ReferenceEquals(this, equalValue))
            {
                return true;
            }

            if (!(equalValue is BaseComplexType valueBaseType))
            {
                return false;
            }

            Type valueType = valueBaseType.GetType();
            if (GetType() != valueType)
            {
                return false;
            }

            foreach (ComplexTypePropertyAttribute property in GetPropertyEnumerator())
            {
                if (!Utils.IsEqual(property.GetValue(this), property.GetValue(valueBaseType)))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary cref="object.ToString()" />
        public override string ToString()
        {
            return ToString(null, null);
        }



        /// <summary>
        /// Returns the string representation of the complex type.
        /// </summary>
        /// <param name="format">(Unused). Leave this as null</param>
        /// <param name="formatProvider">The provider of a mechanism for retrieving an object to control formatting.</param>
        /// <returns>
        /// A <see cref="T:System.String"/> containing the value of the current embeded instance in the specified format.
        /// </returns>
        /// <exception cref="FormatException">Thrown if the <i>format</i> parameter is not null</exception>
        public virtual string ToString(string format, IFormatProvider formatProvider)
        {
            if (format == null)
            {
                var body = new StringBuilder();

                foreach (ComplexTypePropertyAttribute property in GetPropertyEnumerator())
                {
                    AppendPropertyValue(formatProvider, body, property.GetValue(this), property.ValueRank);
                }

                if (body.Length > 0)
                {
                    return body.Append('}').ToString();
                }

                if (!NodeId.IsNull(TypeId))
                {
                    return string.Format(formatProvider, "{{{0}}}", TypeId);
                }

                return "(null)";
            }

            throw new FormatException(Utils.Format("Invalid format string: '{0}'.", format));
        }

        /// <summary cref="IComplexTypeProperties.GetPropertyCount()" />
        public virtual int GetPropertyCount()
        {
            return m_propertyList.Count;
        }

        /// <summary cref="IComplexTypeProperties.GetPropertyNames()" />
        public virtual IList<string> GetPropertyNames()
        {
            return m_propertyList.Select(p => p.Name).ToList();
        }

        /// <summary cref="IComplexTypeProperties.GetPropertyTypes()" />
        public virtual IList<Type> GetPropertyTypes()
        {
            return m_propertyList.Select(p => p.PropertyType).ToList();
        }

        /// <summary>
        /// Access property values by index.
        /// </summary>
        public virtual object this[int index]
        {
            get => m_propertyList.ElementAt(index).GetValue(this);
            set => m_propertyList.ElementAt(index).SetValue(this, value);
        }

        /// <summary>
        /// Access property values by name.
        /// </summary>
        public virtual object this[string name]
        {
            get => m_propertyDict[name].GetValue(this);
            set => m_propertyDict[name].SetValue(this, value);
        }

        /// <summary>
        /// Ordered enumerator for properties.
        /// </summary>
        public virtual IEnumerable<ComplexTypePropertyAttribute> GetPropertyEnumerator()
        {
            return m_propertyList;
        }

        /// <summary>
        /// Formatting helper.
        /// </summary>
        private void AddSeparator(StringBuilder body)
        {
            if (body.Length == 0)
            {
                body.Append('{');
            }
            else
            {
                body.Append(" | ");
            }
        }

        /// <summary>
        /// Append a property to the value string.
        /// Handle arrays and enumerations.
        /// </summary>
        protected void AppendPropertyValue(
            IFormatProvider formatProvider,
            StringBuilder body,
            object value,
            int valueRank)
        {
            AddSeparator(body);
            if (valueRank >= 0 &&
                value is IEnumerable)
            {
                bool first = true;
                var enumerable = value as IEnumerable;
                body.Append('[');
                foreach (object item in enumerable)
                {
                    if (!first)
                    {
                        body.Append(',');
                    }
                    AppendPropertyValue(formatProvider, body, item);
                    first = false;
                }
                body.Append(']');
            }
            else
            {
                AppendPropertyValue(formatProvider, body, value);
            }
        }

        /// <summary>
        /// Append a property to the value string.
        /// </summary>
        private void AppendPropertyValue(
            IFormatProvider formatProvider,
            StringBuilder body,
            object value)
        {
            if (value is byte[] x)
            {
                body.AppendFormat(formatProvider, "Byte[{0}]", x.Length);
                return;
            }

            if (value is XmlElement xmlElements)
            {
                body.AppendFormat(formatProvider, "<{0}>", xmlElements.Name);
                return;
            }

            body.AppendFormat("{0}", value);
        }

        /// <summary>
        /// Encode a property based on the property type and value rank.
        /// </summary>
        protected void EncodeProperty(
            IEncoder encoder,
            string name,
            PropertyInfo property,
            int valueRank
            )
        {
            if (valueRank < 0)
            {
                EncodeProperty(encoder, name, property);
            }
            else
            {
                EncodePropertyArray(encoder, name, property);
            }
        }

        /// <summary>
        /// Encode a property based on the property type and value rank.
        /// </summary>
        protected void EncodeProperty(
            IEncoder encoder,
            PropertyInfo property,
            int valueRank)
        {
            EncodeProperty(encoder, property.Name, property, valueRank);
        }

        /// <summary>
        /// Encode a scalar property based on the property type.
        /// </summary>
        private void EncodeProperty(IEncoder encoder, string name, PropertyInfo property)
        {
            Type propertyType = property.PropertyType;
            if (propertyType == typeof(bool))
            {
                encoder.WriteBoolean(name, (bool)property.GetValue(this));
            }
            else if (propertyType == typeof(sbyte))
            {
                encoder.WriteSByte(name, (sbyte)property.GetValue(this));
            }
            else if (propertyType == typeof(byte))
            {
                encoder.WriteByte(name, (byte)property.GetValue(this));
            }
            else if (propertyType == typeof(short))
            {
                encoder.WriteInt16(name, (short)property.GetValue(this));
            }
            else if (propertyType == typeof(ushort))
            {
                encoder.WriteUInt16(name, (ushort)property.GetValue(this));
            }
            else if (propertyType.IsEnum)
            {
                encoder.WriteEnumerated(name, (Enum)property.GetValue(this));
            }
            else if (propertyType == typeof(int))
            {
                encoder.WriteInt32(name, (int)property.GetValue(this));
            }
            else if (propertyType == typeof(uint))
            {
                encoder.WriteUInt32(name, (uint)property.GetValue(this));
            }
            else if (propertyType == typeof(long))
            {
                encoder.WriteInt64(name, (long)property.GetValue(this));
            }
            else if (propertyType == typeof(ulong))
            {
                encoder.WriteUInt64(name, (ulong)property.GetValue(this));
            }
            else if (propertyType == typeof(float))
            {
                encoder.WriteFloat(name, (float)property.GetValue(this));
            }
            else if (propertyType == typeof(double))
            {
                encoder.WriteDouble(name, (double)property.GetValue(this));
            }
            else if (propertyType == typeof(string))
            {
                encoder.WriteString(name, (string)property.GetValue(this));
            }
            else if (propertyType == typeof(DateTime))
            {
                encoder.WriteDateTime(name, (DateTime)property.GetValue(this));
            }
            else if (propertyType == typeof(Uuid))
            {
                encoder.WriteGuid(name, (Uuid)property.GetValue(this));
            }
            else if (propertyType == typeof(byte[]))
            {
                encoder.WriteByteString(name, (byte[])property.GetValue(this));
            }
            else if (propertyType == typeof(XmlElement))
            {
                encoder.WriteXmlElement(name, (XmlElement)property.GetValue(this));
            }
            else if (propertyType == typeof(NodeId))
            {
                encoder.WriteNodeId(name, (NodeId)property.GetValue(this));
            }
            else if (propertyType == typeof(ExpandedNodeId))
            {
                encoder.WriteExpandedNodeId(name, (ExpandedNodeId)property.GetValue(this));
            }
            else if (propertyType == typeof(StatusCode))
            {
                encoder.WriteStatusCode(name, (StatusCode)property.GetValue(this));
            }
            else if (propertyType == typeof(DiagnosticInfo))
            {
                encoder.WriteDiagnosticInfo(name, (DiagnosticInfo)property.GetValue(this));
            }
            else if (propertyType == typeof(QualifiedName))
            {
                encoder.WriteQualifiedName(name, (QualifiedName)property.GetValue(this));
            }
            else if (propertyType == typeof(LocalizedText))
            {
                encoder.WriteLocalizedText(name, (LocalizedText)property.GetValue(this));
            }
            else if (propertyType == typeof(DataValue))
            {
                encoder.WriteDataValue(name, (DataValue)property.GetValue(this));
            }
            else if (propertyType == typeof(Variant))
            {
                encoder.WriteVariant(name, (Variant)property.GetValue(this));
            }
            else if (propertyType == typeof(ExtensionObject))
            {
                encoder.WriteExtensionObject(name, (ExtensionObject)property.GetValue(this));
            }
            else if (typeof(IEncodeable).IsAssignableFrom(propertyType))
            {
                encoder.WriteEncodeable(name, (IEncodeable)property.GetValue(this), propertyType);
            }
            else
            {
                throw new ServiceResultException(StatusCodes.BadNotSupported,
                    $"Unknown type {propertyType} to encode.");
            }
        }

        /// <summary>
        /// Encode an array property based on the base property type.
        /// </summary>
        private void EncodePropertyArray(IEncoder encoder, string name, PropertyInfo property)
        {
            Type elementType = property.PropertyType.GetElementType() ?? property.PropertyType.GetItemType();
            if (elementType == typeof(bool))
            {
                encoder.WriteBooleanArray(name, (BooleanCollection)property.GetValue(this));
            }
            else if (elementType == typeof(sbyte))
            {
                encoder.WriteSByteArray(name, (SByteCollection)property.GetValue(this));
            }
            else if (elementType == typeof(byte))
            {
                encoder.WriteByteArray(name, (ByteCollection)property.GetValue(this));
            }
            else if (elementType == typeof(short))
            {
                encoder.WriteInt16Array(name, (Int16Collection)property.GetValue(this));
            }
            else if (elementType == typeof(ushort))
            {
                encoder.WriteUInt16Array(name, (UInt16Collection)property.GetValue(this));
            }
            else if (elementType == typeof(int))
            {
                encoder.WriteInt32Array(name, (Int32Collection)property.GetValue(this));
            }
            else if (elementType.IsEnum)
            {
                encoder.WriteEnumeratedArray(name, (Array)property.GetValue(this), elementType);
            }
            else if (elementType == typeof(uint))
            {
                encoder.WriteUInt32Array(name, (UInt32Collection)property.GetValue(this));
            }
            else if (elementType == typeof(long))
            {
                encoder.WriteInt64Array(name, (Int64Collection)property.GetValue(this));
            }
            else if (elementType == typeof(ulong))
            {
                encoder.WriteUInt64Array(name, (UInt64Collection)property.GetValue(this));
            }
            else if (elementType == typeof(float))
            {
                encoder.WriteFloatArray(name, (FloatCollection)property.GetValue(this));
            }
            else if (elementType == typeof(double))
            {
                encoder.WriteDoubleArray(name, (DoubleCollection)property.GetValue(this));
            }
            else if (elementType == typeof(string))
            {
                encoder.WriteStringArray(name, (StringCollection)property.GetValue(this));
            }
            else if (elementType == typeof(DateTime))
            {
                encoder.WriteDateTimeArray(name, (DateTimeCollection)property.GetValue(this));
            }
            else if (elementType == typeof(Uuid))
            {
                encoder.WriteGuidArray(name, (UuidCollection)property.GetValue(this));
            }
            else if (elementType == typeof(byte[]))
            {
                encoder.WriteByteStringArray(name, (ByteStringCollection)property.GetValue(this));
            }
            else if (elementType == typeof(XmlElement))
            {
                encoder.WriteXmlElementArray(name, (XmlElementCollection)property.GetValue(this));
            }
            else if (elementType == typeof(NodeId))
            {
                encoder.WriteNodeIdArray(name, (NodeIdCollection)property.GetValue(this));
            }
            else if (elementType == typeof(ExpandedNodeId))
            {
                encoder.WriteExpandedNodeIdArray(name, (ExpandedNodeIdCollection)property.GetValue(this));
            }
            else if (elementType == typeof(StatusCode))
            {
                encoder.WriteStatusCodeArray(name, (StatusCodeCollection)property.GetValue(this));
            }
            else if (elementType == typeof(DiagnosticInfo))
            {
                encoder.WriteDiagnosticInfoArray(name, (DiagnosticInfoCollection)property.GetValue(this));
            }
            else if (elementType == typeof(QualifiedName))
            {
                encoder.WriteQualifiedNameArray(name, (QualifiedNameCollection)property.GetValue(this));
            }
            else if (elementType == typeof(LocalizedText))
            {
                encoder.WriteLocalizedTextArray(name, (LocalizedTextCollection)property.GetValue(this));
            }
            else if (elementType == typeof(DataValue))
            {
                encoder.WriteDataValueArray(name, (DataValueCollection)property.GetValue(this));
            }
            else if (elementType == typeof(Variant))
            {
                encoder.WriteVariantArray(name, (VariantCollection)property.GetValue(this));
            }
            else if (elementType == typeof(ExtensionObject))
            {
                encoder.WriteExtensionObjectArray(name, (ExtensionObjectCollection)property.GetValue(this));
            }
            else if (typeof(IEncodeable).IsAssignableFrom(elementType))
            {
                object value = property.GetValue(this);
                if (!(value is IEncodeableCollection encodable))
                {
                    encodable = IEncodeableCollection.ToIEncodeableCollection(value as IEncodeable[]);
                }
                encoder.WriteEncodeableArray(property.Name, encodable.ToArray(), property.PropertyType);
            }
            else
            {
                throw new ServiceResultException(StatusCodes.BadNotSupported,
                    $"Unknown type {elementType} to encode.");
            }
        }

        /// <summary>
        /// Decode a property based on the property type and value rank.
        /// </summary>
        protected void DecodeProperty(
            IDecoder decoder,
            PropertyInfo property,
            int valueRank)
        {
            DecodeProperty(decoder, property.Name, property, valueRank);
        }

        /// <summary>
        /// Decode a property based on the property type and value rank.
        /// </summary>
        protected void DecodeProperty(
            IDecoder decoder,
            string name,
            PropertyInfo property,
            int valueRank)
        {
            if (valueRank < 0)
            {
                DecodeProperty(decoder, name, property);
            }
            else
            {
                DecodePropertyArray(decoder, name, property);
            }
        }

        /// <summary>
        /// Decode a scalar property based on the property type.
        /// </summary>
        private void DecodeProperty(IDecoder decoder, string name, PropertyInfo property)
        {
            Type propertyType = property.PropertyType;
            if (propertyType == typeof(bool))
            {
                property.SetValue(this, decoder.ReadBoolean(name));
            }
            else if (propertyType == typeof(sbyte))
            {
                property.SetValue(this, decoder.ReadSByte(name));
            }
            else if (propertyType == typeof(byte))
            {
                property.SetValue(this, decoder.ReadByte(name));
            }
            else if (propertyType == typeof(short))
            {
                property.SetValue(this, decoder.ReadInt16(name));
            }
            else if (propertyType == typeof(ushort))
            {
                property.SetValue(this, decoder.ReadUInt16(name));
            }
            else if (propertyType.IsEnum)
            {
                property.SetValue(this, decoder.ReadEnumerated(name, propertyType));
            }
            else if (propertyType == typeof(int))
            {
                property.SetValue(this, decoder.ReadInt32(name));
            }
            else if (propertyType == typeof(uint))
            {
                property.SetValue(this, decoder.ReadUInt32(name));
            }
            else if (propertyType == typeof(long))
            {
                property.SetValue(this, decoder.ReadInt64(name));
            }
            else if (propertyType == typeof(ulong))
            {
                property.SetValue(this, decoder.ReadUInt64(name));
            }
            else if (propertyType == typeof(float))
            {
                property.SetValue(this, decoder.ReadFloat(name));
            }
            else if (propertyType == typeof(double))
            {
                property.SetValue(this, decoder.ReadDouble(name));
            }
            else if (propertyType == typeof(string))
            {
                property.SetValue(this, decoder.ReadString(name));
            }
            else if (propertyType == typeof(DateTime))
            {
                property.SetValue(this, decoder.ReadDateTime(name));
            }
            else if (propertyType == typeof(Uuid))
            {
                property.SetValue(this, decoder.ReadGuid(name));
            }
            else if (propertyType == typeof(byte[]))
            {
                property.SetValue(this, decoder.ReadByteString(name));
            }
            else if (propertyType == typeof(XmlElement))
            {
                property.SetValue(this, decoder.ReadXmlElement(name));
            }
            else if (propertyType == typeof(NodeId))
            {
                property.SetValue(this, decoder.ReadNodeId(name));
            }
            else if (propertyType == typeof(ExpandedNodeId))
            {
                property.SetValue(this, decoder.ReadExpandedNodeId(name));
            }
            else if (propertyType == typeof(StatusCode))
            {
                property.SetValue(this, decoder.ReadStatusCode(name));
            }
            else if (propertyType == typeof(DiagnosticInfo))
            {
                property.SetValue(this, decoder.ReadDiagnosticInfo(name));
            }
            else if (propertyType == typeof(QualifiedName))
            {
                property.SetValue(this, decoder.ReadQualifiedName(name));
            }
            else if (propertyType == typeof(LocalizedText))
            {
                property.SetValue(this, decoder.ReadLocalizedText(name));
            }
            else if (propertyType == typeof(DataValue))
            {
                property.SetValue(this, decoder.ReadDataValue(name));
            }
            else if (propertyType == typeof(Variant))
            {
                property.SetValue(this, decoder.ReadVariant(name));
            }
            else if (propertyType == typeof(ExtensionObject))
            {
                property.SetValue(this, decoder.ReadExtensionObject(name));
            }
            else if (typeof(IEncodeable).IsAssignableFrom(propertyType))
            {
                property.SetValue(this, decoder.ReadEncodeable(name, propertyType));
            }
            else
            {
                throw new ServiceResultException(StatusCodes.BadNotSupported,
                    $"Unknown type {propertyType} to decode.");
            }
        }

        /// <summary>
        /// Decode an array property based on the base property type.
        /// </summary>
        private void DecodePropertyArray(IDecoder decoder, string name, PropertyInfo property)
        {
            Type elementType = property.PropertyType.GetElementType() ?? property.PropertyType.GetItemType();
            if (elementType == typeof(bool))
            {
                property.SetValue(this, decoder.ReadBooleanArray(name));
            }
            else if (elementType == typeof(sbyte))
            {
                property.SetValue(this, decoder.ReadSByteArray(name));
            }
            else if (elementType == typeof(byte))
            {
                property.SetValue(this, decoder.ReadByteArray(name));
            }
            else if (elementType == typeof(short))
            {
                property.SetValue(this, decoder.ReadInt16Array(name));
            }
            else if (elementType == typeof(ushort))
            {
                property.SetValue(this, decoder.ReadUInt16Array(name));
            }
            else if (elementType.IsEnum)
            {
                property.SetValue(this, decoder.ReadEnumeratedArray(name, elementType));
            }
            else if (elementType == typeof(int))
            {
                property.SetValue(this, decoder.ReadInt32Array(name));
            }
            else if (elementType == typeof(uint))
            {
                property.SetValue(this, decoder.ReadUInt32Array(name));
            }
            else if (elementType == typeof(long))
            {
                property.SetValue(this, decoder.ReadInt64Array(name));
            }
            else if (elementType == typeof(ulong))
            {
                property.SetValue(this, decoder.ReadUInt64Array(name));
            }
            else if (elementType == typeof(float))
            {
                property.SetValue(this, decoder.ReadFloatArray(name));
            }
            else if (elementType == typeof(double))
            {
                property.SetValue(this, decoder.ReadDoubleArray(name));
            }
            else if (elementType == typeof(string))
            {
                property.SetValue(this, decoder.ReadStringArray(name));
            }
            else if (elementType == typeof(DateTime))
            {
                property.SetValue(this, decoder.ReadDateTimeArray(name));
            }
            else if (elementType == typeof(Uuid))
            {
                property.SetValue(this, decoder.ReadGuidArray(name));
            }
            else if (elementType == typeof(byte[]))
            {
                property.SetValue(this, decoder.ReadByteStringArray(name));
            }
            else if (elementType == typeof(XmlElement))
            {
                property.SetValue(this, decoder.ReadXmlElementArray(name));
            }
            else if (elementType == typeof(NodeId))
            {
                property.SetValue(this, decoder.ReadNodeIdArray(name));
            }
            else if (elementType == typeof(ExpandedNodeId))
            {
                property.SetValue(this, decoder.ReadExpandedNodeIdArray(name));
            }
            else if (elementType == typeof(StatusCode))
            {
                property.SetValue(this, decoder.ReadStatusCodeArray(name));
            }
            else if (elementType == typeof(DiagnosticInfo))
            {
                property.SetValue(this, decoder.ReadDiagnosticInfoArray(name));
            }
            else if (elementType == typeof(QualifiedName))
            {
                property.SetValue(this, decoder.ReadQualifiedNameArray(name));
            }
            else if (elementType == typeof(LocalizedText))
            {
                property.SetValue(this, decoder.ReadLocalizedTextArray(name));
            }
            else if (elementType == typeof(DataValue))
            {
                property.SetValue(this, decoder.ReadDataValueArray(name));
            }
            else if (elementType == typeof(Variant))
            {
                property.SetValue(this, decoder.ReadVariantArray(name));
            }
            else if (elementType == typeof(ExtensionObject))
            {
                property.SetValue(this, decoder.ReadExtensionObjectArray(name));
            }
            else if (typeof(IEncodeable).IsAssignableFrom(elementType))
            {
                property.SetValue(this, decoder.ReadEncodeableArray(name, elementType));
            }
            else
            {
                throw new ServiceResultException(StatusCodes.BadNotSupported,
                    $"Unknown type {elementType} to decode.");
            }
        }

        /// <summary>
        /// Initialize the helpers for property enumerator and dictionary.
        /// </summary>
        protected virtual void InitializePropertyAttributes()
        {
            var definitionAttribute = (StructureDefinitionAttribute)
                GetType().GetCustomAttribute(typeof(StructureDefinitionAttribute));
            if (definitionAttribute != null)
            {
                m_structureBaseType = definitionAttribute.BaseDataType;
            }

            var typeAttribute = (StructureTypeIdAttribute)
                GetType().GetCustomAttribute(typeof(StructureTypeIdAttribute));
            if (typeAttribute != null)
            {
                TypeId = ExpandedNodeId.Parse(typeAttribute.ComplexTypeId);
                BinaryEncodingId = ExpandedNodeId.Parse(typeAttribute.BinaryEncodingId);
                XmlEncodingId = ExpandedNodeId.Parse(typeAttribute.XmlEncodingId);
            }

            m_propertyList = new List<ComplexTypePropertyAttribute>();
            PropertyInfo[] properties = GetType().GetProperties();
            foreach (PropertyInfo property in properties)
            {
                var fieldAttribute = (StructureFieldAttribute)
                    property.GetCustomAttribute(typeof(StructureFieldAttribute));

                if (fieldAttribute == null)
                {
                    continue;
                }

                var dataAttribute = (DataMemberAttribute)
                    property.GetCustomAttribute(typeof(DataMemberAttribute));

                var newProperty = new ComplexTypePropertyAttribute(property, fieldAttribute, dataAttribute);

                m_propertyList.Add(newProperty);
            }
            m_propertyList = m_propertyList.OrderBy(p => p.Order).ToList();
            m_propertyDict = m_propertyList.ToDictionary(p => p.Name, p => p);
        }





        /// <summary>
        /// Provide XmlNamespace based on systemType
        /// </summary>
        protected string XmlNamespace
        {
            get
            {
                if (m_xmlName == null)
                {
                    m_xmlName = EncodeableFactory.GetXmlName(GetType());
                }

                return m_xmlName != null ? m_xmlName.Namespace : string.Empty;
            }
        }




        /// <summary>
        /// The list of properties of this complex type.
        /// </summary>
        protected IList<ComplexTypePropertyAttribute> m_propertyList;
        /// <summary>
        /// The list of properties as dictionary.
        /// </summary>
        protected Dictionary<string, ComplexTypePropertyAttribute> m_propertyDict;



        private IServiceMessageContext m_context;
        private StructureBaseDataType m_structureBaseType;
        private XmlQualifiedName m_xmlName;


    }
}//namespace
