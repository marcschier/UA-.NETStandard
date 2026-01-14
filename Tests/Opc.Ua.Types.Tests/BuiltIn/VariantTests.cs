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
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Xml;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace Opc.Ua.Types.Tests.BuiltIn
{
    /// <summary>
    /// Comprehensive tests for the Variant built-in type.
    /// </summary>
    [TestFixture]
    [Category("BuiltInType")]
    [SetCulture("en-us")]
    [SetUICulture("en-us")]
    [Parallelizable]
    public class VariantTests
    {
        private enum EnumValue
        {
            Zero = 0,
            One = 1,
            Two = 2
        }

        public sealed record VariantDescriptor(
            string Name,
            Func<object> ValueFactory,
            Type ValueType,
            TypeInfo TypeInfo,
            string GetMethodName)
        {
            public object CreateValue()
            {
                return ValueFactory();
            }
        }

        private static IEnumerable<TestCaseData> ScalarConstructorCases
        {
            get
            {
                yield return CreateConstructorCase("ScalarBoolean",
                    () => true, TypeInfo.Scalars.Boolean);
                yield return CreateConstructorCase("ScalarSByte",
                    () => (sbyte)-1, TypeInfo.Scalars.SByte);
                yield return CreateConstructorCase("ScalarByte",
                    () => (byte)1, TypeInfo.Scalars.Byte);
                yield return CreateConstructorCase("ScalarInt16",
                    () => (short)-2, TypeInfo.Scalars.Int16);
                yield return CreateConstructorCase("ScalarUInt16",
                    () => (ushort)2, TypeInfo.Scalars.UInt16);
                yield return CreateConstructorCase("ScalarInt32",
                    () => -3, TypeInfo.Scalars.Int32);
                yield return CreateConstructorCase("ScalarUInt32",
                    () => 3u, TypeInfo.Scalars.UInt32);
                yield return CreateConstructorCase("ScalarInt64",
                    () => -4L, TypeInfo.Scalars.Int64);
                yield return CreateConstructorCase("ScalarUInt64",
                    () => 4UL, TypeInfo.Scalars.UInt64);
                yield return CreateConstructorCase("ScalarFloat",
                    () => 1.25f, TypeInfo.Scalars.Float);
                yield return CreateConstructorCase("ScalarDouble",
                    () => 2.25d, TypeInfo.Scalars.Double);
                yield return CreateConstructorCase("ScalarString",
                    () => "opc", TypeInfo.Scalars.String);
                yield return CreateConstructorCase("ScalarDateTime",
                    () => DateTime.SpecifyKind(new DateTime(2024, 1, 2, 3, 4, 5), DateTimeKind.Utc), TypeInfo.Scalars.DateTime);
                yield return CreateConstructorCase("ScalarGuid",
                    () => Uuid.NewUuid(), TypeInfo.Scalars.Guid);
                yield return CreateConstructorCase("ScalarByteString",
                    () => Bytes(1, 2, 3), TypeInfo.Scalars.ByteString);
                yield return CreateConstructorCase("ScalarXmlElement",
                    () => CreateXmlElement("Scalar"), TypeInfo.Scalars.XmlElement);
                yield return CreateConstructorCase("ScalarNodeId",
                    () => new NodeId(10, 1), TypeInfo.Scalars.NodeId);
                yield return CreateConstructorCase("ScalarExpandedNodeId",
                    () => ExpandedNodeId.Parse("nsu=Test;s=Node"), TypeInfo.Scalars.ExpandedNodeId);
                yield return CreateConstructorCase("ScalarStatusCode",
                    () => new StatusCode(123u), TypeInfo.Scalars.StatusCode);
                yield return CreateConstructorCase("ScalarQualifiedName",
                    () => new QualifiedName("name", 2), TypeInfo.Scalars.QualifiedName);
                yield return CreateConstructorCase("ScalarLocalizedText",
                    () => new LocalizedText("en", "text"), TypeInfo.Scalars.LocalizedText);
                yield return CreateConstructorCase("ScalarExtensionObject",
                    () => new ExtensionObject(new Argument()), TypeInfo.Scalars.ExtensionObject);
                yield return CreateConstructorCase("ScalarDataValue",
                    () => new DataValue(5), TypeInfo.Scalars.DataValue);
            }
        }

        private static IEnumerable<TestCaseData> ArrayConstructorCases
        {
            get
            {
                yield return CreateConstructorCase("ArrayBoolean",
                    () => ArrayOf(true, false), TypeInfo.Arrays.Boolean);
                yield return CreateConstructorCase("ArraySByte",
                    () => ArrayOf((sbyte)-1, (sbyte)1), TypeInfo.Arrays.SByte);
                yield return CreateConstructorCase("ArrayInt16",
                    () => ArrayOf((short)-2, (short)2), TypeInfo.Arrays.Int16);
                yield return CreateConstructorCase("ArrayUInt16",
                    () => ArrayOf((ushort)2, (ushort)4), TypeInfo.Arrays.UInt16);
                yield return CreateConstructorCase("ArrayInt32",
                    () => ArrayOf(-3, 3), TypeInfo.Arrays.Int32);
                yield return CreateConstructorCase("ArrayUInt32",
                    () => ArrayOf(3u, 4u), TypeInfo.Arrays.UInt32);
                yield return CreateConstructorCase("ArrayInt64",
                    () => ArrayOf(-4L, 4L), TypeInfo.Arrays.Int64);
                yield return CreateConstructorCase("ArrayUInt64",
                    () => ArrayOf(4UL, 5UL), TypeInfo.Arrays.UInt64);
                yield return CreateConstructorCase("ArrayFloat",
                    () => ArrayOf(1.0f, 2.0f), TypeInfo.Arrays.Float);
                yield return CreateConstructorCase("ArrayDouble",
                    () => ArrayOf(1.0d, 2.0d), TypeInfo.Arrays.Double);
                yield return CreateConstructorCase("ArrayString",
                    () => ArrayOf("a", "b"), TypeInfo.Arrays.String);
                yield return CreateConstructorCase("ArrayDateTime",
                    () => ArrayOf(
                        DateTime.SpecifyKind(new DateTime(2024, 2, 1), DateTimeKind.Utc),
                        DateTime.SpecifyKind(new DateTime(2025, 2, 1), DateTimeKind.Utc)), TypeInfo.Arrays.DateTime);
                yield return CreateConstructorCase("ArrayGuid",
                    () => ArrayOf(
                        new Uuid(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeee1")),
                        new Uuid(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeee2"))), TypeInfo.Arrays.Guid);
                yield return CreateConstructorCase("ArrayByteString",
                    () => ArrayOf(Bytes(1), Bytes(2, 3)), TypeInfo.Arrays.ByteString);
                yield return CreateConstructorCase("ArrayXmlElement",
                    () => ArrayOf(CreateXmlElement("A"), CreateXmlElement("B")), TypeInfo.Arrays.XmlElement);
                yield return CreateConstructorCase("ArrayNodeId",
                    () => ArrayOf(new NodeId(1), new NodeId(2, 1)), TypeInfo.Arrays.NodeId);
                yield return CreateConstructorCase("ArrayExpandedNodeId",
                    () => ArrayOf(
                        ExpandedNodeId.Parse("nsu=Test;s=One"),
                        ExpandedNodeId.Parse("nsu=Test;s=Two")), TypeInfo.Arrays.ExpandedNodeId);
                yield return CreateConstructorCase("ArrayStatusCode",
                    () => ArrayOf(
                        new StatusCode(1u),
                        new StatusCode(2u)), TypeInfo.Arrays.StatusCode);
                yield return CreateConstructorCase("ArrayQualifiedName",
                    () => ArrayOf(
                        new QualifiedName("q1", 1),
                        new QualifiedName("q2", 2)), TypeInfo.Arrays.QualifiedName);
                yield return CreateConstructorCase("ArrayLocalizedText",
                    () => ArrayOf(
                        new LocalizedText("en", "a"),
                        new LocalizedText("de", "b")), TypeInfo.Arrays.LocalizedText);
                yield return CreateConstructorCase("ArrayExtensionObject",
                    () => ArrayOf(
                        new ExtensionObject(new Argument()),
                        new ExtensionObject(new Argument())), TypeInfo.Arrays.ExtensionObject);
                yield return CreateConstructorCase("ArrayDataValue",
                    () => ArrayOf(new DataValue(1), new DataValue(2)), TypeInfo.Arrays.DataValue);
                yield return CreateConstructorCase("ArrayVariant",
                    () => ArrayOf(new Variant(1), new Variant("two")), TypeInfo.Arrays.Variant);
            }
        }

        private static IEnumerable<TestCaseData> ScalarDescriptorCases
        {
            get
            {
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarBoolean",
                        () => true,
                        typeof(bool),
                        TypeInfo.Scalars.Boolean,
                        nameof(Variant.GetBoolean)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarSByte",
                        () => (sbyte)-1,
                        typeof(sbyte),
                        TypeInfo.Scalars.SByte,
                        nameof(Variant.GetSByte)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarByte",
                        () => (byte)1,
                        typeof(byte),
                        TypeInfo.Scalars.Byte,
                        nameof(Variant.GetByte)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarInt16",
                        () => (short)-2,
                        typeof(short),
                        TypeInfo.Scalars.Int16,
                        nameof(Variant.GetInt16)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarUInt16",
                        () => (ushort)2,
                        typeof(ushort),
                        TypeInfo.Scalars.UInt16,
                        nameof(Variant.GetUInt16)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarInt32",
                        () => -3,
                        typeof(int),
                        TypeInfo.Scalars.Int32,
                        nameof(Variant.GetInt32)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarUInt32",
                        () => 3u,
                        typeof(uint),
                        TypeInfo.Scalars.UInt32,
                        nameof(Variant.GetUInt32)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarInt64",
                        () => -4L,
                        typeof(long),
                        TypeInfo.Scalars.Int64,
                        nameof(Variant.GetInt64)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarUInt64",
                        () => 4UL,
                        typeof(ulong),
                        TypeInfo.Scalars.UInt64,
                        nameof(Variant.GetUInt64)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarFloat",
                        () => 1.25f,
                        typeof(float),
                        TypeInfo.Scalars.Float,
                        nameof(Variant.GetFloat)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarDouble",
                        () => 2.25d,
                        typeof(double),
                        TypeInfo.Scalars.Double,
                        nameof(Variant.GetDouble)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarString",
                        () => "opc",
                        typeof(string),
                        TypeInfo.Scalars.String,
                        nameof(Variant.GetString)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarDateTime",
                        () => DateTime.SpecifyKind(new DateTime(2024, 1, 2), DateTimeKind.Utc),
                        typeof(DateTime),
                        TypeInfo.Scalars.DateTime,
                        nameof(Variant.GetDateTime)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarGuid",
                        () => Uuid.NewUuid(),
                        typeof(Uuid),
                        TypeInfo.Scalars.Guid,
                        nameof(Variant.GetGuid)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarByteString",
                        () => Bytes(1, 2),
                        typeof(byte[]),
                        TypeInfo.Scalars.ByteString,
                        nameof(Variant.GetByteString)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarXmlElement",
                        () => CreateXmlElement("Scalar"),
                        typeof(XmlElement),
                        TypeInfo.Scalars.XmlElement,
                        nameof(Variant.GetXmlElement)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarNodeId",
                        () => new NodeId(10, 1),
                        typeof(NodeId),
                        TypeInfo.Scalars.NodeId,
                        nameof(Variant.GetNodeId)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarExpandedNodeId",
                        () => ExpandedNodeId.Parse("nsu=Test;s=Node"),
                        typeof(ExpandedNodeId),
                        TypeInfo.Scalars.ExpandedNodeId,
                        nameof(Variant.GetExpandedNodeId)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarStatusCode",
                        () => new StatusCode(2u),
                        typeof(StatusCode),
                        TypeInfo.Scalars.StatusCode,
                        nameof(Variant.GetStatusCode)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarQualifiedName",
                        () => new QualifiedName("name", 1),
                        typeof(QualifiedName),
                        TypeInfo.Scalars.QualifiedName,
                        nameof(Variant.GetQualifiedName)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarLocalizedText",
                        () => new LocalizedText("en", "value"),
                        typeof(LocalizedText),
                        TypeInfo.Scalars.LocalizedText,
                        nameof(Variant.GetLocalizedText)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarExtensionObject",
                        () => new ExtensionObject(new Argument()),
                        typeof(ExtensionObject),
                        TypeInfo.Scalars.ExtensionObject,
                        nameof(Variant.GetExtensionObject)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ScalarDataValue",
                        () => new DataValue(1),
                        typeof(DataValue),
                        TypeInfo.Scalars.DataValue,
                        nameof(Variant.GetDataValue)));
            }
        }

        private static IEnumerable<TestCaseData> ArrayDescriptorCases
        {
            get
            {
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayBoolean",
                        () => ArrayOf(true, false),
                        typeof(bool[]),
                        TypeInfo.Arrays.Boolean,
                        nameof(Variant.GetBooleanArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArraySByte",
                        () => ArrayOf((sbyte)-1, (sbyte)1),
                        typeof(sbyte[]),
                        TypeInfo.Arrays.SByte,
                        nameof(Variant.GetSByteArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayInt16",
                        () => ArrayOf((short)-2, (short)2),
                        typeof(short[]),
                        TypeInfo.Arrays.Int16,
                        nameof(Variant.GetInt16Array)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayUInt16",
                        () => ArrayOf((ushort)2, (ushort)3),
                        typeof(ushort[]),
                        TypeInfo.Arrays.UInt16,
                        nameof(Variant.GetUInt16Array)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayInt32",
                        () => ArrayOf(-3, 3),
                        typeof(int[]),
                        TypeInfo.Arrays.Int32,
                        nameof(Variant.GetInt32Array)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayUInt32",
                        () => ArrayOf(3u, 4u),
                        typeof(uint[]),
                        TypeInfo.Arrays.UInt32,
                        nameof(Variant.GetUInt32Array)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayInt64",
                        () => ArrayOf(-4L, 4L),
                        typeof(long[]),
                        TypeInfo.Arrays.Int64,
                        nameof(Variant.GetInt64Array)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayUInt64",
                        () => ArrayOf(4UL, 5UL),
                        typeof(ulong[]),
                        TypeInfo.Arrays.UInt64,
                        nameof(Variant.GetUInt64Array)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayFloat",
                        () => ArrayOf(1.0f, 2.0f),
                        typeof(float[]),
                        TypeInfo.Arrays.Float,
                        nameof(Variant.GetFloatArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayDouble",
                        () => ArrayOf(1.0d, 2.0d),
                        typeof(double[]),
                        TypeInfo.Arrays.Double,
                        nameof(Variant.GetDoubleArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayString",
                        () => ArrayOf("a", "b"),
                        typeof(string[]),
                        TypeInfo.Arrays.String,
                        nameof(Variant.GetStringArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayDateTime",
                        () => ArrayOf(
                            DateTime.SpecifyKind(new DateTime(2024, 2, 1), DateTimeKind.Utc),
                            DateTime.SpecifyKind(new DateTime(2025, 2, 1), DateTimeKind.Utc)),
                        typeof(DateTime[]),
                        TypeInfo.Arrays.DateTime,
                        nameof(Variant.GetDateTimeArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayGuid",
                        () => ArrayOf(
                            new Uuid(Guid.Parse("bbbbbbbb-cccc-dddd-eeee-fffffffffff1")),
                            new Uuid(Guid.Parse("bbbbbbbb-cccc-dddd-eeee-fffffffffff2"))),
                        typeof(Uuid[]),
                        TypeInfo.Arrays.Guid,
                        nameof(Variant.GetGuidArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayByteString",
                        () => ArrayOf(Bytes(1), Bytes(2)),
                        typeof(byte[][]),
                        TypeInfo.Arrays.ByteString,
                        nameof(Variant.GetByteStringArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayXmlElement",
                        () => ArrayOf(CreateXmlElement("A"), CreateXmlElement("B")),
                        typeof(XmlElement[]),
                        TypeInfo.Arrays.XmlElement,
                        nameof(Variant.GetXmlElementArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayNodeId",
                        () => ArrayOf(new NodeId(1), new NodeId(2, 1)),
                        typeof(NodeId[]),
                        TypeInfo.Arrays.NodeId,
                        nameof(Variant.GetNodeIdArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayExpandedNodeId",
                        () => ArrayOf(ExpandedNodeId.Parse("nsu=Test;s=One"), ExpandedNodeId.Parse("nsu=Test;s=Two")),
                        typeof(ExpandedNodeId[]),
                        TypeInfo.Arrays.ExpandedNodeId,
                        nameof(Variant.GetExpandedNodeIdArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayStatusCode",
                        () => ArrayOf(new StatusCode(1u), new StatusCode(2u)),
                        typeof(StatusCode[]),
                        TypeInfo.Arrays.StatusCode,
                        nameof(Variant.GetStatusCodeArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayQualifiedName",
                        () => ArrayOf(new QualifiedName("q1", 1), new QualifiedName("q2", 2)),
                        typeof(QualifiedName[]),
                        TypeInfo.Arrays.QualifiedName,
                        nameof(Variant.GetQualifiedNameArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayLocalizedText",
                        () => ArrayOf(new LocalizedText("en", "a"), new LocalizedText("de", "b")),
                        typeof(LocalizedText[]),
                        TypeInfo.Arrays.LocalizedText,
                        nameof(Variant.GetLocalizedTextArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayExtensionObject",
                        () => ArrayOf(new ExtensionObject(new Argument()), new ExtensionObject(new Argument())),
                        typeof(ExtensionObject[]),
                        TypeInfo.Arrays.ExtensionObject,
                        nameof(Variant.GetExtensionObjectArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayDataValue",
                        () => ArrayOf(new DataValue(1), new DataValue(2)),
                        typeof(DataValue[]),
                        TypeInfo.Arrays.DataValue,
                        nameof(Variant.GetDataValueArray)));
                yield return CreateDescriptorCase(
                    new VariantDescriptor(
                        "ArrayVariant",
                        () => ArrayOf(new Variant(1), new Variant("two")),
                        typeof(Variant[]),
                        TypeInfo.Arrays.Variant,
                        nameof(Variant.GetVariantArray)));
            }
        }

        [TestCaseSource(nameof(ScalarConstructorCases))]
        public void ScalarConstructor_SetsExpectedTypeInfo(Func<object> valueFactory, TypeInfo expectedTypeInfo)
        {
            object value = valueFactory();
            var variant = new Variant(value);

            AssertTypeInfo(expectedTypeInfo, variant.TypeInfo);
            AssertValueEquality(value, variant.Value);
        }

        [TestCaseSource(nameof(ArrayConstructorCases))]
        public void ArrayConstructor_SetsExpectedTypeInfo(Func<object> valueFactory, TypeInfo expectedTypeInfo)
        {
            object value = valueFactory();
            var variant = new Variant((Array)value);

            AssertTypeInfo(expectedTypeInfo, variant.TypeInfo);
            AssertValueEquality(value, variant.Value);
        }

        [Test]
        public void MultiDimensionalArrayConstructor_BecomesMatrix()
        {
            int[,] data = new int[2, 2]
            {
                { 1, 2 },
                { 3, 4 }
            };
            var variant = new Variant(data);

            Assert.AreEqual(2, variant.TypeInfo.ValueRank);
            Assert.AreEqual(BuiltInType.Int32, variant.TypeInfo.BuiltInType);
            Assert.That(variant.AsBoxedObject(), Is.TypeOf<Matrix>());
            var matrix = (Matrix)variant.Value;
            Assert.That(data.Cast<int>().ToArray(), Is.EquivalentTo(matrix.Elements.Cast<int>().ToArray()));
        }

        [Test]
        public void MatrixConstructor_PreservesMatrixTypeInfo()
        {
            var matrix = new Matrix(ArrayOf(1, 2, 3, 4), BuiltInType.Int32, 2, 2);
            var variant = new Variant(matrix);

            AssertTypeInfo(matrix.TypeInfo, variant.TypeInfo);
            Assert.AreSame(matrix, variant.Value);
        }

        [Test]
        public void ObjectConstructorWithTypeInfo_CoercesEnumerationValue()
        {
            EnumValue value = EnumValue.Two;
            var variant = new Variant(value, TypeInfo.Scalars.Enumeration);

            Assert.AreEqual(BuiltInType.Enumeration, variant.TypeInfo.BuiltInType);
            Assert.That(variant.GetInt32(), Is.EqualTo(Convert.ToInt32(value, CultureInfo.InvariantCulture)));
            Assert.That(variant.GetEnumeration<EnumValue>(), Is.EqualTo(value));
            Assert.That(variant.Value, Is.EqualTo(value));
        }

        [Test]
        public void ArrayConstructorWithTypeInfo_CoercesEnumerationArray()
        {
            EnumValue[] values = [EnumValue.Zero, EnumValue.One];
            TypeInfo typeInfo = TypeInfo.Create(BuiltInType.Enumeration, ValueRanks.OneDimension);
            var variant = new Variant(values, typeInfo);

            Assert.AreEqual(BuiltInType.Enumeration, variant.TypeInfo.BuiltInType);
            Assert.That(variant.Value, Is.EqualTo(values));
            Assert.That(variant.GetEnumerationArray<EnumValue>(), Is.EqualTo(values));
            Assert.That(variant.GetInt32Array(), Is.EqualTo(
                values.Select(v => Convert.ToInt32(v, CultureInfo.InvariantCulture)).ToArray()));
        }

        [Test]
        public void EnumConstructorWithTypeInfo_CoercesEnumerationValue()
        {
            EnumValue value = EnumValue.Two;
            var variant = new Variant(value);

            Assert.AreEqual(BuiltInType.Enumeration, variant.TypeInfo.BuiltInType);
            Assert.That(variant.GetInt32(), Is.EqualTo(Convert.ToInt32(value, CultureInfo.InvariantCulture)));
            Assert.That(variant.GetEnumeration<EnumValue>(), Is.EqualTo(value));
            Assert.That(variant.Value, Is.EqualTo(value));
        }

        [Test]
        public void EnumArrayConstructorWithTypeInfo_CoercesEnumerationArray()
        {
            EnumValue[] values = [EnumValue.Zero, EnumValue.One];
            var variant = Variant.From(values);

            Assert.AreEqual(BuiltInType.Enumeration, variant.TypeInfo.BuiltInType);
            Assert.That(variant.Value, Is.EqualTo(values));
            Assert.That(variant.GetEnumerationArray<EnumValue>(), Is.EqualTo(values));
            Assert.That(variant.GetInt32Array(), Is.EqualTo(
                values.Select(v => Convert.ToInt32(v, CultureInfo.InvariantCulture)).ToArray()));
        }

        [Test]
        public void ObjectArrayConstructorWrapsElementsInVariants()
        {
            object[] values = [1, "two", true];
            var variant = new Variant(values);

            Assert.AreEqual(ValueRanks.OneDimension, variant.TypeInfo.ValueRank);
            Assert.AreEqual(BuiltInType.Variant, variant.TypeInfo.BuiltInType);
            Variant[] stored = variant.GetVariantArray();
            Assert.AreEqual(values.Length, stored.Length);
            Assert.AreEqual(values[0], stored[0].GetInt32());
            Assert.AreEqual(values[1], stored[1].GetString());
            Assert.AreEqual(values[2], stored[2].GetBoolean());
        }

        [Test]
        public void VariantConstructsArrayFromEnumerable()
        {
            IList source = new List<int> { 1, 2, 3 };
            var typeInfo = TypeInfo.Create(BuiltInType.Int32, ValueRanks.OneDimension);
            var variant = new Variant(source, typeInfo);

            AssertTypeInfo(typeInfo, variant.TypeInfo);
            Assert.That(source, Is.EquivalentTo((int[])variant.Value));
        }

        [TestCaseSource(nameof(ScalarDescriptorCases))]
        public void TryGetScalar_Succeeds(VariantDescriptor descriptor)
        {
            var value = descriptor.CreateValue();
            var variant = new Variant(value);
            MethodInfo method = typeof(Variant).GetMethod(nameof(Variant.TryGet), ArrayOf(descriptor.ValueType.MakeByRefType()));
            object[] args = ArrayOf(CreateDefaultValue(descriptor.ValueType));

            Assert.NotNull(method, $"TryGet overload for {descriptor.Name} should exist");
            bool success = (bool)method!.Invoke(variant, args);

            Assert.IsTrue(success);
            AssertValueEquality(value, args[0]);
        }

        [TestCaseSource(nameof(ArrayDescriptorCases))]
        public void TryGetArray_Succeeds(VariantDescriptor descriptor)
        {
            var values = (Array)descriptor.CreateValue();
            var variant = new Variant(values);
            MethodInfo method = typeof(Variant).GetMethod(nameof(Variant.TryGet), ArrayOf(descriptor.ValueType.MakeByRefType()));
            object[] args = ArrayOf(CreateDefaultValue(descriptor.ValueType));

            Assert.NotNull(method, $"TryGet overload for {descriptor.Name} should exist");
            bool success = (bool)method!.Invoke(variant, args);

            Assert.IsTrue(success);
            AssertValueEquality(values, args[0]);
        }

        [TestCaseSource(nameof(ScalarDescriptorCases))]
        public void GetScalar_ReturnsStoredValue(VariantDescriptor descriptor)
        {
            var value = descriptor.CreateValue();
            var variant = new Variant(value);
            MethodInfo method = typeof(Variant).GetMethod(descriptor.GetMethodName, ArrayOf(descriptor.ValueType));
            object[] args = ArrayOf(CreateDefaultValue(descriptor.ValueType));

            Assert.NotNull(method, $"Get method {descriptor.GetMethodName} should exist");
            object result = method!.Invoke(variant, args);
            AssertValueEquality(value, result);
        }

        [TestCaseSource(nameof(ArrayDescriptorCases))]
        public void GetArray_ReturnsStoredValue(VariantDescriptor descriptor)
        {
            var values = (Array)descriptor.CreateValue();
            var variant = new Variant(values);
            MethodInfo method = typeof(Variant).GetMethod(descriptor.GetMethodName, ArrayOf(descriptor.ValueType));
            object[] args = ArrayOf(CreateDefaultValue(descriptor.ValueType));

            Assert.NotNull(method, $"Get method {descriptor.GetMethodName} should exist");
            object result = method!.Invoke(variant, args);
            AssertValueEquality(values, result);
        }

        [TestCaseSource(nameof(ScalarDescriptorCases))]
        public void GetScalar_ReturnsDefaultOnMismatch(VariantDescriptor descriptor)
        {
            object defaultValue = descriptor.CreateValue();
            var variant = new Variant(true);
            MethodInfo method = typeof(Variant).GetMethod(descriptor.GetMethodName, ArrayOf(descriptor.ValueType));
            object[] args = ArrayOf(CloneValue(defaultValue));

            object result = method!.Invoke(variant, args);
            AssertValueEquality(defaultValue, result);
        }

        [TestCaseSource(nameof(ArrayDescriptorCases))]
        public void GetArray_ReturnsDefaultOnMismatch(VariantDescriptor descriptor)
        {
            object defaultValue = descriptor.CreateValue();
            var variant = new Variant(true);
            MethodInfo method = typeof(Variant).GetMethod(descriptor.GetMethodName, ArrayOf(descriptor.ValueType));
            object[] args = ArrayOf(CloneValue(defaultValue));

            object result = method!.Invoke(variant, args);
            AssertValueEquality(defaultValue, result);
        }

        [TestCaseSource(nameof(ScalarDescriptorCases))]
        public void GenericTryGetScalar_Succeeds(VariantDescriptor descriptor)
        {
            var value = descriptor.CreateValue();
            var variant = new Variant(value);
            MethodInfo method = typeof(Variant).GetMethod(nameof(Variant.TryGetScalar))!
                .MakeGenericMethod(descriptor.ValueType);
            object[] args = ArrayOf(CreateDefaultValue(descriptor.ValueType), descriptor.TypeInfo.BuiltInType);

            bool success = (bool)method.Invoke(variant, args);
            Assert.IsTrue(success);
            AssertValueEquality(value, args[0]);
        }

        [TestCaseSource(nameof(ArrayDescriptorCases))]
        public void GenericTryGetArray_Succeeds(VariantDescriptor descriptor)
        {
            var values = (Array)descriptor.CreateValue();
            var variant = new Variant(values);
            Type elementType = descriptor.ValueType.GetElementType() ?? descriptor.ValueType;
            MethodInfo method = typeof(Variant).GetMethod(nameof(Variant.TryGetArray))!
                .MakeGenericMethod(elementType);
            object[] args = ArrayOf(CreateDefaultValue(descriptor.ValueType), descriptor.TypeInfo.BuiltInType);

            bool success = (bool)method.Invoke(variant, args);
            Assert.IsTrue(success);
            AssertValueEquality(values, args[0]);
        }

        [Test]
        public void GenericTryGetScalar_FailsForWrongBuiltInType()
        {
            var variant = new Variant(1);
            MethodInfo method = typeof(Variant).GetMethod(nameof(Variant.TryGetScalar))!
                .MakeGenericMethod(typeof(int));
            object[] args = ArrayOf<object>(0, BuiltInType.String);

            bool success = (bool)method.Invoke(variant, args);
            Assert.IsFalse(success);
        }

        [Test]
        public void GenericTryGetArray_FailsForWrongBuiltInType()
        {
            var variant = new Variant(ArrayOf(1, 2));
            MethodInfo method = typeof(Variant).GetMethod(nameof(Variant.TryGetArray))!
                .MakeGenericMethod(typeof(int));
            object[] args = ArrayOf<object>(null, BuiltInType.String);

            bool success = (bool)method.Invoke(variant, args);
            Assert.IsFalse(success);
        }

        [Test]
        public void TryGetMatrix_ReturnsMatrix()
        {
            var matrix = new Matrix(ArrayOf(1f, 2f, 3f, 4f), BuiltInType.Float, 2, 2);
            var variant = new Variant(matrix);
            object[] args = ArrayOf<object>(null, BuiltInType.Float);
            MethodInfo method = typeof(Variant).GetMethod(nameof(Variant.TryGetMatrix))!
                .MakeGenericMethod(typeof(float));

            bool success = (bool)method.Invoke(variant, args);
            Assert.IsTrue(success);
            Assert.AreSame(matrix, args[0]);
        }

        [Test]
        public void TryGetMatrix_FromArray()
        {
            double[,] data = new double[2, 1]
            {
                { 1.0 },
                { 2.0 }
            };
            var variant = new Variant(data);
            object[] args = ArrayOf<object>(null, BuiltInType.Double);
            MethodInfo method = typeof(Variant).GetMethod(nameof(Variant.TryGetMatrix))!
                .MakeGenericMethod(typeof(double));

            bool success = (bool)method.Invoke(variant, args);
            Assert.IsTrue(success);
            Assert.That(args[0], Is.TypeOf<Matrix>());
        }

        [Test]
        public void VariantEqualsVariant_UsesValueSemantics()
        {
            var first = new Variant(ArrayOf(1, 2));
            var second = new Variant(ArrayOf(1, 2));
            var third = new Variant(ArrayOf(1, 3));

            Assert.IsTrue(first.Equals(second));
            Assert.IsFalse(first.Equals(third));
        }

        [Test]
        public void VariantEqualsVariant_DetectsTypeMismatch()
        {
            var scalar = new Variant(1);
            var floating = new Variant(1.0f);

            Assert.IsFalse(scalar.Equals(floating));
        }

        [Test]
        public void VariantEqualsObject_HandlesNullAndMismatch()
        {
            var variant = new Variant("value");

            Assert.IsTrue(variant.Equals((object)"value"));
            Assert.IsFalse(variant.Equals((object)"other"));
            Assert.IsTrue(Variant.Null.Equals((object)null));
        }

        [Test]
        public void EqualityOperatorWithVariantOperands()
        {
            Variant left = new Variant(ArrayOf(true, false));
            Variant identical = new Variant(ArrayOf(true, false));
            Variant different = new Variant(ArrayOf(false, false));

            Assert.IsTrue(left == identical);
            Assert.IsFalse(left != identical);
            Assert.IsFalse(left == different);
            Assert.IsTrue(left != different);
        }

        [Test]
        public void ImplicitConversionFromObjectArray_WrapsEachElement()
        {
            object[] values = [1, "two", false];
            Variant variant = values;

            Variant[] stored = variant.GetVariantArray();
            Assert.AreEqual(3, stored.Length);
            Assert.AreEqual(1, stored[0].GetInt32());
            Assert.AreEqual("two", stored[1].GetString());
            Assert.AreEqual(false, stored[2].GetBoolean());
        }

        [Test]
        public void ExplicitConversionThrowsOnMismatch()
        {
            var variant = new Variant(5);

            Assert.Throws<InvalidCastException>(() => _ = (string)variant);
        }

        [Test]
        public void StatusCodeTryGetFallsBackToUInt32()
        {
            var variant = new Variant(123u);

            Assert.IsTrue(variant.TryGet(out StatusCode status));
            Assert.AreEqual(new StatusCode(123u), status);
        }

        [Test]
        public void AsBoxedObjectReturnsDefaultForReferenceTypes()
        {
            var variant = new Variant(null, TypeInfo.Scalars.NodeId);

            Assert.That(variant.AsBoxedObject(), Is.EqualTo(NodeId.Null));
        }

        [Test]
        public void VariantNullBehavesAsExpected()
        {
            Assert.IsTrue(Variant.Null.IsNull);
            Assert.IsNull(Variant.Null.Value);
            Assert.AreEqual(0, Variant.Null.GetHashCode());
        }

        [Test]
        public void GetHashCodeMatchesUnderlyingValue()
        {
            var variant = new Variant(42);

            Assert.AreEqual(variant.Value.GetHashCode(), variant.GetHashCode());
        }

        [Test]
        public void ToStringFormatsByteStringAsHex()
        {
            var variant = new Variant(Bytes(0x0A, 0xFF));

            Assert.AreEqual("0AFF", variant.ToString());
        }

        [Test]
        public void ToStringFormatsXmlElementOuterXml()
        {
            XmlElement element = CreateXmlElement("Alpha");
            var variant = new Variant(element);

            Assert.AreEqual(element.OuterXml, variant.ToString());
        }

        [Test]
        public void ToStringFormatsArraysWithSeparators()
        {
            var variant = new Variant(ArrayOf(1, 2, 3));

            Assert.AreEqual("{1|2|3}", variant.ToString());
        }

        [Test]
        public void ToStringRejectsCustomFormats()
        {
            var variant = new Variant(1);

            Assert.Throws<FormatException>(() => variant.ToString("G", null));
        }

        [TestCaseSource(nameof(ScalarDescriptorCases))]
        public void VariantFromScalarProducesEquivalentVariant(VariantDescriptor descriptor)
        {
            var value = descriptor.CreateValue();
            Variant variant = InvokeVariantFrom(value);

            AssertTypeInfo(descriptor.TypeInfo, variant.TypeInfo);
            AssertValueEquality(value, variant.Value);
        }

        [TestCaseSource(nameof(ArrayDescriptorCases))]
        public void VariantFromArrayProducesEquivalentVariant(VariantDescriptor descriptor)
        {
            var value = descriptor.CreateValue();
            Variant variant = InvokeVariantFrom(value);

            AssertTypeInfo(descriptor.TypeInfo, variant.TypeInfo);
            AssertValueEquality(value, variant.Value);
        }

        [Test]
        public void VariantFromObjectArrayCreatesVariantArray()
        {
            object[] values = [1, "two"];
            var variant = Variant.From(values);

            Variant[] stored = variant.GetVariantArray();
            Assert.AreEqual(2, stored.Length);
            Assert.AreEqual(1, stored[0].GetInt32());
            Assert.AreEqual("two", stored[1].GetString());
        }

        /// <summary>
        /// Initialize Variant from uint with StatusCode TypeInfo.
        /// Tests that a Variant created from uint with StatusCode TypeInfo
        /// can be properly cast to StatusCode.
        /// </summary>
        [Test]
        [Explicit]
        public void VariantFromUIntWithStatusCodeTypeInfo()
        {
            // Test scalar StatusCode creation from uint
            uint statusCodeValue = (uint)StatusCodes.Good;
            var variant = new Variant(statusCodeValue, TypeInfo.Scalars.StatusCode);

            Assert.AreEqual(BuiltInType.StatusCode, variant.TypeInfo.BuiltInType);
            Assert.NotNull(variant.Value);

            // Cast the Value to StatusCode
            StatusCode statusCode = (StatusCode)variant.Value;
            Assert.AreEqual(StatusCodes.Good, statusCode.Code);

            // Test with different status code values
            uint badNodeIdValue = (uint)StatusCodes.BadNodeIdInvalid;
            var variant2 = new Variant(badNodeIdValue, TypeInfo.Scalars.StatusCode);

            Assert.AreEqual(BuiltInType.StatusCode, variant2.TypeInfo.BuiltInType);
            StatusCode statusCode2 = (StatusCode)variant2.Value;
            Assert.AreEqual(StatusCodes.BadNodeIdInvalid, statusCode2.Code);

            // Test with custom status code value
            uint customValue = 0x80AB0000;
            var variant3 = new Variant(customValue, TypeInfo.Scalars.StatusCode);

            Assert.AreEqual(BuiltInType.StatusCode, variant3.TypeInfo.BuiltInType);
            StatusCode statusCode3 = (StatusCode)variant3.Value;
            Assert.AreEqual(customValue, statusCode3.Code);
        }

        /// <summary>
        /// Initialize Variant from uint array with StatusCode TypeInfo.
        /// Tests that a Variant created from uint[] with StatusCode TypeInfo
        /// can be properly cast to StatusCode[].
        /// </summary>
        [Test]
        [Explicit]
        public void VariantFromUIntArrayWithStatusCodeTypeInfo()
        {
            // Test array StatusCode creation from uint[]
            uint[] statusCodeValues = [
                (uint)StatusCodes.Good,
                (uint)StatusCodes.BadNodeIdInvalid,
                (uint)StatusCodes.BadUnexpectedError,
                (uint)StatusCodes.BadAttributeIdInvalid
            ];

            var variant = new Variant(statusCodeValues, TypeInfo.Arrays.StatusCode);

            Assert.AreEqual(BuiltInType.StatusCode, variant.TypeInfo.BuiltInType);
            Assert.NotNull(variant.Value);
            Assert.IsTrue(variant.Value is StatusCode[]);

            // Cast the Value to StatusCode array
            StatusCode[] statusCodes = (StatusCode[])variant.Value;
            Assert.AreEqual(statusCodeValues.Length, statusCodes.Length);

            for (int i = 0; i < statusCodeValues.Length; i++)
            {
                Assert.AreEqual(statusCodeValues[i], statusCodes[i].Code);
            }

            // Test empty array
            uint[] emptyArray = [];
            var variant2 = new Variant(emptyArray, TypeInfo.Arrays.StatusCode);

            Assert.AreEqual(BuiltInType.StatusCode, variant2.TypeInfo.BuiltInType);
            StatusCode[] emptyStatusCodes = (StatusCode[])variant2.Value;
            Assert.AreEqual(0, emptyStatusCodes.Length);

            // Test single element array
            uint[] singleElement = [(uint)StatusCodes.BadNodeIdInvalid];
            var variant3 = new Variant(singleElement, TypeInfo.Arrays.StatusCode);

            Assert.AreEqual(BuiltInType.StatusCode, variant3.TypeInfo.BuiltInType);
            StatusCode[] singleStatusCode = (StatusCode[])variant3.Value;
            Assert.AreEqual(1, singleStatusCode.Length);
            Assert.AreEqual(StatusCodes.BadNodeIdInvalid, singleStatusCode[0].Code);
        }

        private static byte[] CreateDifferentByteArray(byte[] bytes)
        {
            if (bytes.Length == 0)
            {
                return Bytes(1);
            }

            byte[] clone = (byte[])bytes.Clone();
            clone[0] = (byte)(clone[0] + 1);
            return clone;
        }

        private static XmlElement CreateDifferentXmlElement(XmlElement element)
        {
            var clone = (XmlElement)element.CloneNode(true);
            clone.InnerText += "Diff";
            return clone;
        }

        private static Variant InvokeVariantFrom(object value)
        {
            MethodInfo method = typeof(Variant).GetMethod(nameof(Variant.From), ArrayOf(value.GetType()))!;
            return (Variant)method.Invoke(null, ArrayOf(value));
        }

        private static T[] ArrayOf<T>(params T[] items)
        {
            return items;
        }

        private static byte[] Bytes(params byte[] values)
        {
            return values;
        }

        private static TestCaseData CreateConstructorCase(string name, Func<object> valueFactory, TypeInfo typeInfo)
        {
            return new TestCaseData(valueFactory, typeInfo).SetName(name);
        }

        private static TestCaseData CreateDescriptorCase(VariantDescriptor descriptor)
        {
            return new TestCaseData(descriptor).SetName(descriptor.Name);
        }

        private static XmlElement CreateXmlElement(string name)
        {
            var document = new XmlDocument();
            XmlElement element = document.CreateElement(name);
            element.InnerText = name;
            return element;
        }

        private static object CreateDefaultValue(Type type)
        {
            if (type.IsValueType)
            {
                return Activator.CreateInstance(type)!;
            }

            return null;
        }

        private static void AssertTypeInfo(TypeInfo expected, TypeInfo actual)
        {
            Assert.AreEqual(expected.BuiltInType, actual.BuiltInType);
            Assert.AreEqual(expected.ValueRank, actual.ValueRank);
        }

        private static object CloneValue(object value)
        {
            if (value is Array array)
            {
                var clone = Array.CreateInstance(array.GetType().GetElementType()!, array.Length);
                for (int i = 0; i < array.Length; i++)
                {
                    clone.SetValue(CloneValue(array.GetValue(i)), i);
                }

                return clone;
            }

            if (value is XmlElement xmlElement)
            {
                return (XmlElement)xmlElement.CloneNode(true);
            }

            if (value is ICloneable cloneable)
            {
                return cloneable.Clone();
            }

            return value;
        }

        private static void AssertValueEquality(object expected, object actual)
        {
            if (expected is null || actual is null)
            {
                Assert.AreEqual(expected, actual);
                return;
            }

            if (expected is Array expectedArray && actual is Array actualArray)
            {
                Assert.AreEqual(expectedArray.Length, actualArray.Length, "Array lengths differ");
                for (int i = 0; i < expectedArray.Length; i++)
                {
                    AssertValueEquality(expectedArray.GetValue(i), actualArray.GetValue(i));
                }

                return;
            }

            if (expected is XmlElement expectedXml && actual is XmlElement actualXml)
            {
                Assert.AreEqual(expectedXml.OuterXml, actualXml.OuterXml);
                return;
            }

            Assert.AreEqual(expected, actual);
        }
    }
}
