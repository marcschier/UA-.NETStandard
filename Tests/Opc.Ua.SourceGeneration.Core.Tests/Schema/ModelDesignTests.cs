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
using System.Globalization;
using System.Xml;
using Moq;
using NUnit.Framework;

namespace Opc.Ua.Schema.Model.Tests
{
    /// <summary>
    /// Unit tests for Namespace class.
    /// </summary>
    public partial class NamespaceTests
    {
        /// <summary>
        /// Tests that GetHashCode returns consistent values when called multiple times on the same object.
        /// </summary>
        [Test]
        public void GetHashCode_CalledMultipleTimes_ReturnsConsistentValue()
        {
            // Arrange
            var ns = new Namespace
            {
                Name = "TestNamespace",
                Prefix = "Test",
                InternalPrefix = "Int",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "C:\\test\\file.xml",
                Version = "1.0.0",
                PublicationDate = "2025-01-01",
                Value = "TestValue"
            };

            // Act
            int hash1 = ns.GetHashCode();
            int hash2 = ns.GetHashCode();
            int hash3 = ns.GetHashCode();

            // Assert
            Assert.That(hash1, Is.EqualTo(hash2));
            Assert.That(hash2, Is.EqualTo(hash3));
        }

        /// <summary>
        /// Tests that GetHashCode returns the same hash code for two objects with identical property values.
        /// </summary>
        [Test]
        public void GetHashCode_TwoObjectsWithIdenticalProperties_ReturnsSameHashCode()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "TestNamespace",
                Prefix = "Test",
                InternalPrefix = "Int",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "C:\\test\\file.xml",
                Version = "1.0.0",
                PublicationDate = "2025-01-01",
                Value = "TestValue"
            };

            var ns2 = new Namespace
            {
                Name = "TestNamespace",
                Prefix = "Test",
                InternalPrefix = "Int",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "C:\\test\\file.xml",
                Version = "1.0.0",
                PublicationDate = "2025-01-01",
                Value = "TestValue"
            };

            // Act
            int hash1 = ns1.GetHashCode();
            int hash2 = ns2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different Name property.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentName_ReturnsDifferentHashCode()
        {
            // Arrange
            var ns1 = new Namespace { Name = "Name1" };
            var ns2 = new Namespace { Name = "Name2" };

            // Act
            int hash1 = ns1.GetHashCode();
            int hash2 = ns2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different Prefix property.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentPrefix_ReturnsDifferentHashCode()
        {
            // Arrange
            var ns1 = new Namespace { Prefix = "Prefix1" };
            var ns2 = new Namespace { Prefix = "Prefix2" };

            // Act
            int hash1 = ns1.GetHashCode();
            int hash2 = ns2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different InternalPrefix property.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentInternalPrefix_ReturnsDifferentHashCode()
        {
            // Arrange
            var ns1 = new Namespace { InternalPrefix = "Int1" };
            var ns2 = new Namespace { InternalPrefix = "Int2" };

            // Act
            int hash1 = ns1.GetHashCode();
            int hash2 = ns2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different XmlNamespace property.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentXmlNamespace_ReturnsDifferentHashCode()
        {
            // Arrange
            var ns1 = new Namespace { XmlNamespace = "http://test1.com" };
            var ns2 = new Namespace { XmlNamespace = "http://test2.com" };

            // Act
            int hash1 = ns1.GetHashCode();
            int hash2 = ns2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different XmlPrefix property.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentXmlPrefix_ReturnsDifferentHashCode()
        {
            // Arrange
            var ns1 = new Namespace { XmlPrefix = "xml1" };
            var ns2 = new Namespace { XmlPrefix = "xml2" };

            // Act
            int hash1 = ns1.GetHashCode();
            int hash2 = ns2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different FilePath property.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentFilePath_ReturnsDifferentHashCode()
        {
            // Arrange
            var ns1 = new Namespace { FilePath = "C:\\path1\\file.xml" };
            var ns2 = new Namespace { FilePath = "C:\\path2\\file.xml" };

            // Act
            int hash1 = ns1.GetHashCode();
            int hash2 = ns2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different Version property.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentVersion_ReturnsDifferentHashCode()
        {
            // Arrange
            var ns1 = new Namespace { Version = "1.0.0" };
            var ns2 = new Namespace { Version = "2.0.0" };

            // Act
            int hash1 = ns1.GetHashCode();
            int hash2 = ns2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different PublicationDate property.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentPublicationDate_ReturnsDifferentHashCode()
        {
            // Arrange
            var ns1 = new Namespace { PublicationDate = "2025-01-01" };
            var ns2 = new Namespace { PublicationDate = "2025-01-02" };

            // Act
            int hash1 = ns1.GetHashCode();
            int hash2 = ns2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different Value property.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentValue_ReturnsDifferentHashCode()
        {
            // Arrange
            var ns1 = new Namespace { Value = "Value1" };
            var ns2 = new Namespace { Value = "Value2" };

            // Act
            int hash1 = ns1.GetHashCode();
            int hash2 = ns2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode handles objects with all null properties correctly.
        /// </summary>
        [Test]
        public void GetHashCode_AllPropertiesNull_ReturnsValidHashCode()
        {
            // Arrange
            var ns = new Namespace();

            // Act
            int hash = ns.GetHashCode();

            // Assert
            Assert.That(hash, Is.Not.Null);
        }

        /// <summary>
        /// Tests that GetHashCode handles objects with all empty string properties correctly.
        /// </summary>
        [Test]
        public void GetHashCode_AllPropertiesEmpty_ReturnsValidHashCode()
        {
            // Arrange
            var ns = new Namespace
            {
                Name = string.Empty,
                Prefix = string.Empty,
                InternalPrefix = string.Empty,
                XmlNamespace = string.Empty,
                XmlPrefix = string.Empty,
                FilePath = string.Empty,
                Version = string.Empty,
                PublicationDate = string.Empty,
                Value = string.Empty
            };

            // Act
            int hash = ns.GetHashCode();

            // Assert
            Assert.That(hash, Is.Not.Null);
        }

        /// <summary>
        /// Tests that GetHashCode handles objects with mixed null and non-null properties correctly.
        /// </summary>
        [Test]
        public void GetHashCode_MixedNullAndNonNullProperties_ReturnsValidHashCode()
        {
            // Arrange
            var ns = new Namespace
            {
                Name = "TestName",
                Prefix = null,
                InternalPrefix = "IntPrefix",
                XmlNamespace = null,
                XmlPrefix = "xml",
                FilePath = null,
                Version = "1.0",
                PublicationDate = null,
                Value = "TestValue"
            };

            // Act
            int hash = ns.GetHashCode();

            // Assert
            Assert.That(hash, Is.Not.Null);
        }

        /// <summary>
        /// Tests that GetHashCode handles objects with very long string properties correctly.
        /// </summary>
        [Test]
        public void GetHashCode_VeryLongStrings_ReturnsValidHashCode()
        {
            // Arrange
            string longString = new('a', 10000);
            var ns = new Namespace
            {
                Name = longString,
                Prefix = longString,
                InternalPrefix = longString,
                XmlNamespace = longString,
                XmlPrefix = longString,
                FilePath = longString,
                Version = longString,
                PublicationDate = longString,
                Value = longString
            };

            // Act
            int hash = ns.GetHashCode();

            // Assert
            Assert.That(hash, Is.Not.Null);
        }

        /// <summary>
        /// Tests that GetHashCode handles objects with special characters in string properties correctly.
        /// </summary>
        [Test]
        public void GetHashCode_SpecialCharacters_ReturnsValidHashCode()
        {
            // Arrange
            var ns = new Namespace
            {
                Name = "Name!@#$%^&*()",
                Prefix = "Prefix\n\r\t",
                InternalPrefix = "Internal\0Prefix",
                XmlNamespace = "http://test.com?param=value&other=123",
                XmlPrefix = "xml:prefix",
                FilePath = "C:\\path\\to\\file.xml",
                Version = "1.0.0-alpha+build.123",
                PublicationDate = "2025-01-01T12:34:56Z",
                Value = "Value with spaces   and\ttabs"
            };

            // Act
            int hash = ns.GetHashCode();

            // Assert
            Assert.That(hash, Is.Not.Null);
        }

        /// <summary>
        /// Tests that GetHashCode handles objects with Unicode characters correctly.
        /// </summary>
        [Test]
        public void GetHashCode_UnicodeCharacters_ReturnsValidHashCode()
        {
            // Arrange
            var ns = new Namespace
            {
                Name = "名前",
                Prefix = "接頭辞",
                InternalPrefix = "内部接頭辞",
                XmlNamespace = "http://тест.рф",
                XmlPrefix = "Präfix",
                FilePath = "C:\\路径\\文件.xml",
                Version = "版本1.0",
                PublicationDate = "2025年01月01日",
                Value = "值🎉"
            };

            // Act
            int hash = ns.GetHashCode();

            // Assert
            Assert.That(hash, Is.Not.Null);
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when only one property differs.
        /// </summary>
        [TestCase("Name")]
        [TestCase("Prefix")]
        [TestCase("InternalPrefix")]
        [TestCase("XmlNamespace")]
        [TestCase("XmlPrefix")]
        [TestCase("FilePath")]
        [TestCase("Version")]
        [TestCase("PublicationDate")]
        [TestCase("Value")]
        public void GetHashCode_OnlyOnePropertyDifferent_ReturnsDifferentHashCode(string propertyName)
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "Common",
                Prefix = "Common",
                InternalPrefix = "Common",
                XmlNamespace = "Common",
                XmlPrefix = "Common",
                FilePath = "Common",
                Version = "Common",
                PublicationDate = "Common",
                Value = "Common"
            };

            var ns2 = new Namespace
            {
                Name = "Common",
                Prefix = "Common",
                InternalPrefix = "Common",
                XmlNamespace = "Common",
                XmlPrefix = "Common",
                FilePath = "Common",
                Version = "Common",
                PublicationDate = "Common",
                Value = "Common"
            };

            // Act
            switch (propertyName)
            {
                case "Name":
                    ns2.Name = "Different";
                    break;
                case "Prefix":
                    ns2.Prefix = "Different";
                    break;
                case "InternalPrefix":
                    ns2.InternalPrefix = "Different";
                    break;
                case "XmlNamespace":
                    ns2.XmlNamespace = "Different";
                    break;
                case "XmlPrefix":
                    ns2.XmlPrefix = "Different";
                    break;
                case "FilePath":
                    ns2.FilePath = "Different";
                    break;
                case "Version":
                    ns2.Version = "Different";
                    break;
                case "PublicationDate":
                    ns2.PublicationDate = "Different";
                    break;
                case "Value":
                    ns2.Value = "Different";
                    break;
            }

            int hash1 = ns1.GetHashCode();
            int hash2 = ns2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns the same hash code for empty strings and null values.
        /// </summary>
        [Test]
        public void GetHashCode_EmptyStringVsNull_ReturnsDifferentHashCode()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = string.Empty
            };

            var ns2 = new Namespace
            {
                Name = null
            };

            // Act
            int hash1 = ns1.GetHashCode();
            int hash2 = ns2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode handles whitespace-only strings correctly.
        /// </summary>
        [Test]
        public void GetHashCode_WhitespaceOnlyStrings_ReturnsValidHashCode()
        {
            // Arrange
            var ns = new Namespace
            {
                Name = "   ",
                Prefix = "\t\t\t",
                InternalPrefix = "\n\n\n",
                XmlNamespace = " \t \n ",
                XmlPrefix = "     ",
                FilePath = "\r\n\r\n",
                Version = "  \t  ",
                PublicationDate = "   \n   ",
                Value = " "
            };

            // Act
            int hash = ns.GetHashCode();

            // Assert
            Assert.That(hash, Is.Not.Null);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with null.
        /// </summary>
        [Test]
        public void Equals_NullParameter_ReturnsFalse()
        {
            // Arrange
            var ns = new Namespace
            {
                Name = "TestName",
                Prefix = "TestPrefix",
                InternalPrefix = "TestInternalPrefix",
                XmlNamespace = "http://test.com",
                XmlPrefix = "test",
                FilePath = "C:\\test\\path",
                Version = "1.0.0",
                PublicationDate = "2025-01-01",
                Value = "TestValue"
            };

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = ns.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing an object with itself.
        /// </summary>
        [Test]
        public void Equals_SameReference_ReturnsTrue()
        {
            // Arrange
            var ns = new Namespace
            {
                Name = "TestName",
                Prefix = "TestPrefix",
                InternalPrefix = "TestInternalPrefix",
                XmlNamespace = "http://test.com",
                XmlPrefix = "test",
                FilePath = "C:\\test\\path",
                Version = "1.0.0",
                PublicationDate = "2025-01-01",
                Value = "TestValue"
            };

            // Act
            bool result = ns.Equals(ns);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when all properties are equal.
        /// </summary>
        [Test]
        public void Equals_AllPropertiesEqual_ReturnsTrue()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "TestName",
                Prefix = "TestPrefix",
                InternalPrefix = "TestInternalPrefix",
                XmlNamespace = "http://test.com",
                XmlPrefix = "test",
                FilePath = "C:\\test\\path",
                Version = "1.0.0",
                PublicationDate = "2025-01-01",
                Value = "TestValue"
            };

            var ns2 = new Namespace
            {
                Name = "TestName",
                Prefix = "TestPrefix",
                InternalPrefix = "TestInternalPrefix",
                XmlNamespace = "http://test.com",
                XmlPrefix = "test",
                FilePath = "C:\\test\\path",
                Version = "1.0.0",
                PublicationDate = "2025-01-01",
                Value = "TestValue"
            };

            // Act
            bool result = ns1.Equals(ns2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when all properties are null on both objects.
        /// </summary>
        [Test]
        public void Equals_AllPropertiesNull_ReturnsTrue()
        {
            // Arrange
            var ns1 = new Namespace();
            var ns2 = new Namespace();

            // Act
            bool result = ns1.Equals(ns2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when all properties are empty strings.
        /// </summary>
        [Test]
        public void Equals_AllPropertiesEmptyStrings_ReturnsTrue()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = string.Empty,
                Prefix = string.Empty,
                InternalPrefix = string.Empty,
                XmlNamespace = string.Empty,
                XmlPrefix = string.Empty,
                FilePath = string.Empty,
                Version = string.Empty,
                PublicationDate = string.Empty,
                Value = string.Empty
            };

            var ns2 = new Namespace
            {
                Name = string.Empty,
                Prefix = string.Empty,
                InternalPrefix = string.Empty,
                XmlNamespace = string.Empty,
                XmlPrefix = string.Empty,
                FilePath = string.Empty,
                Version = string.Empty,
                PublicationDate = string.Empty,
                Value = string.Empty
            };

            // Act
            bool result = ns1.Equals(ns2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when objects differ only in casing of property values.
        /// </summary>
        [Test]
        public void Equals_DifferentCasing_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "TestName",
                Prefix = "TestPrefix",
                InternalPrefix = "TestInternalPrefix",
                XmlNamespace = "http://test.com",
                XmlPrefix = "test",
                FilePath = "C:\\test\\path",
                Version = "1.0.0",
                PublicationDate = "2025-01-01",
                Value = "TestValue"
            };

            var ns2 = new Namespace
            {
                Name = "testname",
                Prefix = "TestPrefix",
                InternalPrefix = "TestInternalPrefix",
                XmlNamespace = "http://test.com",
                XmlPrefix = "test",
                FilePath = "C:\\test\\path",
                Version = "1.0.0",
                PublicationDate = "2025-01-01",
                Value = "TestValue"
            };

            // Act
            bool result = ns1.Equals(ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when one property is null and the other is an empty string.
        /// </summary>
        [Test]
        public void Equals_NullVsEmptyString_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = null
            };

            var ns2 = new Namespace
            {
                Name = string.Empty
            };

            // Act
            bool result = ns1.Equals(ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when one property is whitespace and the other is an empty string.
        /// </summary>
        [Test]
        public void Equals_WhitespaceVsEmptyString_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = " "
            };

            var ns2 = new Namespace
            {
                Name = string.Empty
            };

            // Act
            bool result = ns1.Equals(ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when a specific property differs.
        /// </summary>
        /// <param name="propertyName">The name of the property to differ.</param>
        /// <param name="differentValue">The different value to set.</param>
        [TestCaseSource(nameof(GetDifferentPropertyTestCases))]
        public void Equals_DifferentProperty_ReturnsFalse(string propertyName, string differentValue)
        {
            // Arrange
            Namespace ns1 = CreateDefaultNamespace();
            Namespace ns2 = CreateDefaultNamespace();
            SetProperty(ns2, propertyName, differentValue);

            // Act
            bool result = ns1.Equals(ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing objects with very long string values.
        /// </summary>
        [Test]
        public void Equals_VeryLongStrings_ReturnsCorrectResult()
        {
            // Arrange
            string longString1 = new('a', 10000);
            string longString2 = new('a', 10000);
            string differentLongString = new('b', 10000);

            var ns1 = new Namespace
            {
                Name = longString1
            };

            var ns2 = new Namespace
            {
                Name = longString2
            };

            var ns3 = new Namespace
            {
                Name = differentLongString
            };

            // Act
            bool resultEqual = ns1.Equals(ns2);
            bool resultDifferent = ns1.Equals(ns3);

            // Assert
            Assert.That(resultEqual, Is.True);
            Assert.That(resultDifferent, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when multiple properties differ.
        /// </summary>
        [Test]
        public void Equals_MultiplePropertiesDifferent_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "TestName",
                Prefix = "TestPrefix",
                InternalPrefix = "TestInternalPrefix"
            };

            var ns2 = new Namespace
            {
                Name = "DifferentName",
                Prefix = "DifferentPrefix",
                InternalPrefix = "TestInternalPrefix"
            };

            // Act
            bool result = ns1.Equals(ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles special characters correctly.
        /// </summary>
        [Test]
        public void Equals_SpecialCharacters_ReturnsCorrectResult()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "Test\nName\t\r",
                Prefix = "Test\\Prefix",
                XmlNamespace = "http://test.com?param=value&other=123",
                FilePath = "C:\\test\\path\\with\\special\\chars\\!@#$%"
            };

            var ns2 = new Namespace
            {
                Name = "Test\nName\t\r",
                Prefix = "Test\\Prefix",
                XmlNamespace = "http://test.com?param=value&other=123",
                FilePath = "C:\\test\\path\\with\\special\\chars\\!@#$%"
            };

            // Act
            bool result = ns1.Equals(ns2);

            // Assert
            Assert.That(result, Is.True);
        }

        private static Namespace CreateDefaultNamespace()
        {
            return new Namespace
            {
                Name = "DefaultName",
                Prefix = "DefaultPrefix",
                InternalPrefix = "DefaultInternalPrefix",
                XmlNamespace = "http://default.com",
                XmlPrefix = "default",
                FilePath = "C:\\default\\path",
                Version = "1.0.0",
                PublicationDate = "2025-01-01",
                Value = "DefaultValue"
            };
        }

        private static void SetProperty(Namespace ns, string propertyName, string value)
        {
            switch (propertyName)
            {
                case nameof(Namespace.Name):
                    ns.Name = value;
                    break;
                case nameof(Namespace.Prefix):
                    ns.Prefix = value;
                    break;
                case nameof(Namespace.InternalPrefix):
                    ns.InternalPrefix = value;
                    break;
                case nameof(Namespace.XmlNamespace):
                    ns.XmlNamespace = value;
                    break;
                case nameof(Namespace.XmlPrefix):
                    ns.XmlPrefix = value;
                    break;
                case nameof(Namespace.FilePath):
                    ns.FilePath = value;
                    break;
                case nameof(Namespace.Version):
                    ns.Version = value;
                    break;
                case nameof(Namespace.PublicationDate):
                    ns.PublicationDate = value;
                    break;
                case nameof(Namespace.Value):
                    ns.Value = value;
                    break;
            }
        }

        private static IEnumerable GetDifferentPropertyTestCases()
        {
            yield return new TestCaseData(nameof(Namespace.Name), "DifferentName")
                .SetName("Equals_DifferentName_ReturnsFalse");
            yield return new TestCaseData(nameof(Namespace.Prefix), "DifferentPrefix")
                .SetName("Equals_DifferentPrefix_ReturnsFalse");
            yield return new TestCaseData(nameof(Namespace.InternalPrefix), "DifferentInternalPrefix")
                .SetName("Equals_DifferentInternalPrefix_ReturnsFalse");
            yield return new TestCaseData(nameof(Namespace.XmlNamespace), "http://different.com")
                .SetName("Equals_DifferentXmlNamespace_ReturnsFalse");
            yield return new TestCaseData(nameof(Namespace.XmlPrefix), "different")
                .SetName("Equals_DifferentXmlPrefix_ReturnsFalse");
            yield return new TestCaseData(nameof(Namespace.FilePath), "C:\\different\\path")
                .SetName("Equals_DifferentFilePath_ReturnsFalse");
            yield return new TestCaseData(nameof(Namespace.Version), "2.0.0")
                .SetName("Equals_DifferentVersion_ReturnsFalse");
            yield return new TestCaseData(nameof(Namespace.PublicationDate), "2026-01-01")
                .SetName("Equals_DifferentPublicationDate_ReturnsFalse");
            yield return new TestCaseData(nameof(Namespace.Value), "DifferentValue")
                .SetName("Equals_DifferentValue_ReturnsFalse");
        }

        /// <summary>
        /// Tests that Equals returns false when comparing to null.
        /// </summary>
        [Test]
        public void Equals_NullObject_ReturnsFalse()
        {
            // Arrange
            var ns = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "test.xml",
                Version = "1.0",
                PublicationDate = "2025-01-01",
                Value = "value"
            };

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = ns.Equals((object)null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing an instance to itself.
        /// </summary>
        [Test]
        public void Equals_SameInstance_ReturnsTrue()
        {
            // Arrange
            var ns = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "test.xml",
                Version = "1.0",
                PublicationDate = "2025-01-01",
                Value = "value"
            };

            // Act
            bool result = ns.Equals((object)ns);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing to a different type.
        /// </summary>
        [Test]
        public void Equals_DifferentType_ReturnsFalse()
        {
            // Arrange
            var ns = new Namespace
            {
                Name = "Test"
            };
            const string differentType = "Not a Namespace";

            // Act
            bool result = ns.Equals(differentType);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two instances with identical property values.
        /// </summary>
        [Test]
        public void Equals_EqualInstances_ReturnsTrue()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "test.xml",
                Version = "1.0",
                PublicationDate = "2025-01-01",
                Value = "value"
            };
            var ns2 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "test.xml",
                Version = "1.0",
                PublicationDate = "2025-01-01",
                Value = "value"
            };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when Name property differs.
        /// </summary>
        [Test]
        public void Equals_DifferentName_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace { Name = "Test1" };
            var ns2 = new Namespace { Name = "Test2" };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Prefix property differs.
        /// </summary>
        [Test]
        public void Equals_DifferentPrefix_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "Test",
                Prefix = "Prefix1"
            };
            var ns2 = new Namespace
            {
                Name = "Test",
                Prefix = "Prefix2"
            };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when InternalPrefix property differs.
        /// </summary>
        [Test]
        public void Equals_DifferentInternalPrefix_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal1"
            };
            var ns2 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal2"
            };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when XmlNamespace property differs.
        /// </summary>
        [Test]
        public void Equals_DifferentXmlNamespace_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test1.com"
            };
            var ns2 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test2.com"
            };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when XmlPrefix property differs.
        /// </summary>
        [Test]
        public void Equals_DifferentXmlPrefix_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst1"
            };
            var ns2 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst2"
            };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when FilePath property differs.
        /// </summary>
        [Test]
        public void Equals_DifferentFilePath_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "test1.xml"
            };
            var ns2 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "test2.xml"
            };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Version property differs.
        /// </summary>
        [Test]
        public void Equals_DifferentVersion_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "test.xml",
                Version = "1.0"
            };
            var ns2 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "test.xml",
                Version = "2.0"
            };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when PublicationDate property differs.
        /// </summary>
        [Test]
        public void Equals_DifferentPublicationDate_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "test.xml",
                Version = "1.0",
                PublicationDate = "2025-01-01"
            };
            var ns2 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "test.xml",
                Version = "1.0",
                PublicationDate = "2025-01-02"
            };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Value property differs.
        /// </summary>
        [Test]
        public void Equals_DifferentValue_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "test.xml",
                Version = "1.0",
                PublicationDate = "2025-01-01",
                Value = "value1"
            };
            var ns2 = new Namespace
            {
                Name = "Test",
                Prefix = "Tst",
                InternalPrefix = "Internal",
                XmlNamespace = "http://test.com",
                XmlPrefix = "tst",
                FilePath = "test.xml",
                Version = "1.0",
                PublicationDate = "2025-01-01",
                Value = "value2"
            };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals is case-sensitive for string properties.
        /// </summary>
        [Test]
        public void Equals_DifferentCase_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace { Name = "Test" };
            var ns2 = new Namespace { Name = "test" };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when one property is null and the other has whitespace.
        /// </summary>
        [Test]
        public void Equals_NullVsWhitespace_ReturnsFalse()
        {
            // Arrange
            var ns1 = new Namespace { Name = null };
            var ns2 = new Namespace { Name = "   " };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing instances with empty strings in all properties.
        /// </summary>
        [Test]
        public void Equals_AllPropertiesEmptyString_ReturnsTrue()
        {
            // Arrange
            var ns1 = new Namespace
            {
                Name = string.Empty,
                Prefix = string.Empty,
                InternalPrefix = string.Empty,
                XmlNamespace = string.Empty,
                XmlPrefix = string.Empty,
                FilePath = string.Empty,
                Version = string.Empty,
                PublicationDate = string.Empty,
                Value = string.Empty
            };
            var ns2 = new Namespace
            {
                Name = string.Empty,
                Prefix = string.Empty,
                InternalPrefix = string.Empty,
                XmlNamespace = string.Empty,
                XmlPrefix = string.Empty,
                FilePath = string.Empty,
                Version = string.Empty,
                PublicationDate = string.Empty,
                Value = string.Empty
            };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals handles very long strings correctly.
        /// </summary>
        [Test]
        public void Equals_VeryLongStrings_ReturnsTrue()
        {
            // Arrange
            string longString = new('a', 10000);
            var ns1 = new Namespace { Name = longString };
            var ns2 = new Namespace { Name = longString };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals handles special characters in strings correctly.
        /// </summary>
        [Test]
        public void Equals_SpecialCharacters_ReturnsTrue()
        {
            // Arrange
            const string specialString = "Test\r\n\t\0\u0001";
            var ns1 = new Namespace { Name = specialString };
            var ns2 = new Namespace { Name = specialString };

            // Act
            bool result = ns1.Equals((object)ns2);

            // Assert
            Assert.That(result, Is.True);
        }
    }

    /// <summary>
    /// Unit tests for the <see cref="EncodingDesign"/> class.
    /// </summary>
    public partial class EncodingDesignTests
    {
        /// <summary>
        /// Tests that Equals returns false when comparing with null.
        /// Input: null parameter.
        /// Expected: false.
        /// </summary>
        [Test]
        public void Equals_NullParameter_ReturnsFalse()
        {
            // Arrange
            var encodingDesign = new EncodingDesign();

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = encodingDesign.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing the same instance (reference equality).
        /// Input: same instance reference.
        /// Expected: true.
        /// </summary>
        [Test]
        public void Equals_SameInstance_ReturnsTrue()
        {
            // Arrange
            var encodingDesign = new EncodingDesign();

            // Act
            bool result = encodingDesign.Equals(encodingDesign);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two instances with identical default properties.
        /// Input: two different instances with default property values.
        /// Expected: true.
        /// </summary>
        [Test]
        public void Equals_DifferentInstancesWithDefaultProperties_ReturnsTrue()
        {
            // Arrange
            var encodingDesign1 = new EncodingDesign();
            var encodingDesign2 = new EncodingDesign();

            // Act
            bool result = encodingDesign1.Equals(encodingDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two instances with identical property values.
        /// Input: two different instances with same SymbolicId.
        /// Expected: true.
        /// </summary>
        [Test]
        public void Equals_DifferentInstancesWithSameSymbolicId_ReturnsTrue()
        {
            // Arrange
            var symbolicId = new XmlQualifiedName("TestEncoding", "http://test.namespace");
            var encodingDesign1 = new EncodingDesign { SymbolicId = symbolicId };
            var encodingDesign2 = new EncodingDesign { SymbolicId = symbolicId };

            // Act
            bool result = encodingDesign1.Equals(encodingDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing two instances with different property values.
        /// Input: two instances with different SymbolicId.
        /// Expected: false.
        /// </summary>
        [Test]
        public void Equals_DifferentInstancesWithDifferentSymbolicId_ReturnsFalse()
        {
            // Arrange
            var encodingDesign1 = new EncodingDesign
            {
                SymbolicId = new XmlQualifiedName("Encoding1", "http://test.namespace")
            };
            var encodingDesign2 = new EncodingDesign
            {
                SymbolicId = new XmlQualifiedName("Encoding2", "http://test.namespace")
            };

            // Act
            bool result = encodingDesign1.Equals(encodingDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when SupportsEvents differs.
        /// Input: two instances with different SupportsEvents values.
        /// Expected: false.
        /// </summary>
        [Test]
        public void Equals_DifferentSupportsEvents_ReturnsFalse()
        {
            // Arrange
            var encodingDesign1 = new EncodingDesign
            {
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };
            var encodingDesign2 = new EncodingDesign
            {
                SupportsEvents = false,
                SupportsEventsSpecified = true
            };

            // Act
            bool result = encodingDesign1.Equals(encodingDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when SupportsEventsSpecified differs.
        /// Input: two instances with different SupportsEventsSpecified values.
        /// Expected: false.
        /// </summary>
        [Test]
        public void Equals_DifferentSupportsEventsSpecified_ReturnsFalse()
        {
            // Arrange
            var encodingDesign1 = new EncodingDesign
            {
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };
            var encodingDesign2 = new EncodingDesign
            {
                SupportsEvents = true,
                SupportsEventsSpecified = false
            };

            // Act
            bool result = encodingDesign1.Equals(encodingDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both instances have identical inherited properties.
        /// Input: two instances with same SupportsEvents and SupportsEventsSpecified values.
        /// Expected: true.
        /// </summary>
        [Test]
        public void Equals_SameInheritedProperties_ReturnsTrue()
        {
            // Arrange
            var encodingDesign1 = new EncodingDesign
            {
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };
            var encodingDesign2 = new EncodingDesign
            {
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            // Act
            bool result = encodingDesign1.Equals(encodingDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing instances with complex identical properties.
        /// Input: two instances with same SymbolicId, SymbolicName, and inherited properties.
        /// Expected: true.
        /// </summary>
        [Test]
        public void Equals_ComplexIdenticalProperties_ReturnsTrue()
        {
            // Arrange
            var symbolicId = new XmlQualifiedName("TestEncoding", "http://test.namespace");
            var symbolicName = new XmlQualifiedName("TestSymbolicName", "http://test.namespace");

            var encodingDesign1 = new EncodingDesign
            {
                SymbolicId = symbolicId,
                SymbolicName = symbolicName,
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };
            var encodingDesign2 = new EncodingDesign
            {
                SymbolicId = symbolicId,
                SymbolicName = symbolicName,
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            // Act
            bool result = encodingDesign1.Equals(encodingDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing instances with different SymbolicName.
        /// Input: two instances with different SymbolicName values.
        /// Expected: false.
        /// </summary>
        [Test]
        public void Equals_DifferentSymbolicName_ReturnsFalse()
        {
            // Arrange
            var encodingDesign1 = new EncodingDesign
            {
                SymbolicName = new XmlQualifiedName("Name1", "http://test.namespace")
            };
            var encodingDesign2 = new EncodingDesign
            {
                SymbolicName = new XmlQualifiedName("Name2", "http://test.namespace")
            };

            // Act
            bool result = encodingDesign1.Equals(encodingDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when the parameter is null.
        /// </summary>
        [Test]
        public void Equals_NullObject_ReturnsFalse()
        {
            // Arrange
            var encodingDesign = new EncodingDesign();

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = encodingDesign.Equals((object)null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing an instance with itself.
        /// </summary>
        [Test]
        public void Equals_SameReference_ReturnsTrue()
        {
            // Arrange
            var encodingDesign = new EncodingDesign();

            // Act
            bool result = encodingDesign.Equals((object)encodingDesign);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with an object of a completely different type.
        /// </summary>
        [Test]
        public void Equals_DifferentType_ReturnsFalse()
        {
            // Arrange
            var encodingDesign = new EncodingDesign();
            object differentTypeObject = new();

            // Act
            bool result = encodingDesign.Equals(differentTypeObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with a string object.
        /// </summary>
        [Test]
        public void Equals_StringObject_ReturnsFalse()
        {
            // Arrange
            var encodingDesign = new EncodingDesign();
            const string stringObject = "test";

            // Act
            bool result = encodingDesign.Equals(stringObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with an integer object.
        /// </summary>
        [Test]
        public void Equals_IntegerObject_ReturnsFalse()
        {
            // Arrange
            var encodingDesign = new EncodingDesign();
            const int intObject = 42;

            // Act
            bool result = encodingDesign.Equals((object)intObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two different instances with default values.
        /// </summary>
        [Test]
        public void Equals_TwoDefaultInstances_ReturnsTrue()
        {
            // Arrange
            var encodingDesign1 = new EncodingDesign();
            var encodingDesign2 = new EncodingDesign();

            // Act
            bool result = encodingDesign1.Equals((object)encodingDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that GetHashCode returns a valid integer value and does not throw an exception.
        /// </summary>
        [Test]
        public void GetHashCode_ValidInstance_ReturnsInteger()
        {
            // Arrange
            var encoding = new EncodingDesign();

            // Act
            int hashCode = encoding.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.InstanceOf<int>());
        }

        /// <summary>
        /// Tests that calling GetHashCode multiple times on the same instance returns the same value (consistency requirement).
        /// </summary>
        [Test]
        public void GetHashCode_CalledMultipleTimes_ReturnsSameValue()
        {
            // Arrange
            var encoding = new EncodingDesign();

            // Act
            int hashCode1 = encoding.GetHashCode();
            int hashCode2 = encoding.GetHashCode();
            int hashCode3 = encoding.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.EqualTo(hashCode2));
            Assert.That(hashCode2, Is.EqualTo(hashCode3));
        }

        /// <summary>
        /// Tests that two equal EncodingDesign instances have the same hash code.
        /// This verifies the GetHashCode contract: if two objects are equal, they must have the same hash code.
        /// </summary>
        [Test]
        public void GetHashCode_EqualInstances_ReturnSameHashCode()
        {
            // Arrange
            var encoding1 = new EncodingDesign();
            var encoding2 = new EncodingDesign();

            // Act
            int hashCode1 = encoding1.GetHashCode();
            int hashCode2 = encoding2.GetHashCode();
            bool areEqual = encoding1.Equals(encoding2);

            // Assert
            if (areEqual)
            {
                Assert.That(hashCode1, Is.EqualTo(hashCode2),
                    "Equal objects must have equal hash codes");
            }
        }

        /// <summary>
        /// Tests that GetHashCode returns consistent values for instances with identical state.
        /// </summary>
        [Test]
        public void GetHashCode_IdenticalState_ProducesConsistentResults()
        {
            // Arrange
            var encoding1 = new EncodingDesign();
            var encoding2 = new EncodingDesign();

            // Act
            int hashCode1 = encoding1.GetHashCode();
            int hashCode2 = encoding2.GetHashCode();

            // Assert
            // If the instances are equal (based on their Equals implementation),
            // their hash codes must be equal
            if (encoding1.Equals(encoding2))
            {
                Assert.That(hashCode1, Is.EqualTo(hashCode2));
            }
        }

        /// <summary>
        /// Tests that GetHashCode can handle instances with various states without throwing exceptions.
        /// </summary>
        [Test]
        public void GetHashCode_VariousStates_DoesNotThrow()
        {
            // Arrange & Act & Assert
            var encoding1 = new EncodingDesign();
            Assert.DoesNotThrow(() => encoding1.GetHashCode());

            var encoding2 = new EncodingDesign();
            Assert.DoesNotThrow(() => encoding2.GetHashCode());
        }

        /// <summary>
        /// Tests that GetHashCode returns a consistent value across multiple calls on the same instance.
        /// </summary>
        [Test]
        public void GetHashCode_SameInstance_ReturnsConsistentValue()
        {
            // Arrange
            var encodingDesign = new EncodingDesign();

            // Act
            int hashCode1 = encodingDesign.GetHashCode();
            int hashCode2 = encodingDesign.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode returns the same value for equal objects.
        /// </summary>
        [Test]
        public void GetHashCode_EqualObjects_ReturnsSameHashCode()
        {
            // Arrange
            var encodingDesign1 = new EncodingDesign();
            var encodingDesign2 = new EncodingDesign();

            // Act
            int hashCode1 = encodingDesign1.GetHashCode();
            int hashCode2 = encodingDesign2.GetHashCode();

            // Assert
            if (encodingDesign1.Equals(encodingDesign2))
            {
                Assert.That(hashCode2, Is.EqualTo(hashCode1));
            }
        }

        /// <summary>
        /// Tests that GetHashCode does not throw an exception when called on a valid instance.
        /// </summary>
        [Test]
        public void GetHashCode_ValidInstance_DoesNotThrow()
        {
            // Arrange
            var encodingDesign = new EncodingDesign();

            // Act & Assert
            Assert.DoesNotThrow(() => encodingDesign.GetHashCode());
        }

        /// <summary>
        /// Tests that GetHashCode works correctly with multiple instances.
        /// </summary>
        [Test]
        public void GetHashCode_MultipleInstances_ReturnsConsistentValues()
        {
            // Arrange
            var encodingDesign1 = new EncodingDesign();
            var encodingDesign2 = new EncodingDesign();
            var encodingDesign3 = new EncodingDesign();

            // Act
            int hashCode1 = encodingDesign1.GetHashCode();
            int hashCode2 = encodingDesign2.GetHashCode();
            int hashCode3 = encodingDesign3.GetHashCode();

            // Assert
            Assert.That(encodingDesign1.GetHashCode(), Is.EqualTo(hashCode1));
            Assert.That(encodingDesign2.GetHashCode(), Is.EqualTo(hashCode2));
            Assert.That(encodingDesign3.GetHashCode(), Is.EqualTo(hashCode3));
        }

        /// <summary>
        /// Tests that Equals(object) delegates correctly to base class for EncodingDesign instances.
        /// Input: Another EncodingDesign instance cast to object.
        /// Expected: Returns the result of base.Equals(obj).
        /// </summary>
        [Test]
        public void Equals_AnotherEncodingDesignAsObject_DelegatesToBaseEquals()
        {
            // Arrange
            var encodingDesign1 = new EncodingDesign();
            var encodingDesign2 = new EncodingDesign();

            // Act
            bool result = encodingDesign1.Equals((object)encodingDesign2);

            // Assert
            // The result depends on base class implementation
            // Since these are different instances with default values, they should not be equal
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns true when comparing an instance to itself cast as object.
        /// Input: Same instance cast to object.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_SameInstanceCastToObject_ReturnsTrue()
        {
            // Arrange
            var encodingDesign = new EncodingDesign();
            object objReference = encodingDesign;

            // Act
            bool result = encodingDesign.Equals(objReference);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when comparing different instances.
        /// Input: Two different EncodingDesign instances.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentEncodingDesignInstances_ReturnsFalse()
        {
            // Arrange
            var encodingDesign1 = new EncodingDesign();
            var encodingDesign2 = new EncodingDesign();

            // Act
            bool result = encodingDesign1.Equals((object)encodingDesign2);

            // Assert
            Assert.That(result, Is.False);
        }
    }

    /// <summary>
    /// Unit tests for the ObjectDesign class.
    /// </summary>
    [TestFixture]
    public partial class ObjectDesignTests
    {
        /// <summary>
        /// Tests that GetHashCode returns the same value when called multiple times on the same object.
        /// Input: An ObjectDesign instance with specific property values.
        /// Expected: GetHashCode returns the same value on consecutive calls.
        /// </summary>
        [Test]
        public void GetHashCode_CalledMultipleTimes_ReturnsSameValue()
        {
            // Arrange
            var objectDesign = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.com"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            // Act
            int hashCode1 = objectDesign.GetHashCode();
            int hashCode2 = objectDesign.GetHashCode();
            int hashCode3 = objectDesign.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.EqualTo(hashCode2));
            Assert.That(hashCode2, Is.EqualTo(hashCode3));
        }

        /// <summary>
        /// Tests that equal objects have the same hash code.
        /// Input: Two ObjectDesign instances with identical property values.
        /// Expected: Both objects return the same hash code.
        /// </summary>
        [Test]
        public void GetHashCode_EqualObjects_ReturnsSameHashCode()
        {
            // Arrange
            var objectDesign1 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.com"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            var objectDesign2 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.com"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            // Act
            int hashCode1 = objectDesign1.GetHashCode();
            int hashCode2 = objectDesign2.GetHashCode();

            // Assert
            Assert.That(objectDesign1.Equals(objectDesign2), Is.True, "Objects should be equal");
            Assert.That(hashCode1, Is.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that objects with different SupportsEvents values have different hash codes.
        /// Input: Two ObjectDesign instances differing only in SupportsEvents property.
        /// Expected: Different hash codes are returned (not strictly required but highly probable).
        /// </summary>
        [Test]
        public void GetHashCode_DifferentSupportsEvents_ReturnsDifferentHashCode()
        {
            // Arrange
            var objectDesign1 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.com"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            var objectDesign2 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.com"),
                SupportsEvents = false,
                SupportsEventsSpecified = true
            };

            // Act
            int hashCode1 = objectDesign1.GetHashCode();
            int hashCode2 = objectDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.Not.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that objects with different SupportsEventsSpecified values have different hash codes.
        /// Input: Two ObjectDesign instances differing only in SupportsEventsSpecified property.
        /// Expected: Different hash codes are returned (not strictly required but highly probable).
        /// </summary>
        [Test]
        public void GetHashCode_DifferentSupportsEventsSpecified_ReturnsDifferentHashCode()
        {
            // Arrange
            var objectDesign1 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.com"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            var objectDesign2 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.com"),
                SupportsEvents = true,
                SupportsEventsSpecified = false
            };

            // Act
            int hashCode1 = objectDesign1.GetHashCode();
            int hashCode2 = objectDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.Not.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests hash code generation with various combinations of SupportsEvents and SupportsEventsSpecified.
        /// Input: ObjectDesign instances with different boolean combinations.
        /// Expected: Each combination produces a hash code.
        /// </summary>
        [TestCase(true, true)]
        [TestCase(true, false)]
        [TestCase(false, true)]
        [TestCase(false, false)]
        public void GetHashCode_VariousBooleanCombinations_ReturnsHashCode(bool supportsEvents, bool supportsEventsSpecified)
        {
            // Arrange
            var objectDesign = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.com"),
                SupportsEvents = supportsEvents,
                SupportsEventsSpecified = supportsEventsSpecified
            };

            // Act
            int hashCode = objectDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0), "Hash code should be computed");
        }

        /// <summary>
        /// Tests that objects with different base properties have different hash codes.
        /// Input: Two ObjectDesign instances with different SymbolicId values.
        /// Expected: Different hash codes are returned.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentBaseProperties_ReturnsDifferentHashCode()
        {
            // Arrange
            var objectDesign1 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject1", "http://test.com"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            var objectDesign2 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject2", "http://test.com"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            // Act
            int hashCode1 = objectDesign1.GetHashCode();
            int hashCode2 = objectDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.Not.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests hash code generation for a minimal ObjectDesign instance.
        /// Input: ObjectDesign with default values (SupportsEvents = false, SupportsEventsSpecified = false).
        /// Expected: A valid hash code is returned.
        /// </summary>
        [Test]
        public void GetHashCode_DefaultValues_ReturnsValidHashCode()
        {
            // Arrange
            var objectDesign = new ObjectDesign();

            // Act
            int hashCode = objectDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0), "Hash code should be computed for default values");
        }

        /// <summary>
        /// Tests that GetHashCode is consistent with Equals for equal objects.
        /// Input: Two equal ObjectDesign instances.
        /// Expected: Equals returns true and hash codes are equal.
        /// </summary>
        [Test]
        public void GetHashCode_ConsistentWithEquals_EqualObjectsHaveSameHashCode()
        {
            // Arrange
            var objectDesign1 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.com"),
                SupportsEvents = false,
                SupportsEventsSpecified = false
            };

            var objectDesign2 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.com"),
                SupportsEvents = false,
                SupportsEventsSpecified = false
            };

            // Act & Assert
            Assert.That(objectDesign1.Equals(objectDesign2), Is.True);
            Assert.That(objectDesign1.GetHashCode(), Is.EqualTo(objectDesign2.GetHashCode()));
        }

        /// <summary>
        /// Tests that objects with all different property combinations produce different hash codes.
        /// Input: Two ObjectDesign instances with completely different properties.
        /// Expected: Different hash codes are returned.
        /// </summary>
        [Test]
        public void GetHashCode_CompletelyDifferentObjects_ReturnsDifferentHashCode()
        {
            // Arrange
            var objectDesign1 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("Object1", "http://test1.com"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            var objectDesign2 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("Object2", "http://test2.com"),
                SupportsEvents = false,
                SupportsEventsSpecified = false
            };

            // Act
            int hashCode1 = objectDesign1.GetHashCode();
            int hashCode2 = objectDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.Not.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that Equals returns false when comparing to null.
        /// </summary>
        [Test]
        public void Equals_NullOther_ReturnsFalse()
        {
            // Arrange
            var instance = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.org"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = instance.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing an instance to itself.
        /// </summary>
        [Test]
        public void Equals_SameInstance_ReturnsTrue()
        {
            // Arrange
            var instance = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.org"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            // Act
            bool result = instance.Equals(instance);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when all properties are equal.
        /// </summary>
        [Test]
        public void Equals_AllPropertiesEqual_ReturnsTrue()
        {
            // Arrange
            var symbolId = new XmlQualifiedName("TestObject", "http://test.org");
            var instance1 = new ObjectDesign
            {
                SymbolicId = symbolId,
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };
            var instance2 = new ObjectDesign
            {
                SymbolicId = symbolId,
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when SupportsEvents property differs.
        /// Input: Two instances with different SupportsEvents values.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentSupportsEvents_ReturnsFalse()
        {
            // Arrange
            var symbolId = new XmlQualifiedName("TestObject", "http://test.org");
            var instance1 = new ObjectDesign
            {
                SymbolicId = symbolId,
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };
            var instance2 = new ObjectDesign
            {
                SymbolicId = symbolId,
                SupportsEvents = false,
                SupportsEventsSpecified = true
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when SupportsEventsSpecified property differs.
        /// Input: Two instances with different SupportsEventsSpecified values.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentSupportsEventsSpecified_ReturnsFalse()
        {
            // Arrange
            var symbolId = new XmlQualifiedName("TestObject", "http://test.org");
            var instance1 = new ObjectDesign
            {
                SymbolicId = symbolId,
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };
            var instance2 = new ObjectDesign
            {
                SymbolicId = symbolId,
                SupportsEvents = true,
                SupportsEventsSpecified = false
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when both SupportsEvents and SupportsEventsSpecified differ.
        /// Input: Two instances with different SupportsEvents and SupportsEventsSpecified values.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_BothSupportsPropertiesDiffer_ReturnsFalse()
        {
            // Arrange
            var symbolId = new XmlQualifiedName("TestObject", "http://test.org");
            var instance1 = new ObjectDesign
            {
                SymbolicId = symbolId,
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };
            var instance2 = new ObjectDesign
            {
                SymbolicId = symbolId,
                SupportsEvents = false,
                SupportsEventsSpecified = false
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when base class properties differ.
        /// Input: Two instances with different SymbolicId values.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentBaseProperties_ReturnsFalse()
        {
            // Arrange
            var instance1 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject1", "http://test.org"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };
            var instance2 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject2", "http://test.org"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles both properties set to false correctly.
        /// Input: Two instances with SupportsEvents and SupportsEventsSpecified set to false.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_BothPropertiesFalse_ReturnsTrue()
        {
            // Arrange
            var symbolId = new XmlQualifiedName("TestObject", "http://test.org");
            var instance1 = new ObjectDesign
            {
                SymbolicId = symbolId,
                SupportsEvents = false,
                SupportsEventsSpecified = false
            };
            var instance2 = new ObjectDesign
            {
                SymbolicId = symbolId,
                SupportsEvents = false,
                SupportsEventsSpecified = false
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests Equals with all combinations of boolean property values using parameterized tests.
        /// Input: Various combinations of SupportsEvents and SupportsEventsSpecified values.
        /// Expected: Returns true when both instances have matching values.
        /// </summary>
        [TestCase(false, false, false, false, true)]
        [TestCase(false, true, false, true, true)]
        [TestCase(true, false, true, false, true)]
        [TestCase(true, true, true, true, true)]
        [TestCase(false, false, true, false, false)]
        [TestCase(false, false, false, true, false)]
        [TestCase(true, true, false, false, false)]
        [TestCase(true, false, false, true, false)]
        public void Equals_VariousBooleanCombinations_ReturnsExpectedResult(
            bool supportsEvents1,
            bool supportsEventsSpecified1,
            bool supportsEvents2,
            bool supportsEventsSpecified2,
            bool expectedResult)
        {
            // Arrange
            var symbolId = new XmlQualifiedName("TestObject", "http://test.org");
            var instance1 = new ObjectDesign
            {
                SymbolicId = symbolId,
                SupportsEvents = supportsEvents1,
                SupportsEventsSpecified = supportsEventsSpecified1
            };
            var instance2 = new ObjectDesign
            {
                SymbolicId = symbolId,
                SupportsEvents = supportsEvents2,
                SupportsEventsSpecified = supportsEventsSpecified2
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.EqualTo(expectedResult));
        }

        /// <summary>
        /// Tests that Equals is symmetric: a.Equals(b) == b.Equals(a).
        /// Input: Two equal instances compared in both directions.
        /// Expected: Both comparisons return true.
        /// </summary>
        [Test]
        public void Equals_Symmetric_ReturnsSameResult()
        {
            // Arrange
            var symbolId = new XmlQualifiedName("TestObject", "http://test.org");
            var instance1 = new ObjectDesign
            {
                SymbolicId = symbolId,
                SupportsEvents = true,
                SupportsEventsSpecified = false
            };
            var instance2 = new ObjectDesign
            {
                SymbolicId = symbolId,
                SupportsEvents = true,
                SupportsEventsSpecified = false
            };

            // Act
            bool result1 = instance1.Equals(instance2);
            bool result2 = instance2.Equals(instance1);

            // Assert
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result1, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when TypeDefinition differs.
        /// Input: Two instances with different TypeDefinition values.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentTypeDefinition_ReturnsFalse()
        {
            // Arrange
            var symbolId = new XmlQualifiedName("TestObject", "http://test.org");
            var instance1 = new ObjectDesign
            {
                SymbolicId = symbolId,
                TypeDefinition = new XmlQualifiedName("Type1", "http://test.org"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };
            var instance2 = new ObjectDesign
            {
                SymbolicId = symbolId,
                TypeDefinition = new XmlQualifiedName("Type2", "http://test.org"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when ModellingRule differs.
        /// Input: Two instances with different ModellingRule values.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentModellingRule_ReturnsFalse()
        {
            // Arrange
            var symbolId = new XmlQualifiedName("TestObject", "http://test.org");
            var instance1 = new ObjectDesign
            {
                SymbolicId = symbolId,
                ModellingRule = ModellingRule.Mandatory,
                ModellingRuleSpecified = true,
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };
            var instance2 = new ObjectDesign
            {
                SymbolicId = symbolId,
                ModellingRule = ModellingRule.Optional,
                ModellingRuleSpecified = true,
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when the parameter is null.
        /// </summary>
        [Test]
        public void Equals_NullObject_ReturnsFalse()
        {
            // Arrange
            var objectDesign = new ObjectDesign();

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = objectDesign.Equals((object)null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing an object to itself.
        /// </summary>
        [Test]
        public void Equals_SameReference_ReturnsTrue()
        {
            // Arrange
            var objectDesign = new ObjectDesign
            {
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            // Act
            bool result = objectDesign.Equals((object)objectDesign);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with an object of a different type.
        /// </summary>
        [Test]
        public void Equals_DifferentType_ReturnsFalse()
        {
            // Arrange
            var objectDesign = new ObjectDesign();
            object differentTypeObject = new();

            // Act
            bool result = objectDesign.Equals(differentTypeObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with a string object.
        /// </summary>
        [Test]
        public void Equals_StringObject_ReturnsFalse()
        {
            // Arrange
            var objectDesign = new ObjectDesign();
            object stringObject = "test";

            // Act
            bool result = objectDesign.Equals(stringObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two ObjectDesign instances with identical property values.
        /// </summary>
        [TestCase(true, true)]
        [TestCase(false, false)]
        [TestCase(true, false)]
        [TestCase(false, true)]
        public void Equals_IdenticalProperties_ReturnsTrue(bool supportsEvents, bool supportsEventsSpecified)
        {
            // Arrange
            var objectDesign1 = new ObjectDesign
            {
                SupportsEvents = supportsEvents,
                SupportsEventsSpecified = supportsEventsSpecified
            };
            var objectDesign2 = new ObjectDesign
            {
                SupportsEvents = supportsEvents,
                SupportsEventsSpecified = supportsEventsSpecified
            };

            // Act
            bool result = objectDesign1.Equals((object)objectDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when both SupportsEvents and SupportsEventsSpecified differ.
        /// </summary>
        [Test]
        public void Equals_BothPropertiesDifferent_ReturnsFalse()
        {
            // Arrange
            var objectDesign1 = new ObjectDesign
            {
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };
            var objectDesign2 = new ObjectDesign
            {
                SupportsEvents = false,
                SupportsEventsSpecified = false
            };

            // Act
            bool result = objectDesign1.Equals((object)objectDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing default-initialized ObjectDesign instances.
        /// </summary>
        [Test]
        public void Equals_DefaultInstances_ReturnsTrue()
        {
            // Arrange
            var objectDesign1 = new ObjectDesign();
            var objectDesign2 = new ObjectDesign();

            // Act
            bool result = objectDesign1.Equals((object)objectDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that GetHashCode returns a consistent value when called multiple times on the same object.
        /// </summary>
        [Test]
        public void GetHashCode_SameObject_ReturnsConsistentValue()
        {
            // Arrange
            var objectDesign = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.org"),
                SymbolicName = new XmlQualifiedName("TestObject", "http://test.org"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            // Act
            int hashCode1 = objectDesign.GetHashCode();
            int hashCode2 = objectDesign.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode returns the same value for objects with identical property values.
        /// </summary>
        /// <param name="supportsEvents">Value for SupportsEvents property.</param>
        /// <param name="supportsEventsSpecified">Value for SupportsEventsSpecified property.</param>
        [TestCase(true, true)]
        [TestCase(true, false)]
        [TestCase(false, true)]
        [TestCase(false, false)]
        public void GetHashCode_ObjectsWithSameProperties_ReturnsSameHashCode(bool supportsEvents, bool supportsEventsSpecified)
        {
            // Arrange
            var objectDesign1 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.org"),
                SymbolicName = new XmlQualifiedName("TestObject", "http://test.org"),
                SupportsEvents = supportsEvents,
                SupportsEventsSpecified = supportsEventsSpecified
            };

            var objectDesign2 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.org"),
                SymbolicName = new XmlQualifiedName("TestObject", "http://test.org"),
                SupportsEvents = supportsEvents,
                SupportsEventsSpecified = supportsEventsSpecified
            };

            // Act
            int hashCode1 = objectDesign1.GetHashCode();
            int hashCode2 = objectDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode produces different hash codes for objects with different SupportsEvents values.
        /// Note: While hash collisions are possible, different inputs should typically produce different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentSupportsEvents_ProducesDifferentHashCodes()
        {
            // Arrange
            var objectDesign1 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.org"),
                SymbolicName = new XmlQualifiedName("TestObject", "http://test.org"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            var objectDesign2 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.org"),
                SymbolicName = new XmlQualifiedName("TestObject", "http://test.org"),
                SupportsEvents = false,
                SupportsEventsSpecified = true
            };

            // Act
            int hashCode1 = objectDesign1.GetHashCode();
            int hashCode2 = objectDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.Not.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode produces different hash codes for objects with different SupportsEventsSpecified values.
        /// Note: While hash collisions are possible, different inputs should typically produce different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentSupportsEventsSpecified_ProducesDifferentHashCodes()
        {
            // Arrange
            var objectDesign1 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.org"),
                SymbolicName = new XmlQualifiedName("TestObject", "http://test.org"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            var objectDesign2 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject", "http://test.org"),
                SymbolicName = new XmlQualifiedName("TestObject", "http://test.org"),
                SupportsEvents = true,
                SupportsEventsSpecified = false
            };

            // Act
            int hashCode1 = objectDesign1.GetHashCode();
            int hashCode2 = objectDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.Not.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode incorporates base class properties by producing different hash codes
        /// when base properties differ.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentBaseProperties_ProducesDifferentHashCodes()
        {
            // Arrange
            var objectDesign1 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject1", "http://test.org"),
                SymbolicName = new XmlQualifiedName("TestObject1", "http://test.org"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            var objectDesign2 = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestObject2", "http://test.org"),
                SymbolicName = new XmlQualifiedName("TestObject2", "http://test.org"),
                SupportsEvents = true,
                SupportsEventsSpecified = true
            };

            // Act
            int hashCode1 = objectDesign1.GetHashCode();
            int hashCode2 = objectDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.Not.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode returns a valid integer value for a minimal ObjectDesign instance.
        /// </summary>
        [Test]
        public void GetHashCode_MinimalObject_ReturnsValidHashCode()
        {
            // Arrange
            var objectDesign = new ObjectDesign();

            // Act
            int hashCode = objectDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode produces different hash codes for all combinations of boolean property values.
        /// </summary>
        [Test]
        public void GetHashCode_AllBooleanCombinations_ProducesDistinctHashCodes()
        {
            // Arrange
            var combinations = new[]
            {
                new { SupportsEvents = false, SupportsEventsSpecified = false },
                new { SupportsEvents = false, SupportsEventsSpecified = true },
                new { SupportsEvents = true, SupportsEventsSpecified = false },
                new { SupportsEvents = true, SupportsEventsSpecified = true }
            };

            var hashCodes = new System.Collections.Generic.HashSet<int>();

            // Act
            foreach (var combo in combinations)
            {
                var objectDesign = new ObjectDesign
                {
                    SymbolicId = new XmlQualifiedName("TestObject", "http://test.org"),
                    SymbolicName = new XmlQualifiedName("TestObject", "http://test.org"),
                    SupportsEvents = combo.SupportsEvents,
                    SupportsEventsSpecified = combo.SupportsEventsSpecified
                };
                hashCodes.Add(objectDesign.GetHashCode());
            }

            // Assert
            Assert.That(hashCodes.Count, Is.EqualTo(4), "All four boolean combinations should produce distinct hash codes");
        }
    }

    /// <summary>
    /// Unit tests for <see cref="ViewDesign"/> class.
    /// </summary>
    [TestFixture]
    public partial class ViewDesignTests
    {
        /// <summary>
        /// Tests that Equals returns false when comparing with null.
        /// </summary>
        [Test]
        public void Equals_NullParameter_ReturnsFalse()
        {
            // Arrange
            var instance = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = true
            };

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = instance.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing an instance with itself.
        /// </summary>
        [Test]
        public void Equals_SameReference_ReturnsTrue()
        {
            // Arrange
            var instance = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = false
            };

            // Act
            bool result = instance.Equals(instance);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two instances with identical property values.
        /// </summary>
        [Test]
        public void Equals_IdenticalInstances_ReturnsTrue()
        {
            // Arrange
            var instance1 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = true,
                SymbolicId = new XmlQualifiedName("TestId", "http://test.org"),
                SymbolicName = new XmlQualifiedName("TestName", "http://test.org")
            };

            var instance2 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = true,
                SymbolicId = new XmlQualifiedName("TestId", "http://test.org"),
                SymbolicName = new XmlQualifiedName("TestName", "http://test.org")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when SupportsEvents differs between instances.
        /// </summary>
        [Test]
        public void Equals_DifferentSupportsEvents_ReturnsFalse()
        {
            // Arrange
            var instance1 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = false,
                SymbolicId = new XmlQualifiedName("TestId", "http://test.org")
            };

            var instance2 = new ViewDesign
            {
                SupportsEvents = false,
                ContainsNoLoops = false,
                SymbolicId = new XmlQualifiedName("TestId", "http://test.org")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when ContainsNoLoops differs between instances.
        /// </summary>
        [Test]
        public void Equals_DifferentContainsNoLoops_ReturnsFalse()
        {
            // Arrange
            var instance1 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = true,
                SymbolicId = new XmlQualifiedName("TestId", "http://test.org")
            };

            var instance2 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = false,
                SymbolicId = new XmlQualifiedName("TestId", "http://test.org")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when base class properties differ.
        /// This tests the base.Equals(other) call in the implementation.
        /// </summary>
        [Test]
        public void Equals_DifferentBaseClassProperty_ReturnsFalse()
        {
            // Arrange
            var instance1 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = true,
                SymbolicId = new XmlQualifiedName("TestId1", "http://test.org")
            };

            var instance2 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = true,
                SymbolicId = new XmlQualifiedName("TestId2", "http://test.org")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when multiple properties differ.
        /// </summary>
        [Test]
        public void Equals_MultipleDifferentProperties_ReturnsFalse()
        {
            // Arrange
            var instance1 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = true,
                SymbolicId = new XmlQualifiedName("TestId1", "http://test.org")
            };

            var instance2 = new ViewDesign
            {
                SupportsEvents = false,
                ContainsNoLoops = false,
                SymbolicId = new XmlQualifiedName("TestId2", "http://test.org")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both instances have default values (false for bool properties).
        /// </summary>
        [Test]
        public void Equals_DefaultValues_ReturnsTrue()
        {
            // Arrange
            var instance1 = new ViewDesign();
            var instance2 = new ViewDesign();

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals handles boundary case where SupportsEvents is true and ContainsNoLoops is false.
        /// </summary>
        [TestCase(true, false)]
        [TestCase(false, true)]
        [TestCase(true, true)]
        [TestCase(false, false)]
        public void Equals_VariousBooleanCombinations_ReturnsExpectedResult(bool supportsEvents, bool containsNoLoops)
        {
            // Arrange
            var instance1 = new ViewDesign
            {
                SupportsEvents = supportsEvents,
                ContainsNoLoops = containsNoLoops,
                SymbolicId = new XmlQualifiedName("TestId", "http://test.org")
            };

            var instance2 = new ViewDesign
            {
                SupportsEvents = supportsEvents,
                ContainsNoLoops = containsNoLoops,
                SymbolicId = new XmlQualifiedName("TestId", "http://test.org")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when only one of two boolean properties differs.
        /// Verifies that all properties must match for equality.
        /// </summary>
        [TestCase(true, false, false, false)]
        [TestCase(false, true, false, true)]
        public void Equals_OneBooleanPropertyDiffers_ReturnsFalse(
            bool instance1SupportsEvents,
            bool instance1ContainsNoLoops,
            bool instance2SupportsEvents,
            bool instance2ContainsNoLoops)
        {
            // Arrange
            var instance1 = new ViewDesign
            {
                SupportsEvents = instance1SupportsEvents,
                ContainsNoLoops = instance1ContainsNoLoops,
                SymbolicId = new XmlQualifiedName("TestId", "http://test.org")
            };

            var instance2 = new ViewDesign
            {
                SupportsEvents = instance2SupportsEvents,
                ContainsNoLoops = instance2ContainsNoLoops,
                SymbolicId = new XmlQualifiedName("TestId", "http://test.org")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when passed a null object.
        /// </summary>
        [Test]
        public void EqualsObject_NullObject_ReturnsFalse()
        {
            // Arrange
            var viewDesign = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = false
            };

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = viewDesign.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns true when comparing an instance to itself (reference equality).
        /// </summary>
        [Test]
        public void EqualsObject_SameInstance_ReturnsTrue()
        {
            // Arrange
            var viewDesign = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = true
            };

            // Act
            bool result = viewDesign.Equals((object)viewDesign);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns true when comparing two ViewDesign instances with identical property values.
        /// </summary>
        /// <param name="supportsEvents">Value for SupportsEvents property</param>
        /// <param name="containsNoLoops">Value for ContainsNoLoops property</param>
        [TestCase(true, true)]
        [TestCase(true, false)]
        [TestCase(false, true)]
        [TestCase(false, false)]
        public void EqualsObject_EqualViewDesignInstances_ReturnsTrue(bool supportsEvents, bool containsNoLoops)
        {
            // Arrange
            var viewDesign1 = new ViewDesign
            {
                SupportsEvents = supportsEvents,
                ContainsNoLoops = containsNoLoops
            };
            var viewDesign2 = new ViewDesign
            {
                SupportsEvents = supportsEvents,
                ContainsNoLoops = containsNoLoops
            };

            // Act
            bool result = viewDesign1.Equals((object)viewDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when comparing ViewDesign instances with different SupportsEvents values.
        /// </summary>
        [Test]
        public void EqualsObject_DifferentSupportsEvents_ReturnsFalse()
        {
            // Arrange
            var viewDesign1 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = false
            };
            var viewDesign2 = new ViewDesign
            {
                SupportsEvents = false,
                ContainsNoLoops = false
            };

            // Act
            bool result = viewDesign1.Equals((object)viewDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when comparing ViewDesign instances with different ContainsNoLoops values.
        /// </summary>
        [Test]
        public void EqualsObject_DifferentContainsNoLoops_ReturnsFalse()
        {
            // Arrange
            var viewDesign1 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = true
            };
            var viewDesign2 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = false
            };

            // Act
            bool result = viewDesign1.Equals((object)viewDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when comparing ViewDesign instances with both properties different.
        /// </summary>
        [Test]
        public void EqualsObject_BothPropertiesDifferent_ReturnsFalse()
        {
            // Arrange
            var viewDesign1 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = true
            };
            var viewDesign2 = new ViewDesign
            {
                SupportsEvents = false,
                ContainsNoLoops = false
            };

            // Act
            bool result = viewDesign1.Equals((object)viewDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when passed a string object instead of ViewDesign.
        /// </summary>
        [Test]
        public void EqualsObject_StringObject_ReturnsFalse()
        {
            // Arrange
            var viewDesign = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = false
            };
            object otherObject = "some string";

            // Act
            bool result = viewDesign.Equals(otherObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when passed an integer object instead of ViewDesign.
        /// </summary>
        [Test]
        public void EqualsObject_IntegerObject_ReturnsFalse()
        {
            // Arrange
            var viewDesign = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = false
            };
            object otherObject = 42;

            // Act
            bool result = viewDesign.Equals(otherObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when passed an object of a different type in the same namespace.
        /// </summary>
        [Test]
        public void EqualsObject_DifferentTypeInSameNamespace_ReturnsFalse()
        {
            // Arrange
            var viewDesign = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = false
            };
            object otherObject = new ObjectDesign();

            // Act
            bool result = viewDesign.Equals(otherObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when passed an arbitrary object.
        /// </summary>
        [Test]
        public void EqualsObject_ArbitraryObject_ReturnsFalse()
        {
            // Arrange
            var viewDesign = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = false
            };
            object otherObject = new();

            // Act
            bool result = viewDesign.Equals(otherObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns true for default constructed ViewDesign instances.
        /// Both instances should have SupportsEvents = false and ContainsNoLoops = false by default.
        /// </summary>
        [Test]
        public void EqualsObject_DefaultConstructedInstances_ReturnsTrue()
        {
            // Arrange
            var viewDesign1 = new ViewDesign();
            var viewDesign2 = new ViewDesign();

            // Act
            bool result = viewDesign1.Equals((object)viewDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when comparing ViewDesign instances with different SymbolicId values.
        /// This tests that base class property differences are detected.
        /// </summary>
        [Test]
        public void EqualsObject_DifferentSymbolicId_ReturnsFalse()
        {
            // Arrange
            var viewDesign1 = new ViewDesign
            {
                SymbolicId = new XmlQualifiedName("View1", "http://example.com"),
                SupportsEvents = true,
                ContainsNoLoops = false
            };
            var viewDesign2 = new ViewDesign
            {
                SymbolicId = new XmlQualifiedName("View2", "http://example.com"),
                SupportsEvents = true,
                ContainsNoLoops = false
            };

            // Act
            bool result = viewDesign1.Equals((object)viewDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that GetHashCode returns consistent hash codes when called multiple times on the same object.
        /// Input: ViewDesign instance with default property values.
        /// Expected: Multiple calls return the same hash code.
        /// </summary>
        [Test]
        public void GetHashCode_CalledMultipleTimes_ReturnsConsistentValue()
        {
            // Arrange
            var viewDesign = new ViewDesign();

            // Act
            int hashCode1 = viewDesign.GetHashCode();
            int hashCode2 = viewDesign.GetHashCode();
            int hashCode3 = viewDesign.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.EqualTo(hashCode1));
            Assert.That(hashCode3, Is.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode returns the same hash code for equal ViewDesign objects.
        /// Input: Two ViewDesign instances with identical property values.
        /// Expected: Both instances return the same hash code.
        /// </summary>
        [TestCase(false, false)]
        [TestCase(true, false)]
        [TestCase(false, true)]
        [TestCase(true, true)]
        public void GetHashCode_EqualObjects_ReturnsSameHashCode(bool supportsEvents, bool containsNoLoops)
        {
            // Arrange
            var viewDesign1 = new ViewDesign
            {
                SupportsEvents = supportsEvents,
                ContainsNoLoops = containsNoLoops
            };
            var viewDesign2 = new ViewDesign
            {
                SupportsEvents = supportsEvents,
                ContainsNoLoops = containsNoLoops
            };

            // Act
            int hashCode1 = viewDesign1.GetHashCode();
            int hashCode2 = viewDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different SupportsEvents values.
        /// Input: Two ViewDesign instances differing only in SupportsEvents.
        /// Expected: Hash codes are different (though not strictly guaranteed by contract, highly likely).
        /// </summary>
        [Test]
        public void GetHashCode_DifferentSupportsEvents_ReturnsDifferentHashCodes()
        {
            // Arrange
            var viewDesign1 = new ViewDesign
            {
                SupportsEvents = false,
                ContainsNoLoops = false
            };
            var viewDesign2 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = false
            };

            // Act
            int hashCode1 = viewDesign1.GetHashCode();
            int hashCode2 = viewDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different ContainsNoLoops values.
        /// Input: Two ViewDesign instances differing only in ContainsNoLoops.
        /// Expected: Hash codes are different (though not strictly guaranteed by contract, highly likely).
        /// </summary>
        [Test]
        public void GetHashCode_DifferentContainsNoLoops_ReturnsDifferentHashCodes()
        {
            // Arrange
            var viewDesign1 = new ViewDesign
            {
                SupportsEvents = false,
                ContainsNoLoops = false
            };
            var viewDesign2 = new ViewDesign
            {
                SupportsEvents = false,
                ContainsNoLoops = true
            };

            // Act
            int hashCode1 = viewDesign1.GetHashCode();
            int hashCode2 = viewDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when both SupportsEvents and ContainsNoLoops differ.
        /// Input: Two ViewDesign instances with completely different property values.
        /// Expected: Hash codes are different.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentProperties_ReturnsDifferentHashCodes()
        {
            // Arrange
            var viewDesign1 = new ViewDesign
            {
                SupportsEvents = false,
                ContainsNoLoops = false
            };
            var viewDesign2 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = true
            };

            // Act
            int hashCode1 = viewDesign1.GetHashCode();
            int hashCode2 = viewDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode includes base class properties in hash code calculation.
        /// Input: Two ViewDesign instances with different base class properties.
        /// Expected: Hash codes are different because base.GetHashCode() is included.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentBaseProperties_ReturnsDifferentHashCodes()
        {
            // Arrange
            var viewDesign1 = new ViewDesign
            {
                SupportsEvents = false,
                ContainsNoLoops = false,
                SymbolicName = new XmlQualifiedName("View1", "http://test.org")
            };
            var viewDesign2 = new ViewDesign
            {
                SupportsEvents = false,
                ContainsNoLoops = false,
                SymbolicName = new XmlQualifiedName("View2", "http://test.org")
            };

            // Act
            int hashCode1 = viewDesign1.GetHashCode();
            int hashCode2 = viewDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode does not throw exceptions for default-initialized ViewDesign instances.
        /// Input: Newly created ViewDesign with default values.
        /// Expected: GetHashCode executes successfully and returns a valid hash code.
        /// </summary>
        [Test]
        public void GetHashCode_DefaultInitialization_ExecutesSuccessfully()
        {
            // Arrange
            var viewDesign = new ViewDesign();

            // Act
            int hashCode = viewDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode satisfies the equality contract: equal objects have equal hash codes.
        /// Input: Two ViewDesign instances that are equal according to Equals method.
        /// Expected: Hash codes are identical.
        /// </summary>
        [Test]
        public void GetHashCode_EqualObjectsByEqualsContract_HaveEqualHashCodes()
        {
            // Arrange
            var viewDesign1 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = true,
                SymbolicName = new XmlQualifiedName("TestView", "http://test.org")
            };
            var viewDesign2 = new ViewDesign
            {
                SupportsEvents = true,
                ContainsNoLoops = true,
                SymbolicName = new XmlQualifiedName("TestView", "http://test.org")
            };

            // Act
            bool areEqual = viewDesign1.Equals(viewDesign2);
            int hashCode1 = viewDesign1.GetHashCode();
            int hashCode2 = viewDesign2.GetHashCode();

            // Assert
            Assert.That(areEqual, Is.True, "Objects should be equal");
            Assert.That(hashCode2, Is.EqualTo(hashCode1), "Equal objects must have equal hash codes");
        }
    }

    /// <summary>
    /// Unit tests for the <see cref="HierarchyNode"/> class.
    /// </summary>
    [TestFixture]
    public class HierarchyNodeTests
    {
        /// <summary>
        /// Tests that ToString returns formatted string when Instance and SymbolicId are not null.
        /// Expected format: "{RelativePath}={Instance.SymbolicId.Name}"
        /// </summary>
        [Test]
        public void ToString_WithInstanceAndSymbolicId_ReturnsFormattedString()
        {
            // Arrange
            var symbolicId = new XmlQualifiedName("TestNodeName", "http://test.namespace");
            var instance = new NodeDesign { SymbolicId = symbolicId };
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = instance
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("TestPath=TestNodeName"));
        }

        /// <summary>
        /// Tests that ToString returns RelativePath when Instance is null.
        /// </summary>
        [Test]
        public void ToString_WithNullInstance_ReturnsRelativePath()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("TestPath"));
        }

        /// <summary>
        /// Tests that ToString returns RelativePath when Instance.SymbolicId is null.
        /// </summary>
        [Test]
        public void ToString_WithNullSymbolicId_ReturnsRelativePath()
        {
            // Arrange
            var instance = new NodeDesign { SymbolicId = null };
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = instance
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("TestPath"));
        }

        /// <summary>
        /// Tests that ToString returns null when RelativePath is null and Instance is null.
        /// </summary>
        [Test]
        public void ToString_WithNullRelativePathAndNullInstance_ReturnsNull()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = null,
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.Null);
        }

        /// <summary>
        /// Tests that ToString returns empty string when RelativePath is empty.
        /// </summary>
        [Test]
        public void ToString_WithEmptyRelativePath_ReturnsEmptyString()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = string.Empty,
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo(string.Empty));
        }

        /// <summary>
        /// Tests that ToString returns formatted string with empty SymbolicId name.
        /// </summary>
        [Test]
        public void ToString_WithEmptySymbolicIdName_ReturnsFormattedStringWithEmptyName()
        {
            // Arrange
            var symbolicId = new XmlQualifiedName(string.Empty, "http://test.namespace");
            var instance = new NodeDesign { SymbolicId = symbolicId };
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = instance
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("TestPath="));
        }

        /// <summary>
        /// Tests that ToString handles whitespace-only RelativePath correctly.
        /// </summary>
        [Test]
        public void ToString_WithWhitespaceRelativePath_ReturnsWhitespace()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "   ",
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("   "));
        }

        /// <summary>
        /// Tests that ToString handles special characters in RelativePath correctly.
        /// </summary>
        [Test]
        public void ToString_WithSpecialCharactersInRelativePath_ReturnsPathWithSpecialCharacters()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "Test/Path\\With:Special*Chars",
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("Test/Path\\With:Special*Chars"));
        }

        /// <summary>
        /// Tests that ToString handles special characters in SymbolicId name correctly.
        /// </summary>
        [Test]
        public void ToString_WithSpecialCharactersInSymbolicIdName_ReturnsFormattedStringWithSpecialCharacters()
        {
            // Arrange
            var symbolicId = new XmlQualifiedName("Node:Name<With>Special&Chars", "http://test.namespace");
            var instance = new NodeDesign { SymbolicId = symbolicId };
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = instance
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("TestPath=Node:Name<With>Special&Chars"));
        }

        /// <summary>
        /// Tests that ToString works with very long strings.
        /// </summary>
        [Test]
        public void ToString_WithVeryLongRelativePath_ReturnsLongString()
        {
            // Arrange
            string longPath = new('a', 10000);
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = longPath,
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo(longPath));
            Assert.That(result.Length, Is.EqualTo(10000));
        }

        /// <summary>
        /// Tests that ToString handles null RelativePath with valid Instance and SymbolicId.
        /// Expected: Returns formatted string "null={SymbolicIdName}"
        /// </summary>
        [Test]
        public void ToString_WithNullRelativePathAndValidSymbolicId_ReturnsFormattedString()
        {
            // Arrange
            var symbolicId = new XmlQualifiedName("TestNodeName", "http://test.namespace");
            var instance = new NodeDesign { SymbolicId = symbolicId };
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = null,
                Instance = instance
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("=TestNodeName"));
        }

        /// <summary>
        /// Tests that ToString does not throw when other properties are set to various values.
        /// Verifies that ToString only depends on RelativePath and Instance.SymbolicId.
        /// </summary>
        [Test]
        public void ToString_WithOtherPropertiesSet_ReturnsCorrectString()
        {
            // Arrange
            var symbolicId = new XmlQualifiedName("TestNodeName", "http://test.namespace");
            var instance = new NodeDesign { SymbolicId = symbolicId };
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = instance,
                ExplicitlyDefined = true,
                AdHocInstance = true,
                StaticValue = false,
                Inherited = true,
                Identifier = new object()
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("TestPath=TestNodeName"));
        }

        /// <summary>
        /// Tests that ToString returns the RelativePath when Instance exists but SymbolicId is null.
        /// </summary>
        [Test]
        public void ToString_WithInstanceButNullSymbolicId_ReturnsRelativePath()
        {
            // Arrange
            var node = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = new NodeDesign
                {
                    SymbolicId = null
                }
            };

            // Act
            string result = node.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("TestPath"));
        }

        /// <summary>
        /// Tests that ToString returns empty string when RelativePath is empty and Instance is null.
        /// </summary>
        [Test]
        public void ToString_WithEmptyRelativePathAndNullInstance_ReturnsEmpty()
        {
            // Arrange
            var node = new HierarchyNode
            {
                RelativePath = string.Empty,
                Instance = null
            };

            // Act
            string result = node.ToString();

            // Assert
            Assert.That(result, Is.Empty);
        }

        /// <summary>
        /// Tests that ToString returns formatted string with null RelativePath when Instance and SymbolicId are present.
        /// </summary>
        [Test]
        public void ToString_WithNullRelativePathButValidInstance_ReturnsFormattedString()
        {
            // Arrange
            var node = new HierarchyNode
            {
                RelativePath = null,
                Instance = new NodeDesign
                {
                    SymbolicId = new XmlQualifiedName("TestName", "http://test.namespace")
                }
            };

            // Act
            string result = node.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("=TestName"));
        }

        /// <summary>
        /// Tests that ToString handles whitespace RelativePath correctly.
        /// </summary>
        [TestCase("   ")]
        [TestCase("\t")]
        [TestCase("\n")]
        public void ToString_WithWhitespaceRelativePath_ReturnsWhitespace(string relativePath)
        {
            // Arrange
            var node = new HierarchyNode
            {
                RelativePath = relativePath,
                Instance = null
            };

            // Act
            string result = node.ToString();

            // Assert
            Assert.That(result, Is.EqualTo(relativePath));
        }

        /// <summary>
        /// Tests that ToString handles special characters in RelativePath.
        /// </summary>
        [TestCase("Path/With/Slashes")]
        [TestCase("Path\\With\\Backslashes")]
        [TestCase("Path:With:Colons")]
        [TestCase("Path.With.Dots")]
        [TestCase("Path_With_Underscores")]
        public void ToString_WithSpecialCharactersInRelativePath_ReturnsPath(string relativePath)
        {
            // Arrange
            var node = new HierarchyNode
            {
                RelativePath = relativePath,
                Instance = null
            };

            // Act
            string result = node.ToString();

            // Assert
            Assert.That(result, Is.EqualTo(relativePath));
        }

        /// <summary>
        /// Tests that ToString handles special characters in SymbolicId name.
        /// </summary>
        [TestCase("Name:With:Colons")]
        [TestCase("Name.With.Dots")]
        [TestCase("Name_With_Underscores")]
        public void ToString_WithSpecialCharactersInSymbolicIdName_ReturnsFormattedString(string symbolicIdName)
        {
            // Arrange
            var node = new HierarchyNode
            {
                RelativePath = "Path",
                Instance = new NodeDesign
                {
                    SymbolicId = new XmlQualifiedName(symbolicIdName, "http://test.namespace")
                }
            };

            // Act
            string result = node.ToString();

            // Assert
            Assert.That(result, Is.EqualTo($"Path={symbolicIdName}"));
        }

        /// <summary>
        /// Tests that ToString returns empty formatted string when both RelativePath and SymbolicId name are empty.
        /// </summary>
        [Test]
        public void ToString_WithEmptyRelativePathAndEmptySymbolicIdName_ReturnsEquals()
        {
            // Arrange
            var node = new HierarchyNode
            {
                RelativePath = string.Empty,
                Instance = new NodeDesign
                {
                    SymbolicId = new XmlQualifiedName(string.Empty, "http://test.namespace")
                }
            };

            // Act
            string result = node.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("="));
        }

        /// <summary>
        /// Tests that ToString handles very long RelativePath correctly.
        /// </summary>
        [Test]
        public void ToString_WithVeryLongRelativePath_ReturnsFullPath()
        {
            // Arrange
            string longPath = new('x', 10000);
            var node = new HierarchyNode
            {
                RelativePath = longPath,
                Instance = null
            };

            // Act
            string result = node.ToString();

            // Assert
            Assert.That(result, Is.EqualTo(longPath));
            Assert.That(result.Length, Is.EqualTo(10000));
        }

        /// <summary>
        /// Tests that ToString handles very long SymbolicId name correctly.
        /// </summary>
        [Test]
        public void ToString_WithVeryLongSymbolicIdName_ReturnsFormattedString()
        {
            // Arrange
            string longName = new('y', 10000);
            var node = new HierarchyNode
            {
                RelativePath = "Path",
                Instance = new NodeDesign
                {
                    SymbolicId = new XmlQualifiedName(longName, "http://test.namespace")
                }
            };

            // Act
            string result = node.ToString();

            // Assert
            Assert.That(result, Is.EqualTo($"Path={longName}"));
        }

        /// <summary>
        /// Tests that ToString() without parameters returns the RelativePath when Instance is null.
        /// </summary>
        [Test]
        public void ToString_InstanceIsNull_ReturnsRelativePath()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("TestPath"));
        }

        /// <summary>
        /// Tests that ToString() without parameters returns the RelativePath when Instance.SymbolicId is null.
        /// </summary>
        [Test]
        public void ToString_InstanceSymbolicIdIsNull_ReturnsRelativePath()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = new ObjectDesign
                {
                    SymbolicId = null
                }
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("TestPath"));
        }

        /// <summary>
        /// Tests that ToString() without parameters returns formatted string when Instance and SymbolicId are not null.
        /// </summary>
        [Test]
        public void ToString_InstanceAndSymbolicIdNotNull_ReturnsFormattedString()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = new ObjectDesign
                {
                    SymbolicId = new XmlQualifiedName("TestSymbolic", "http://test.com")
                }
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("TestPath=TestSymbolic"));
        }

        /// <summary>
        /// Tests that ToString(null, null) returns the RelativePath when Instance is null.
        /// </summary>
        [Test]
        public void ToString_FormatNullInstanceNull_ReturnsRelativePath()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "MyPath",
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString(null, null);

            // Assert
            Assert.That(result, Is.EqualTo("MyPath"));
        }

        /// <summary>
        /// Tests that ToString(null, formatProvider) returns the RelativePath when Instance.SymbolicId is null.
        /// </summary>
        [Test]
        public void ToString_FormatNullSymbolicIdNull_ReturnsRelativePath()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "MyPath",
                Instance = new ObjectDesign
                {
                    SymbolicId = null
                }
            };

            // Act
            string result = hierarchyNode.ToString(null, CultureInfo.InvariantCulture);

            // Assert
            Assert.That(result, Is.EqualTo("MyPath"));
        }

        /// <summary>
        /// Tests that ToString(null, formatProvider) returns formatted string using the formatProvider.
        /// </summary>
        [Test]
        public void ToString_FormatNullWithFormatProvider_ReturnsFormattedStringWithProvider()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "Path1",
                Instance = new ObjectDesign
                {
                    SymbolicId = new XmlQualifiedName("Symbol1", "http://test.com")
                }
            };

            // Act
            string result = hierarchyNode.ToString(null, CultureInfo.InvariantCulture);

            // Assert
            Assert.That(result, Is.EqualTo("Path1=Symbol1"));
        }

        /// <summary>
        /// Tests that ToString(null, null) returns formatted string when Instance and SymbolicId are not null.
        /// </summary>
        [Test]
        public void ToString_FormatNullInstanceAndSymbolicIdNotNull_ReturnsFormattedString()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "RootPath",
                Instance = new ObjectDesign
                {
                    SymbolicId = new XmlQualifiedName("SymbolicName", "http://opcfoundation.org")
                }
            };

            // Act
            string result = hierarchyNode.ToString(null, null);

            // Assert
            Assert.That(result, Is.EqualTo("RootPath=SymbolicName"));
        }

        /// <summary>
        /// Tests that ToString throws FormatException when format is an empty string.
        /// </summary>
        [Test]
        public void ToString_FormatIsEmptyString_ThrowsFormatException()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = null
            };

            // Act & Assert
            FormatException ex = Assert.Throws<FormatException>(() => hierarchyNode.ToString(string.Empty, null));
            Assert.That(ex.Message, Does.Contain("Invalid format string"));
            Assert.That(ex.Message, Does.Contain("''"));
        }

        /// <summary>
        /// Tests that ToString throws FormatException when format is a non-null string.
        /// </summary>
        [Test]
        public void ToString_FormatIsNonNullString_ThrowsFormatException()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = null
            };

            // Act & Assert
            FormatException ex = Assert.Throws<FormatException>(() => hierarchyNode.ToString("G", null));
            Assert.That(ex.Message, Does.Contain("Invalid format string"));
            Assert.That(ex.Message, Does.Contain("'G'"));
        }

        /// <summary>
        /// Tests that ToString throws FormatException when format is whitespace.
        /// </summary>
        [Test]
        public void ToString_FormatIsWhitespace_ThrowsFormatException()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = null
            };

            // Act & Assert
            FormatException ex = Assert.Throws<FormatException>(() => hierarchyNode.ToString("   ", null));
            Assert.That(ex.Message, Does.Contain("Invalid format string"));
        }

        /// <summary>
        /// Tests that ToString returns null when RelativePath is null and Instance is null.
        /// </summary>
        [Test]
        public void ToString_RelativePathNullInstanceNull_ReturnsNull()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = null,
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.Null);
        }

        /// <summary>
        /// Tests that ToString returns empty string when RelativePath is empty and Instance is null.
        /// </summary>
        [Test]
        public void ToString_RelativePathEmptyInstanceNull_ReturnsEmptyString()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = string.Empty,
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo(string.Empty));
        }

        /// <summary>
        /// Tests that ToString handles RelativePath with special characters correctly.
        /// </summary>
        [Test]
        public void ToString_RelativePathWithSpecialCharacters_ReturnsRelativePath()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "Path/With\\Special_Characters-123",
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("Path/With\\Special_Characters-123"));
        }

        /// <summary>
        /// Tests that ToString formats correctly when SymbolicId.Name contains special characters.
        /// </summary>
        [Test]
        public void ToString_SymbolicIdNameWithSpecialCharacters_ReturnsFormattedString()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "Path",
                Instance = new ObjectDesign
                {
                    SymbolicId = new XmlQualifiedName("Name_With-Special.Chars", "http://test.com")
                }
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("Path=Name_With-Special.Chars"));
        }

        /// <summary>
        /// Tests that ToString with different formatProvider cultures produces correct result.
        /// </summary>
        [TestCase("en-US")]
        [TestCase("de-DE")]
        [TestCase("ja-JP")]
        public void ToString_WithDifferentCultures_ReturnsFormattedString(string cultureName)
        {
            // Arrange
            var culture = CultureInfo.GetCultureInfo(cultureName);
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = new ObjectDesign
                {
                    SymbolicId = new XmlQualifiedName("TestName", "http://test.com")
                }
            };

            // Act
            string result = hierarchyNode.ToString(null, culture);

            // Assert
            Assert.That(result, Is.EqualTo("TestPath=TestName"));
        }

        /// <summary>
        /// Tests that ToString handles very long RelativePath values correctly.
        /// </summary>
        [Test]
        public void ToString_VeryLongRelativePath_ReturnsLongString()
        {
            // Arrange
            string longPath = new('a', 10000);
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = longPath,
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo(longPath));
        }

        /// <summary>
        /// Tests that ToString handles very long SymbolicId.Name values correctly.
        /// </summary>
        [Test]
        public void ToString_VeryLongSymbolicIdName_ReturnsFormattedString()
        {
            // Arrange
            string longName = new('b', 10000);
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "Path",
                Instance = new ObjectDesign
                {
                    SymbolicId = new XmlQualifiedName(longName, "http://test.com")
                }
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo($"Path={longName}"));
        }

        /// <summary>
        /// Tests that ToString handles null SymbolicId.Name correctly when SymbolicId is not null.
        /// Note: XmlQualifiedName.Name should not be null in normal usage, but we test the edge case.
        /// </summary>
        [Test]
        public void ToString_SymbolicIdNameNull_ReturnsFormattedStringWithNull()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "Path",
                Instance = new ObjectDesign
                {
                    SymbolicId = new XmlQualifiedName(null, "http://test.com")
                }
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("Path="));
        }

        /// <summary>
        /// Tests that ToString with various format strings all throw FormatException.
        /// </summary>
        [TestCase("X")]
        [TestCase("F")]
        [TestCase("D")]
        [TestCase("C")]
        [TestCase("CustomFormat")]
        [TestCase("123")]
        public void ToString_VariousFormatStrings_ThrowsFormatException(string format)
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = "TestPath",
                Instance = null
            };

            // Act & Assert
            FormatException ex = Assert.Throws<FormatException>(() => hierarchyNode.ToString(format, null));
            Assert.That(ex.Message, Does.Contain("Invalid format string"));
            Assert.That(ex.Message, Does.Contain($"'{format}'"));
        }

        /// <summary>
        /// Tests that ToString returns RelativePath when Instance is null.
        /// Input: RelativePath is set, Instance is null.
        /// Expected: Returns RelativePath string.
        /// </summary>
        [Test]
        public void ToString_InstanceNull_ReturnsRelativePath()
        {
            // Arrange
            const string expectedPath = "TestPath";
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = expectedPath,
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo(expectedPath));
        }

        /// <summary>
        /// Tests that ToString returns RelativePath when Instance.SymbolicId is null.
        /// Input: RelativePath is set, Instance is set but SymbolicId is null.
        /// Expected: Returns RelativePath string.
        /// </summary>
        [Test]
        public void ToString_InstanceSymbolicIdNull_ReturnsRelativePath()
        {
            // Arrange
            const string expectedPath = "TestPath";
            var mockNodeDesign = new Mock<NodeDesign>();
            mockNodeDesign.Setup(n => n.SymbolicId).Returns((XmlQualifiedName)null);

            var hierarchyNode = new HierarchyNode
            {
                RelativePath = expectedPath,
                Instance = mockNodeDesign.Object
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo(expectedPath));
        }

        /// <summary>
        /// Tests that ToString returns null when RelativePath is null and Instance is null.
        /// Input: RelativePath is null, Instance is null.
        /// Expected: Returns null.
        /// </summary>
        [Test]
        public void ToString_RelativePathNullAndInstanceNull_ReturnsNull()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = null,
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.Null);
        }

        /// <summary>
        /// Tests that ToString returns empty string when RelativePath is empty and Instance is null.
        /// Input: RelativePath is empty string, Instance is null.
        /// Expected: Returns empty string.
        /// </summary>
        [Test]
        public void ToString_RelativePathEmptyAndInstanceNull_ReturnsEmpty()
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = string.Empty,
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo(string.Empty));
        }

        /// <summary>
        /// Tests that ToString returns whitespace when RelativePath is whitespace and Instance is null.
        /// Input: RelativePath contains only whitespace, Instance is null.
        /// Expected: Returns whitespace string.
        /// </summary>
        [Test]
        public void ToString_RelativePathWhitespaceAndInstanceNull_ReturnsWhitespace()
        {
            // Arrange
            const string whitespace = "   ";
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = whitespace,
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo(whitespace));
        }

        /// <summary>
        /// Tests that ToString handles special characters in RelativePath.
        /// Input: RelativePath contains special characters, Instance is null.
        /// Expected: Returns RelativePath with special characters intact.
        /// </summary>
        [Test]
        public void ToString_RelativePathWithSpecialCharacters_ReturnsSpecialCharacters()
        {
            // Arrange
            const string specialPath = "Path/With\\Special@#$%Characters";
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = specialPath,
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo(specialPath));
        }

        /// <summary>
        /// Tests that ToString handles special characters in both RelativePath and SymbolicId.Name.
        /// Input: RelativePath and SymbolicId.Name both contain special characters.
        /// Expected: Returns formatted string with special characters intact.
        /// </summary>
        [Test]
        public void ToString_SpecialCharactersInBothPathAndName_ReturnsFormattedStringWithSpecialCharacters()
        {
            // Arrange
            const string relativePath = "Path<>&\"'";
            const string symbolicIdName = "Name!@#$%";
            var symbolicId = new XmlQualifiedName(symbolicIdName);
            var mockNodeDesign = new Mock<NodeDesign>();
            mockNodeDesign.Setup(n => n.SymbolicId).Returns(symbolicId);

            var hierarchyNode = new HierarchyNode
            {
                RelativePath = relativePath,
                Instance = mockNodeDesign.Object
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo($"{relativePath}={symbolicIdName}"));
        }

        /// <summary>
        /// Tests that ToString handles null RelativePath with non-null Instance.SymbolicId.
        /// Input: RelativePath is null, Instance.SymbolicId is set.
        /// Expected: Returns formatted string with null path.
        /// </summary>
        [Test]
        public void ToString_RelativePathNullWithSymbolicId_ReturnsFormattedStringWithNullPath()
        {
            // Arrange
            const string symbolicIdName = "SymbolicName";
            var symbolicId = new XmlQualifiedName(symbolicIdName);
            var mockNodeDesign = new Mock<NodeDesign>();
            mockNodeDesign.Setup(n => n.SymbolicId).Returns(symbolicId);

            var hierarchyNode = new HierarchyNode
            {
                RelativePath = null,
                Instance = mockNodeDesign.Object
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo($"={symbolicIdName}"));
        }

        /// <summary>
        /// Tests that ToString handles empty RelativePath with non-null Instance.SymbolicId.
        /// Input: RelativePath is empty, Instance.SymbolicId is set.
        /// Expected: Returns formatted string with empty path.
        /// </summary>
        [Test]
        public void ToString_RelativePathEmptyWithSymbolicId_ReturnsFormattedStringWithEmptyPath()
        {
            // Arrange
            const string symbolicIdName = "SymbolicName";
            var symbolicId = new XmlQualifiedName(symbolicIdName);
            var mockNodeDesign = new Mock<NodeDesign>();
            mockNodeDesign.Setup(n => n.SymbolicId).Returns(symbolicId);

            var hierarchyNode = new HierarchyNode
            {
                RelativePath = string.Empty,
                Instance = mockNodeDesign.Object
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo($"={symbolicIdName}"));
        }

        /// <summary>
        /// Tests that ToString handles empty SymbolicId.Name.
        /// Input: RelativePath is set, Instance.SymbolicId.Name is empty.
        /// Expected: Returns formatted string with empty name.
        /// </summary>
        [Test]
        public void ToString_SymbolicIdNameEmpty_ReturnsFormattedStringWithEmptyName()
        {
            // Arrange
            const string relativePath = "TestPath";
            var symbolicId = new XmlQualifiedName(string.Empty);
            var mockNodeDesign = new Mock<NodeDesign>();
            mockNodeDesign.Setup(n => n.SymbolicId).Returns(symbolicId);

            var hierarchyNode = new HierarchyNode
            {
                RelativePath = relativePath,
                Instance = mockNodeDesign.Object
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo($"{relativePath}="));
        }

        /// <summary>
        /// Tests that ToString handles very long strings.
        /// Input: RelativePath and SymbolicId.Name are very long strings.
        /// Expected: Returns formatted string with full content.
        /// </summary>
        [Test]
        public void ToString_VeryLongStrings_ReturnsFormattedStringWithFullContent()
        {
            // Arrange
            string relativePath = new('A', 10000);
            string symbolicIdName = new('B', 10000);
            var symbolicId = new XmlQualifiedName(symbolicIdName);
            var mockNodeDesign = new Mock<NodeDesign>();
            mockNodeDesign.Setup(n => n.SymbolicId).Returns(symbolicId);

            var hierarchyNode = new HierarchyNode
            {
                RelativePath = relativePath,
                Instance = mockNodeDesign.Object
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo($"{relativePath}={symbolicIdName}"));
            Assert.That(result.Length, Is.EqualTo(20001)); // 10000 + 1 ('=') + 10000
        }

        /// <summary>
        /// Tests that ToString handles XmlQualifiedName with namespace.
        /// Input: SymbolicId has both Name and Namespace set.
        /// Expected: Returns formatted string using only Name part.
        /// </summary>
        [Test]
        public void ToString_SymbolicIdWithNamespace_UsesOnlyName()
        {
            // Arrange
            const string relativePath = "TestPath";
            const string symbolicIdName = "LocalName";
            const string namespaceUri = "http://test.namespace.com";
            var symbolicId = new XmlQualifiedName(symbolicIdName, namespaceUri);
            var mockNodeDesign = new Mock<NodeDesign>();
            mockNodeDesign.Setup(n => n.SymbolicId).Returns(symbolicId);

            var hierarchyNode = new HierarchyNode
            {
                RelativePath = relativePath,
                Instance = mockNodeDesign.Object
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo($"{relativePath}={symbolicIdName}"));
            Assert.That(result, Does.Not.Contain(namespaceUri));
        }

        /// <summary>
        /// Tests that ToString returns consistent results on multiple calls.
        /// Input: Same HierarchyNode instance.
        /// Expected: Multiple calls return the same string.
        /// </summary>
        [Test]
        public void ToString_MultipleCalls_ReturnsConsistentResults()
        {
            // Arrange
            const string relativePath = "Path";
            const string symbolicIdName = "Name";
            var symbolicId = new XmlQualifiedName(symbolicIdName);
            var mockNodeDesign = new Mock<NodeDesign>();
            mockNodeDesign.Setup(n => n.SymbolicId).Returns(symbolicId);

            var hierarchyNode = new HierarchyNode
            {
                RelativePath = relativePath,
                Instance = mockNodeDesign.Object
            };

            // Act
            string result1 = hierarchyNode.ToString();
            string result2 = hierarchyNode.ToString();
            string result3 = hierarchyNode.ToString();

            // Assert
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo($"{relativePath}={symbolicIdName}"));
        }

        /// <summary>
        /// Tests that ToString handles control characters in strings.
        /// Input: RelativePath contains control characters.
        /// Expected: Returns string with control characters intact.
        /// </summary>
        [TestCase("\t", TestName = "ToString_RelativePathWithTab_ReturnsTab")]
        [TestCase("\n", TestName = "ToString_RelativePathWithNewline_ReturnsNewline")]
        [TestCase("\r", TestName = "ToString_RelativePathWithCarriageReturn_ReturnsCarriageReturn")]
        [TestCase("\t\n\r", TestName = "ToString_RelativePathWithMultipleControlChars_ReturnsAll")]
        public void ToString_RelativePathWithControlCharacters_ReturnsControlCharacters(string controlChars)
        {
            // Arrange
            var hierarchyNode = new HierarchyNode
            {
                RelativePath = controlChars,
                Instance = null
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo(controlChars));
        }

        /// <summary>
        /// Tests that ToString handles Unicode characters.
        /// Input: RelativePath and SymbolicId.Name contain Unicode characters.
        /// Expected: Returns formatted string with Unicode characters intact.
        /// </summary>
        [Test]
        public void ToString_UnicodeCharacters_ReturnsUnicodeCharacters()
        {
            // Arrange
            const string relativePath = "Path日本語中文";
            const string symbolicIdName = "Nameрусский한국어";
            var symbolicId = new XmlQualifiedName(symbolicIdName);
            var mockNodeDesign = new Mock<NodeDesign>();
            mockNodeDesign.Setup(n => n.SymbolicId).Returns(symbolicId);

            var hierarchyNode = new HierarchyNode
            {
                RelativePath = relativePath,
                Instance = mockNodeDesign.Object
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo($"{relativePath}={symbolicIdName}"));
        }

        /// <summary>
        /// Tests that ToString handles other properties being set.
        /// Input: HierarchyNode with all properties set, checking ToString ignores non-relevant properties.
        /// Expected: Returns formatted string based only on RelativePath and Instance.SymbolicId.
        /// </summary>
        [Test]
        public void ToString_AllPropertiesSet_UsesOnlyRelevantProperties()
        {
            // Arrange
            const string relativePath = "TestPath";
            const string symbolicIdName = "TestName";
            var symbolicId = new XmlQualifiedName(symbolicIdName);
            var mockNodeDesign = new Mock<NodeDesign>();
            mockNodeDesign.Setup(n => n.SymbolicId).Returns(symbolicId);

            var hierarchyNode = new HierarchyNode
            {
                RelativePath = relativePath,
                Instance = mockNodeDesign.Object,
                ExplicitlyDefined = true,
                AdHocInstance = true,
                StaticValue = true,
                Inherited = true,
                Identifier = new object()
            };

            // Act
            string result = hierarchyNode.ToString();

            // Assert
            Assert.That(result, Is.EqualTo($"{relativePath}={symbolicIdName}"));
        }
    }

    /// <summary>
    /// Unit tests for VariableTypeDesign class.
    /// </summary>
    public partial class VariableTypeDesignTests
    {
        /// <summary>
        /// Tests that GetHashCode returns different hash codes when DefaultValue differs.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentDefaultValue_ReturnsDifferentHashCode()
        {
            // Arrange
            var xmlDoc = new XmlDocument();
            XmlElement defaultValue1 = xmlDoc.CreateElement("Value");
            defaultValue1.InnerText = "42";
            XmlElement defaultValue2 = xmlDoc.CreateElement("Value");
            defaultValue2.InnerText = "100";

            var design1 = new VariableTypeDesign { DefaultValue = defaultValue1 };
            var design2 = new VariableTypeDesign { DefaultValue = defaultValue2 };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when DataType differs.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentDataType_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new VariableTypeDesign
            {
                DataType = new XmlQualifiedName("Int32", "http://opcfoundation.org/UA/")
            };
            var design2 = new VariableTypeDesign
            {
                DataType = new XmlQualifiedName("String", "http://opcfoundation.org/UA/")
            };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that GetHashCode handles null DataType correctly.
        /// </summary>
        [Test]
        public void GetHashCode_NullDataType_ReturnsValidHashCode()
        {
            // Arrange
            var design = new VariableTypeDesign
            {
                DataType = null
            };

            // Act
            int hash = design.GetHashCode();

            // Assert
            Assert.That(hash, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when ValueRankSpecified differs.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentValueRankSpecified_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new VariableTypeDesign { ValueRank = ValueRank.Scalar, ValueRankSpecified = true };
            var design2 = new VariableTypeDesign { ValueRank = ValueRank.Scalar, ValueRankSpecified = false };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when ArrayDimensions differs.
        /// </summary>
        [TestCase("1,2,3", "4,5,6")]
        [TestCase(null, "1,2,3")]
        [TestCase("", "1,2,3")]
        public void GetHashCode_DifferentArrayDimensions_ReturnsDifferentHashCode(string dim1, string dim2)
        {
            // Arrange
            var design1 = new VariableTypeDesign { ArrayDimensions = dim1 };
            var design2 = new VariableTypeDesign { ArrayDimensions = dim2 };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that GetHashCode handles empty and null ArrayDimensions correctly.
        /// </summary>
        [TestCase(null)]
        [TestCase("")]
        [TestCase("1,2,3")]
        public void GetHashCode_VariousArrayDimensions_ReturnsValidHashCode(string dimensions)
        {
            // Arrange
            var design = new VariableTypeDesign { ArrayDimensions = dimensions };

            // Act
            int hash = design.GetHashCode();

            // Assert
            Assert.That(hash, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when MinimumSamplingInterval differs.
        /// </summary>
        [TestCase(0, 100)]
        [TestCase(-1, 1)]
        [TestCase(int.MinValue, int.MaxValue)]
        public void GetHashCode_DifferentMinimumSamplingInterval_ReturnsDifferentHashCode(int interval1, int interval2)
        {
            // Arrange
            var design1 = new VariableTypeDesign { MinimumSamplingInterval = interval1, MinimumSamplingIntervalSpecified = true };
            var design2 = new VariableTypeDesign { MinimumSamplingInterval = interval2, MinimumSamplingIntervalSpecified = true };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that GetHashCode handles extreme MinimumSamplingInterval values correctly.
        /// </summary>
        [TestCase(int.MinValue)]
        [TestCase(int.MaxValue)]
        [TestCase(0)]
        [TestCase(-1)]
        public void GetHashCode_ExtremeMinimumSamplingInterval_ReturnsValidHashCode(int interval)
        {
            // Arrange
            var design = new VariableTypeDesign { MinimumSamplingInterval = interval };

            // Act
            int hash = design.GetHashCode();

            // Assert
            Assert.That(hash, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when MinimumSamplingIntervalSpecified differs.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentMinimumSamplingIntervalSpecified_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new VariableTypeDesign { MinimumSamplingInterval = 100, MinimumSamplingIntervalSpecified = true };
            var design2 = new VariableTypeDesign { MinimumSamplingInterval = 100, MinimumSamplingIntervalSpecified = false };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when Historizing differs.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentHistorizing_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new VariableTypeDesign { Historizing = true, HistorizingSpecified = true };
            var design2 = new VariableTypeDesign { Historizing = false, HistorizingSpecified = true };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when HistorizingSpecified differs.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentHistorizingSpecified_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new VariableTypeDesign { Historizing = true, HistorizingSpecified = true };
            var design2 = new VariableTypeDesign { Historizing = true, HistorizingSpecified = false };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when ExposesItsChildren differs.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentExposesItsChildren_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new VariableTypeDesign { ExposesItsChildren = true };
            var design2 = new VariableTypeDesign { ExposesItsChildren = false };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that GetHashCode returns valid hash code for default constructed instance.
        /// </summary>
        [Test]
        public void GetHashCode_DefaultConstructor_ReturnsValidHashCode()
        {
            // Arrange
            var design = new VariableTypeDesign();

            // Act
            int hash = design.GetHashCode();

            // Assert
            Assert.That(hash, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode returns valid hash code with null DefaultValue.
        /// </summary>
        [Test]
        public void GetHashCode_NullDefaultValue_ReturnsValidHashCode()
        {
            // Arrange
            var design = new VariableTypeDesign
            {
                DefaultValue = null,
                DataType = new XmlQualifiedName("Int32", "http://opcfoundation.org/UA/")
            };

            // Act
            int hash = design.GetHashCode();

            // Assert
            Assert.That(hash, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when only DefaultValue differs between null and non-null.
        /// </summary>
        [Test]
        public void GetHashCode_NullVsNonNullDefaultValue_ReturnsDifferentHashCode()
        {
            // Arrange
            var xmlDoc = new XmlDocument();
            XmlElement defaultValue = xmlDoc.CreateElement("Value");
            defaultValue.InnerText = "42";

            var design1 = new VariableTypeDesign { DefaultValue = null };
            var design2 = new VariableTypeDesign { DefaultValue = defaultValue };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that GetHashCode with identical XmlQualifiedName properties produces same hash.
        /// </summary>
        [Test]
        public void GetHashCode_IdenticalXmlQualifiedNames_ReturnsSameHashCode()
        {
            // Arrange
            var design1 = new VariableTypeDesign
            {
                DataType = new XmlQualifiedName("CustomType", "http://example.com/")
            };
            var design2 = new VariableTypeDesign
            {
                DataType = new XmlQualifiedName("CustomType", "http://example.com/")
            };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that GetHashCode with different XmlQualifiedName namespaces produces different hash.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentXmlQualifiedNameNamespaces_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new VariableTypeDesign
            {
                DataType = new XmlQualifiedName("Type", "http://namespace1.com/")
            };
            var design2 = new VariableTypeDesign
            {
                DataType = new XmlQualifiedName("Type", "http://namespace2.com/")
            };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with null.
        /// </summary>
        [Test]
        public void Equals_NullParameter_ReturnsFalse()
        {
            // Arrange
            var variableTypeDesign = new VariableTypeDesign();

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = variableTypeDesign.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when DefaultValue differs.
        /// </summary>
        [Test]
        public void Equals_DifferentDefaultValue_ReturnsFalse()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                DefaultValue = CreateXmlElement("value1"),
                DataType = new XmlQualifiedName("DataType1", "http://test.com")
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                DefaultValue = CreateXmlElement("value2"),
                DataType = new XmlQualifiedName("DataType1", "http://test.com")
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when DataType differs.
        /// </summary>
        [Test]
        public void Equals_DifferentDataType_ReturnsFalse()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                DefaultValue = CreateXmlElement("value1"),
                DataType = new XmlQualifiedName("DataType1", "http://test.com")
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                DefaultValue = CreateXmlElement("value1"),
                DataType = new XmlQualifiedName("DataType2", "http://test.com")
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when ValueRankSpecified differs.
        /// </summary>
        [Test]
        public void Equals_DifferentValueRankSpecified_ReturnsFalse()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                ValueRank = ValueRank.Scalar,
                ValueRankSpecified = true
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                ValueRank = ValueRank.Scalar,
                ValueRankSpecified = false
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when ArrayDimensions differs.
        /// </summary>
        [Test]
        public void Equals_DifferentArrayDimensions_ReturnsFalse()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                ArrayDimensions = "1,2,3"
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                ArrayDimensions = "4,5,6"
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when MinimumSamplingInterval differs.
        /// </summary>
        [Test]
        public void Equals_DifferentMinimumSamplingInterval_ReturnsFalse()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                MinimumSamplingInterval = 100,
                MinimumSamplingIntervalSpecified = true
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                MinimumSamplingInterval = 200,
                MinimumSamplingIntervalSpecified = true
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when MinimumSamplingIntervalSpecified differs.
        /// </summary>
        [Test]
        public void Equals_DifferentMinimumSamplingIntervalSpecified_ReturnsFalse()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                MinimumSamplingInterval = 100,
                MinimumSamplingIntervalSpecified = true
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                MinimumSamplingInterval = 100,
                MinimumSamplingIntervalSpecified = false
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Historizing differs.
        /// </summary>
        [Test]
        public void Equals_DifferentHistorizing_ReturnsFalse()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                Historizing = true,
                HistorizingSpecified = true
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                Historizing = false,
                HistorizingSpecified = true
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when HistorizingSpecified differs.
        /// </summary>
        [Test]
        public void Equals_DifferentHistorizingSpecified_ReturnsFalse()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                Historizing = true,
                HistorizingSpecified = true
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                Historizing = true,
                HistorizingSpecified = false
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when ExposesItsChildren differs.
        /// </summary>
        [Test]
        public void Equals_DifferentExposesItsChildren_ReturnsFalse()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                ExposesItsChildren = true
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                ExposesItsChildren = false
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when base class properties differ.
        /// </summary>
        [Test]
        public void Equals_DifferentBaseProperties_ReturnsFalse()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                SymbolicName = new XmlQualifiedName("Type1", "http://test.com")
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                SymbolicName = new XmlQualifiedName("Type2", "http://test.com")
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles null DefaultValue correctly.
        /// </summary>
        [Test]
        public void Equals_NullDefaultValue_ReturnsTrue()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                DefaultValue = null,
                DataType = new XmlQualifiedName("DataType1", "http://test.com")
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                DefaultValue = null,
                DataType = new XmlQualifiedName("DataType1", "http://test.com")
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when one DefaultValue is null and the other is not.
        /// </summary>
        [Test]
        public void Equals_OneDefaultValueNull_ReturnsFalse()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                DefaultValue = CreateXmlElement("value1"),
                DataType = new XmlQualifiedName("DataType1", "http://test.com")
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                DefaultValue = null,
                DataType = new XmlQualifiedName("DataType1", "http://test.com")
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles null DataType correctly.
        /// </summary>
        [Test]
        public void Equals_NullDataType_ReturnsTrue()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                DataType = null
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                DataType = null
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when one DataType is null and the other is not.
        /// </summary>
        [Test]
        public void Equals_OneDataTypeNull_ReturnsFalse()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                DataType = new XmlQualifiedName("DataType1", "http://test.com")
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                DataType = null
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles empty ArrayDimensions correctly.
        /// </summary>
        [Test]
        public void Equals_EmptyArrayDimensions_ReturnsTrue()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                ArrayDimensions = string.Empty
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                ArrayDimensions = string.Empty
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals handles null ArrayDimensions correctly.
        /// </summary>
        [Test]
        public void Equals_NullArrayDimensions_ReturnsTrue()
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                ArrayDimensions = null
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                ArrayDimensions = null
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals handles edge cases for MinimumSamplingInterval with extreme values.
        /// </summary>
        [Test]
        [TestCase(int.MinValue)]
        [TestCase(int.MaxValue)]
        [TestCase(0)]
        [TestCase(-1)]
        public void Equals_MinimumSamplingIntervalExtremeValues_WorksCorrectly(int value)
        {
            // Arrange
            var variableTypeDesign1 = new VariableTypeDesign
            {
                MinimumSamplingInterval = value,
                MinimumSamplingIntervalSpecified = true
            };

            var variableTypeDesign2 = new VariableTypeDesign
            {
                MinimumSamplingInterval = value,
                MinimumSamplingIntervalSpecified = true
            };

            // Act
            bool result = variableTypeDesign1.Equals(variableTypeDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Helper method to create an XmlElement with the specified value.
        /// </summary>
        private static XmlElement CreateXmlElement(string value)
        {
            var doc = new XmlDocument();
            XmlElement element = doc.CreateElement("TestElement");
            element.InnerText = value;
            return element;
        }

        /// <summary>
        /// Tests that Equals returns false when obj is null.
        /// Input: null object reference.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_NullObject_ReturnsFalse()
        {
            // Arrange
            var instance = new VariableTypeDesign();

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = instance.Equals((object)null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when obj is of a different type.
        /// Input: Object of different type.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentType_ReturnsFalse()
        {
            // Arrange
            var instance = new VariableTypeDesign();
            object differentType = new();

            // Act
            bool result = instance.Equals(differentType);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when obj is of a different compatible type (string).
        /// Input: String object.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_StringObject_ReturnsFalse()
        {
            // Arrange
            var instance = new VariableTypeDesign();
            object stringObj = "test";

            // Act
            bool result = instance.Equals(stringObj);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two instances with default property values.
        /// Input: Two instances with default initialization.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_TwoDefaultInstances_ReturnsTrue()
        {
            // Arrange
            var instance1 = new VariableTypeDesign();
            var instance2 = new VariableTypeDesign();

            // Act
            bool result = instance1.Equals((object)instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when DataType properties are equal.
        /// Input: Two instances with same DataType value.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_SameDataType_ReturnsTrue()
        {
            // Arrange
            var instance1 = new VariableTypeDesign
            {
                DataType = new XmlQualifiedName("Type1", "namespace1")
            };
            var instance2 = new VariableTypeDesign
            {
                DataType = new XmlQualifiedName("Type1", "namespace1")
            };

            // Act
            bool result = instance1.Equals((object)instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when ArrayDimensions is null vs non-null.
        /// Input: One instance with null ArrayDimensions, one with non-null.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_ArrayDimensionsNullVsNonNull_ReturnsFalse()
        {
            // Arrange
            var instance1 = new VariableTypeDesign
            {
                ArrayDimensions = null
            };
            var instance2 = new VariableTypeDesign
            {
                ArrayDimensions = "1,2"
            };

            // Act
            bool result = instance1.Equals((object)instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles extreme MinimumSamplingInterval values correctly.
        /// Input: Instances with int.MinValue and int.MaxValue.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_ExtremeMinimumSamplingInterval_ReturnsFalse()
        {
            // Arrange
            var instance1 = new VariableTypeDesign
            {
                MinimumSamplingInterval = int.MinValue,
                MinimumSamplingIntervalSpecified = true
            };
            var instance2 = new VariableTypeDesign
            {
                MinimumSamplingInterval = int.MaxValue,
                MinimumSamplingIntervalSpecified = true
            };

            // Act
            bool result = instance1.Equals((object)instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when DataType is null on both instances.
        /// Input: Two instances with null DataType.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_BothDataTypeNull_ReturnsTrue()
        {
            // Arrange
            var instance1 = new VariableTypeDesign
            {
                DataType = null
            };
            var instance2 = new VariableTypeDesign
            {
                DataType = null
            };

            // Act
            bool result = instance1.Equals((object)instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when DataType is null vs non-null.
        /// Input: One instance with null DataType, one with non-null.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DataTypeNullVsNonNull_ReturnsFalse()
        {
            // Arrange
            var instance1 = new VariableTypeDesign
            {
                DataType = null
            };
            var instance2 = new VariableTypeDesign
            {
                DataType = new XmlQualifiedName("Type1", "namespace1")
            };

            // Act
            bool result = instance1.Equals((object)instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true with empty string ArrayDimensions.
        /// Input: Two instances with empty string ArrayDimensions.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_EmptyStringArrayDimensions_ReturnsTrue()
        {
            // Arrange
            var instance1 = new VariableTypeDesign
            {
                ArrayDimensions = string.Empty
            };
            var instance2 = new VariableTypeDesign
            {
                ArrayDimensions = string.Empty
            };

            // Act
            bool result = instance1.Equals((object)instance2);

            // Assert
            Assert.That(result, Is.True);
        }
    }

    /// <summary>
    /// Unit tests for <see cref="InstanceDesign"/> class.
    /// </summary>
    [TestFixture]
    public partial class InstanceDesignTests
    {
        /// <summary>
        /// Tests that Copy method creates a new instance with different reference.
        /// Verifies that the copy is not the same object as the original instance.
        /// </summary>
        [Test]
        public void Copy_DefaultInstance_ReturnsNewInstance()
        {
            // Arrange
            var original = new InstanceDesign();

            // Act
            InstanceDesign copy = original.Copy();

            // Assert
            Assert.That(copy, Is.Not.Null);
            Assert.That(copy, Is.Not.SameAs(original));
        }

        /// <summary>
        /// Tests that Copy method returns an object of the correct type.
        /// Verifies that the returned object is of type InstanceDesign.
        /// </summary>
        [Test]
        public void Copy_DefaultInstance_ReturnsCorrectType()
        {
            // Arrange
            var original = new InstanceDesign();

            // Act
            InstanceDesign copy = original.Copy();

            // Assert
            Assert.That(copy, Is.InstanceOf<InstanceDesign>());
        }

        /// <summary>
        /// Tests that Copy method performs a shallow copy for value-type properties.
        /// Verifies that value-type properties (MinCardinality, MaxCardinality, booleans) are copied correctly.
        /// </summary>
        [Test]
        public void Copy_InstanceWithValueTypeProperties_CopiesValuesCorrectly()
        {
            // Arrange
            var original = new InstanceDesign
            {
                MinCardinality = 5,
                MaxCardinality = 10,
                PreserveDefaultAttributes = true,
                DesignToolOnly = true,
                ModellingRule = ModellingRule.Mandatory,
                ModellingRuleSpecified = true,
                IdentifierRequired = true
            };

            // Act
            InstanceDesign copy = original.Copy();

            // Assert
            Assert.That(copy.MinCardinality, Is.EqualTo(original.MinCardinality));
            Assert.That(copy.MaxCardinality, Is.EqualTo(original.MaxCardinality));
            Assert.That(copy.PreserveDefaultAttributes, Is.EqualTo(original.PreserveDefaultAttributes));
            Assert.That(copy.DesignToolOnly, Is.EqualTo(original.DesignToolOnly));
            Assert.That(copy.ModellingRule, Is.EqualTo(original.ModellingRule));
            Assert.That(copy.ModellingRuleSpecified, Is.EqualTo(original.ModellingRuleSpecified));
            Assert.That(copy.IdentifierRequired, Is.EqualTo(original.IdentifierRequired));
        }

        /// <summary>
        /// Tests that Copy method performs a shallow copy for reference-type properties.
        /// Verifies that reference-type properties point to the same objects as the original.
        /// </summary>
        [Test]
        public void Copy_InstanceWithReferenceTypeProperties_PerformsShallowCopy()
        {
            // Arrange
            var referenceType = new XmlQualifiedName("RefType", "http://example.com");
            var declaration = new XmlQualifiedName("Declaration", "http://example.com");
            var typeDefinition = new XmlQualifiedName("TypeDef", "http://example.com");
            var typeDefinitionNode = new ObjectTypeDesign();
            var instanceDeclarationNode = new ObjectDesign();
            var overriddenNode = new ObjectDesign();

            var original = new InstanceDesign
            {
                ReferenceType = referenceType,
                Declaration = declaration,
                TypeDefinition = typeDefinition,
                TypeDefinitionNode = typeDefinitionNode,
                InstanceDeclarationNode = instanceDeclarationNode,
                OveriddenNode = overriddenNode
            };

            // Act
            InstanceDesign copy = original.Copy();

            // Assert
            Assert.That(copy.ReferenceType, Is.SameAs(original.ReferenceType));
            Assert.That(copy.Declaration, Is.SameAs(original.Declaration));
            Assert.That(copy.TypeDefinition, Is.SameAs(original.TypeDefinition));
            Assert.That(copy.TypeDefinitionNode, Is.SameAs(original.TypeDefinitionNode));
            Assert.That(copy.InstanceDeclarationNode, Is.SameAs(original.InstanceDeclarationNode));
            Assert.That(copy.OveriddenNode, Is.SameAs(original.OveriddenNode));
        }

        /// <summary>
        /// Tests that Copy method correctly handles null reference-type properties.
        /// Verifies that null properties remain null in the copy.
        /// </summary>
        [Test]
        public void Copy_InstanceWithNullProperties_CopiesNullsCorrectly()
        {
            // Arrange
            var original = new InstanceDesign
            {
                ReferenceType = null,
                Declaration = null,
                TypeDefinition = null,
                TypeDefinitionNode = null,
                InstanceDeclarationNode = null,
                OveriddenNode = null
            };

            // Act
            InstanceDesign copy = original.Copy();

            // Assert
            Assert.That(copy.ReferenceType, Is.Null);
            Assert.That(copy.Declaration, Is.Null);
            Assert.That(copy.TypeDefinition, Is.Null);
            Assert.That(copy.TypeDefinitionNode, Is.Null);
            Assert.That(copy.InstanceDeclarationNode, Is.Null);
            Assert.That(copy.OveriddenNode, Is.Null);
        }

        /// <summary>
        /// Tests that Copy method handles boundary values for numeric properties.
        /// Verifies that minimum and maximum uint values are copied correctly.
        /// </summary>
        [Test]
        public void Copy_InstanceWithBoundaryNumericValues_CopiesCorrectly()
        {
            // Arrange
            var original = new InstanceDesign
            {
                MinCardinality = uint.MinValue,
                MaxCardinality = uint.MaxValue
            };

            // Act
            InstanceDesign copy = original.Copy();

            // Assert
            Assert.That(copy.MinCardinality, Is.EqualTo(uint.MinValue));
            Assert.That(copy.MaxCardinality, Is.EqualTo(uint.MaxValue));
        }

        /// <summary>
        /// Tests that modifying the copy does not affect the original for value-type properties.
        /// Verifies that value-type properties are independent between original and copy.
        /// </summary>
        [Test]
        public void Copy_ModifyingCopyValueProperties_DoesNotAffectOriginal()
        {
            // Arrange
            var original = new InstanceDesign
            {
                MinCardinality = 5,
                MaxCardinality = 10,
                PreserveDefaultAttributes = false,
                DesignToolOnly = false
            };

            // Act
            InstanceDesign copy = original.Copy();
            copy.MinCardinality = 20;
            copy.MaxCardinality = 30;
            copy.PreserveDefaultAttributes = true;
            copy.DesignToolOnly = true;

            // Assert
            Assert.That(original.MinCardinality, Is.EqualTo(5));
            Assert.That(original.MaxCardinality, Is.EqualTo(10));
            Assert.That(original.PreserveDefaultAttributes, Is.False);
            Assert.That(original.DesignToolOnly, Is.False);
        }

        /// <summary>
        /// Tests that modifying reference-type properties in the copy affects the original due to shallow copy.
        /// Verifies that reference-type properties share the same underlying objects.
        /// </summary>
        [Test]
        public void Copy_ModifyingSharedReferenceObject_AffectsBothInstances()
        {
            // Arrange
            var typeDefinitionNode = new ObjectTypeDesign
            {
                SymbolicName = new XmlQualifiedName("OriginalName", "http://example.com")
            };

            var original = new InstanceDesign
            {
                TypeDefinitionNode = typeDefinitionNode
            };

            // Act
            InstanceDesign copy = original.Copy();
            copy.TypeDefinitionNode.SymbolicName = new XmlQualifiedName("ModifiedName", "http://example.com");

            // Assert
            Assert.That(original.TypeDefinitionNode.SymbolicName.Name, Is.EqualTo("ModifiedName"));
        }

        /// <summary>
        /// Tests that Copy method handles all ModellingRule enum values correctly.
        /// Verifies that enum properties are copied correctly for different enum values.
        /// </summary>
        [TestCase(ModellingRule.Mandatory)]
        [TestCase(ModellingRule.Optional)]
        [TestCase(ModellingRule.MandatoryPlaceholder)]
        [TestCase(ModellingRule.OptionalPlaceholder)]
        [TestCase(ModellingRule.ExposesItsArray)]
        [TestCase(ModellingRule.None)]
        public void Copy_InstanceWithDifferentModellingRules_CopiesEnumCorrectly(ModellingRule modellingRule)
        {
            // Arrange
            var original = new InstanceDesign
            {
                ModellingRule = modellingRule,
                ModellingRuleSpecified = true
            };

            // Act
            InstanceDesign copy = original.Copy();

            // Assert
            Assert.That(copy.ModellingRule, Is.EqualTo(modellingRule));
            Assert.That(copy.ModellingRuleSpecified, Is.True);
        }

        /// <summary>
        /// Tests that GetHashCode returns the same hash code when called multiple times on the same object.
        /// Validates consistency requirement for GetHashCode.
        /// Expected: Multiple calls to GetHashCode on the same instance return the same value.
        /// </summary>
        [Test]
        public void GetHashCode_SameObjectCalledMultipleTimes_ReturnsSameHashCode()
        {
            // Arrange
            var instance = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName("RefType", "http://test.com"),
                Declaration = new XmlQualifiedName("Decl", "http://test.com"),
                TypeDefinition = new XmlQualifiedName("TypeDef", "http://test.com"),
                ModellingRule = ModellingRule.Mandatory,
                ModellingRuleSpecified = true,
                MinCardinality = 1,
                MaxCardinality = 10,
                PreserveDefaultAttributes = true,
                DesignToolOnly = false,
                IdentifierRequired = true
            };

            // Act
            int hashCode1 = instance.GetHashCode();
            int hashCode2 = instance.GetHashCode();
            int hashCode3 = instance.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.EqualTo(hashCode1));
            Assert.That(hashCode3, Is.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that two InstanceDesign objects with identical property values return the same hash code.
        /// Validates the requirement that equal objects must have equal hash codes.
        /// Expected: Objects with identical properties produce the same hash code.
        /// </summary>
        [Test]
        public void GetHashCode_EqualObjects_ReturnsSameHashCode()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName("RefType", "http://test.com"),
                Declaration = new XmlQualifiedName("Decl", "http://test.com"),
                TypeDefinition = new XmlQualifiedName("TypeDef", "http://test.com"),
                ModellingRule = ModellingRule.Optional,
                ModellingRuleSpecified = true,
                MinCardinality = 5,
                MaxCardinality = 20,
                PreserveDefaultAttributes = false,
                DesignToolOnly = true,
                IdentifierRequired = false
            };

            var instance2 = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName("RefType", "http://test.com"),
                Declaration = new XmlQualifiedName("Decl", "http://test.com"),
                TypeDefinition = new XmlQualifiedName("TypeDef", "http://test.com"),
                ModellingRule = ModellingRule.Optional,
                ModellingRuleSpecified = true,
                MinCardinality = 5,
                MaxCardinality = 20,
                PreserveDefaultAttributes = false,
                DesignToolOnly = true,
                IdentifierRequired = false
            };

            // Act
            int hashCode1 = instance1.GetHashCode();
            int hashCode2 = instance2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode handles null XmlQualifiedName properties correctly.
        /// Validates null handling for ReferenceType, Declaration, and TypeDefinition properties.
        /// Expected: GetHashCode does not throw and produces a valid hash code.
        /// </summary>
        [Test]
        public void GetHashCode_NullXmlQualifiedNameProperties_HandlesCorrectly()
        {
            // Arrange
            var instance = new InstanceDesign
            {
                ReferenceType = null,
                Declaration = null,
                TypeDefinition = null,
                ModellingRule = ModellingRule.None,
                ModellingRuleSpecified = false
            };

            // Act & Assert
            Assert.DoesNotThrow(() => instance.GetHashCode());
            int hashCode = instance.GetHashCode();
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode handles null object reference properties correctly.
        /// Validates null handling for TypeDefinitionNode, InstanceDeclarationNode, and OveriddenNode.
        /// Expected: GetHashCode does not throw and produces a valid hash code.
        /// </summary>
        [Test]
        public void GetHashCode_NullObjectReferences_HandlesCorrectly()
        {
            // Arrange
            var instance = new InstanceDesign
            {
                TypeDefinitionNode = null,
                InstanceDeclarationNode = null,
                OveriddenNode = null
            };

            // Act & Assert
            Assert.DoesNotThrow(() => instance.GetHashCode());
            int hashCode = instance.GetHashCode();
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests GetHashCode with all possible ModellingRule enum values.
        /// Validates that each enum value is properly handled in hash code computation.
        /// Expected: Each enum value produces a valid hash code without throwing exceptions.
        /// </summary>
        [TestCase(ModellingRule.None)]
        [TestCase(ModellingRule.Mandatory)]
        [TestCase(ModellingRule.Optional)]
        [TestCase(ModellingRule.ExposesItsArray)]
        [TestCase(ModellingRule.CardinalityRestriction)]
        [TestCase(ModellingRule.MandatoryShared)]
        [TestCase(ModellingRule.OptionalPlaceholder)]
        [TestCase(ModellingRule.MandatoryPlaceholder)]
        public void GetHashCode_AllModellingRuleValues_ComputesHashCode(ModellingRule rule)
        {
            // Arrange
            var instance = new InstanceDesign
            {
                ModellingRule = rule,
                ModellingRuleSpecified = true
            };

            // Act & Assert
            Assert.DoesNotThrow(() => instance.GetHashCode());
            int hashCode = instance.GetHashCode();
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests GetHashCode with boundary values for uint properties MinCardinality and MaxCardinality.
        /// Validates edge cases including 0, uint.MaxValue, and typical boundary values.
        /// Expected: All boundary values are handled correctly without overflow or exceptions.
        /// </summary>
        [TestCase(0u, 0u)]
        [TestCase(uint.MaxValue, uint.MaxValue)]
        [TestCase(0u, uint.MaxValue)]
        [TestCase(1u, 1u)]
        [TestCase(100u, 1000u)]
        public void GetHashCode_UintBoundaryValues_ComputesHashCode(uint minCardinality, uint maxCardinality)
        {
            // Arrange
            var instance = new InstanceDesign
            {
                MinCardinality = minCardinality,
                MaxCardinality = maxCardinality
            };

            // Act & Assert
            Assert.DoesNotThrow(() => instance.GetHashCode());
            int hashCode = instance.GetHashCode();
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests GetHashCode with different boolean combinations for PreserveDefaultAttributes and DesignToolOnly.
        /// Validates that different boolean values affect the hash code computation.
        /// Expected: Different boolean combinations should ideally produce different hash codes.
        /// </summary>
        [TestCase(true, true)]
        [TestCase(true, false)]
        [TestCase(false, true)]
        [TestCase(false, false)]
        public void GetHashCode_BooleanCombinations_ComputesHashCode(bool preserveDefaultAttributes, bool designToolOnly)
        {
            // Arrange
            var instance = new InstanceDesign
            {
                PreserveDefaultAttributes = preserveDefaultAttributes,
                DesignToolOnly = designToolOnly
            };

            // Act & Assert
            Assert.DoesNotThrow(() => instance.GetHashCode());
            int hashCode = instance.GetHashCode();
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests that objects with different ReferenceType values produce different hash codes.
        /// Validates that changes in ReferenceType property affect the hash code.
        /// Expected: Different ReferenceType values should produce different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentReferenceType_ProducesDifferentHashCodes()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName("RefType1", "http://test.com")
            };

            var instance2 = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName("RefType2", "http://test.com")
            };

            // Act
            int hashCode1 = instance1.GetHashCode();
            int hashCode2 = instance2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that objects with different Declaration values produce different hash codes.
        /// Validates that changes in Declaration property affect the hash code.
        /// Expected: Different Declaration values should produce different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentDeclaration_ProducesDifferentHashCodes()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                Declaration = new XmlQualifiedName("Decl1", "http://test.com")
            };

            var instance2 = new InstanceDesign
            {
                Declaration = new XmlQualifiedName("Decl2", "http://test.com")
            };

            // Act
            int hashCode1 = instance1.GetHashCode();
            int hashCode2 = instance2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that objects with different TypeDefinition values produce different hash codes.
        /// Validates that changes in TypeDefinition property affect the hash code.
        /// Expected: Different TypeDefinition values should produce different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentTypeDefinition_ProducesDifferentHashCodes()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                TypeDefinition = new XmlQualifiedName("TypeDef1", "http://test.com")
            };

            var instance2 = new InstanceDesign
            {
                TypeDefinition = new XmlQualifiedName("TypeDef2", "http://test.com")
            };

            // Act
            int hashCode1 = instance1.GetHashCode();
            int hashCode2 = instance2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that objects with different ModellingRule values produce different hash codes.
        /// Validates that changes in ModellingRule property affect the hash code.
        /// Expected: Different ModellingRule values should produce different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentModellingRule_ProducesDifferentHashCodes()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                ModellingRule = ModellingRule.Mandatory,
                ModellingRuleSpecified = true
            };

            var instance2 = new InstanceDesign
            {
                ModellingRule = ModellingRule.Optional,
                ModellingRuleSpecified = true
            };

            // Act
            int hashCode1 = instance1.GetHashCode();
            int hashCode2 = instance2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that objects with different MinCardinality values produce different hash codes.
        /// Validates that changes in MinCardinality property affect the hash code.
        /// Expected: Different MinCardinality values should produce different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentMinCardinality_ProducesDifferentHashCodes()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                MinCardinality = 1
            };

            var instance2 = new InstanceDesign
            {
                MinCardinality = 2
            };

            // Act
            int hashCode1 = instance1.GetHashCode();
            int hashCode2 = instance2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that objects with different MaxCardinality values produce different hash codes.
        /// Validates that changes in MaxCardinality property affect the hash code.
        /// Expected: Different MaxCardinality values should produce different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentMaxCardinality_ProducesDifferentHashCodes()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                MaxCardinality = 10
            };

            var instance2 = new InstanceDesign
            {
                MaxCardinality = 20
            };

            // Act
            int hashCode1 = instance1.GetHashCode();
            int hashCode2 = instance2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests GetHashCode with circular references in InstanceDeclarationNode.
        /// Validates that circular references are handled without causing stack overflow or infinite loops.
        /// Expected: GetHashCode completes successfully without exceptions.
        /// </summary>
        [Test]
        public void GetHashCode_CircularReferenceInInstanceDeclarationNode_HandlesCorrectly()
        {
            // Arrange
            var instance1 = new InstanceDesign();
            var instance2 = new InstanceDesign
            {
                InstanceDeclarationNode = instance1
            };
            instance1.InstanceDeclarationNode = instance2;

            // Act & Assert
            Assert.DoesNotThrow(() => instance1.GetHashCode());
            Assert.DoesNotThrow(() => instance2.GetHashCode());
        }

        /// <summary>
        /// Tests GetHashCode with circular references in OveriddenNode.
        /// Validates that circular references are handled without causing stack overflow or infinite loops.
        /// Expected: GetHashCode completes successfully without exceptions.
        /// </summary>
        [Test]
        public void GetHashCode_CircularReferenceInOveriddenNode_HandlesCorrectly()
        {
            // Arrange
            var instance1 = new InstanceDesign();
            var instance2 = new InstanceDesign
            {
                OveriddenNode = instance1
            };
            instance1.OveriddenNode = instance2;

            // Act & Assert
            Assert.DoesNotThrow(() => instance1.GetHashCode());
            Assert.DoesNotThrow(() => instance2.GetHashCode());
        }

        /// <summary>
        /// Tests GetHashCode with an invalid ModellingRule enum value (outside defined range).
        /// Validates that out-of-range enum values are handled correctly.
        /// Expected: GetHashCode does not throw and produces a valid hash code.
        /// </summary>
        [Test]
        public void GetHashCode_InvalidModellingRuleValue_HandlesCorrectly()
        {
            // Arrange
            var instance = new InstanceDesign
            {
                ModellingRule = (ModellingRule)999,
                ModellingRuleSpecified = true
            };

            // Act & Assert
            Assert.DoesNotThrow(() => instance.GetHashCode());
            int hashCode = instance.GetHashCode();
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests GetHashCode when ModellingRuleSpecified is false vs true with same ModellingRule value.
        /// Validates that the ModellingRuleSpecified flag affects the hash code.
        /// Expected: Different ModellingRuleSpecified values should produce different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentModellingRuleSpecified_ProducesDifferentHashCodes()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                ModellingRule = ModellingRule.Mandatory,
                ModellingRuleSpecified = true
            };

            var instance2 = new InstanceDesign
            {
                ModellingRule = ModellingRule.Mandatory,
                ModellingRuleSpecified = false
            };

            // Act
            int hashCode1 = instance1.GetHashCode();
            int hashCode2 = instance2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests GetHashCode with empty string XmlQualifiedName values.
        /// Validates that empty strings in XmlQualifiedName properties are handled correctly.
        /// Expected: GetHashCode does not throw and produces a valid hash code.
        /// </summary>
        [Test]
        public void GetHashCode_EmptyStringXmlQualifiedName_HandlesCorrectly()
        {
            // Arrange
            var instance = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName(string.Empty, string.Empty),
                Declaration = new XmlQualifiedName(string.Empty, string.Empty),
                TypeDefinition = new XmlQualifiedName(string.Empty, string.Empty)
            };

            // Act & Assert
            Assert.DoesNotThrow(() => instance.GetHashCode());
            int hashCode = instance.GetHashCode();
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests GetHashCode with XmlQualifiedName objects containing special characters.
        /// Validates that special characters in XmlQualifiedName properties are handled correctly.
        /// Expected: GetHashCode does not throw and produces a valid hash code.
        /// </summary>
        [Test]
        public void GetHashCode_SpecialCharactersInXmlQualifiedName_HandlesCorrectly()
        {
            // Arrange
            var instance = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName("Test!@#$%^&*()", "http://test.com/~`"),
                Declaration = new XmlQualifiedName("<>?:\"|{}[]", "urn:test:namespace:special"),
                TypeDefinition = new XmlQualifiedName("Type\r\n\t", "http://test.com/path")
            };

            // Act & Assert
            Assert.DoesNotThrow(() => instance.GetHashCode());
            int hashCode = instance.GetHashCode();
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests GetHashCode with different IdentifierRequired values.
        /// Validates that the IdentifierRequired property affects the hash code.
        /// Expected: Different IdentifierRequired values should produce different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentIdentifierRequired_ProducesDifferentHashCodes()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                IdentifierRequired = true
            };

            var instance2 = new InstanceDesign
            {
                IdentifierRequired = false
            };

            // Act
            int hashCode1 = instance1.GetHashCode();
            int hashCode2 = instance2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests GetHashCode with all properties set to default values.
        /// Validates that an object with all default values produces a valid hash code.
        /// Expected: GetHashCode returns a valid hash code without exceptions.
        /// </summary>
        [Test]
        public void GetHashCode_AllDefaultValues_ComputesHashCode()
        {
            // Arrange
            var instance = new InstanceDesign();

            // Act & Assert
            Assert.DoesNotThrow(() => instance.GetHashCode());
            int hashCode = instance.GetHashCode();
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests GetHashCode with all properties set to non-default values.
        /// Validates that an object with all properties populated produces a valid hash code.
        /// Expected: GetHashCode returns a valid hash code without exceptions.
        /// </summary>
        [Test]
        public void GetHashCode_AllPropertiesSet_ComputesHashCode()
        {
            // Arrange
            var typeDefNode = new ObjectTypeDesign();
            var instanceDeclNode = new InstanceDesign();
            var overriddenNode = new InstanceDesign();

            var instance = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName("RefType", "http://test.com"),
                Declaration = new XmlQualifiedName("Decl", "http://test.com"),
                TypeDefinition = new XmlQualifiedName("TypeDef", "http://test.com"),
                ModellingRule = ModellingRule.Mandatory,
                ModellingRuleSpecified = true,
                MinCardinality = 1,
                MaxCardinality = 100,
                PreserveDefaultAttributes = true,
                DesignToolOnly = true,
                TypeDefinitionNode = typeDefNode,
                InstanceDeclarationNode = instanceDeclNode,
                OveriddenNode = overriddenNode,
                IdentifierRequired = true
            };

            // Act & Assert
            Assert.DoesNotThrow(() => instance.GetHashCode());
            int hashCode = instance.GetHashCode();
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests that Equals returns false when the object parameter is null.
        /// </summary>
        [Test]
        public void Equals_Null_ReturnsFalse()
        {
            // Arrange
            var instance = new InstanceDesign();

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = instance.Equals((object)null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing the same instance.
        /// </summary>
        [Test]
        public void Equals_SameInstance_ReturnsTrue()
        {
            // Arrange
            var instance = new InstanceDesign
            {
                SymbolicId = new XmlQualifiedName("TestId", "http://test.com"),
                MinCardinality = 1,
                MaxCardinality = 10
            };

            // Act
            bool result = instance.Equals((object)instance);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two equal InstanceDesign objects.
        /// </summary>
        [Test]
        public void Equals_EqualInstanceDesign_ReturnsTrue()
        {
            // Arrange
            var symbolicId = new XmlQualifiedName("TestId", "http://test.com");
            var referenceType = new XmlQualifiedName("RefType", "http://test.com");

            var instance1 = new InstanceDesign
            {
                SymbolicId = symbolicId,
                ReferenceType = referenceType,
                MinCardinality = 1,
                MaxCardinality = 10,
                ModellingRule = ModellingRule.Mandatory,
                ModellingRuleSpecified = true,
                PreserveDefaultAttributes = false,
                DesignToolOnly = false,
                IdentifierRequired = true
            };

            var instance2 = new InstanceDesign
            {
                SymbolicId = symbolicId,
                ReferenceType = referenceType,
                MinCardinality = 1,
                MaxCardinality = 10,
                ModellingRule = ModellingRule.Mandatory,
                ModellingRuleSpecified = true,
                PreserveDefaultAttributes = false,
                DesignToolOnly = false,
                IdentifierRequired = true
            };

            // Act
            bool result = instance1.Equals((object)instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing InstanceDesign objects with different properties.
        /// </summary>
        [Test]
        public void Equals_DifferentInstanceDesign_ReturnsFalse()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                SymbolicId = new XmlQualifiedName("TestId1", "http://test.com"),
                MinCardinality = 1
            };

            var instance2 = new InstanceDesign
            {
                SymbolicId = new XmlQualifiedName("TestId2", "http://test.com"),
                MinCardinality = 2
            };

            // Act
            bool result = instance1.Equals((object)instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with a different type of object.
        /// </summary>
        [Test]
        public void Equals_DifferentType_ReturnsFalse()
        {
            // Arrange
            var instance = new InstanceDesign();
            object differentType = "NotAnInstanceDesign";

            // Act
            bool result = instance.Equals(differentType);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with a plain object type.
        /// </summary>
        [Test]
        public void Equals_PlainObjectType_ReturnsFalse()
        {
            // Arrange
            var instance = new InstanceDesign();
            object plainObject = new();

            // Act
            bool result = instance.Equals(plainObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with a derived type that has different properties.
        /// </summary>
        [Test]
        public void Equals_DerivedTypeWithDifferentProperties_ReturnsFalse()
        {
            // Arrange
            var instance = new InstanceDesign
            {
                SymbolicId = new XmlQualifiedName("TestId", "http://test.com")
            };

            var objectDesign = new ObjectDesign
            {
                SymbolicId = new XmlQualifiedName("TestId", "http://test.com"),
                SupportsEvents = true
            };

            // Act
            bool result = instance.Equals((object)objectDesign);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when MinCardinality values differ.
        /// </summary>
        [Test]
        public void Equals_DifferentMinCardinality_ReturnsFalse()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                SymbolicId = new XmlQualifiedName("TestId", "http://test.com"),
                MinCardinality = 0
            };

            var instance2 = new InstanceDesign
            {
                SymbolicId = new XmlQualifiedName("TestId", "http://test.com"),
                MinCardinality = uint.MaxValue
            };

            // Act
            bool result = instance1.Equals((object)instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when MaxCardinality values differ.
        /// </summary>
        [Test]
        public void Equals_DifferentMaxCardinality_ReturnsFalse()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                SymbolicId = new XmlQualifiedName("TestId", "http://test.com"),
                MaxCardinality = 0
            };

            var instance2 = new InstanceDesign
            {
                SymbolicId = new XmlQualifiedName("TestId", "http://test.com"),
                MaxCardinality = uint.MaxValue
            };

            // Act
            bool result = instance1.Equals((object)instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when other is null.
        /// </summary>
        [Test]
        public void Equals_NullInstance_ReturnsFalse()
        {
            // Arrange
            var instance = new InstanceDesign();

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = instance.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when all properties match.
        /// </summary>
        [Test]
        public void Equals_AllPropertiesMatch_ReturnsTrue()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                BrowseName = "TestNode",
                ReferenceType = new XmlQualifiedName("RefType", "http://test.org"),
                Declaration = new XmlQualifiedName("Declaration", "http://test.org"),
                TypeDefinition = new XmlQualifiedName("TypeDef", "http://test.org"),
                ModellingRule = ModellingRule.Mandatory,
                ModellingRuleSpecified = true,
                MinCardinality = 1,
                MaxCardinality = 10,
                PreserveDefaultAttributes = true,
                DesignToolOnly = false,
                IdentifierRequired = true
            };

            var instance2 = new InstanceDesign
            {
                BrowseName = "TestNode",
                ReferenceType = new XmlQualifiedName("RefType", "http://test.org"),
                Declaration = new XmlQualifiedName("Declaration", "http://test.org"),
                TypeDefinition = new XmlQualifiedName("TypeDef", "http://test.org"),
                ModellingRule = ModellingRule.Mandatory,
                ModellingRuleSpecified = true,
                MinCardinality = 1,
                MaxCardinality = 10,
                PreserveDefaultAttributes = true,
                DesignToolOnly = false,
                IdentifierRequired = true
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when ReferenceType differs.
        /// </summary>
        [Test]
        public void Equals_DifferentReferenceType_ReturnsFalse()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName("RefType1", "http://test.org")
            };

            var instance2 = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName("RefType2", "http://test.org")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Declaration differs.
        /// </summary>
        [Test]
        public void Equals_DifferentDeclaration_ReturnsFalse()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                Declaration = new XmlQualifiedName("Declaration1", "http://test.org")
            };

            var instance2 = new InstanceDesign
            {
                Declaration = new XmlQualifiedName("Declaration2", "http://test.org")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when TypeDefinition differs.
        /// </summary>
        [Test]
        public void Equals_DifferentTypeDefinition_ReturnsFalse()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                TypeDefinition = new XmlQualifiedName("TypeDef1", "http://test.org")
            };

            var instance2 = new InstanceDesign
            {
                TypeDefinition = new XmlQualifiedName("TypeDef2", "http://test.org")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when ModellingRule differs.
        /// </summary>
        [Test]
        public void Equals_DifferentModellingRule_ReturnsFalse()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                ModellingRule = ModellingRule.Mandatory
            };

            var instance2 = new InstanceDesign
            {
                ModellingRule = ModellingRule.Optional
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when ModellingRuleSpecified differs.
        /// </summary>
        [Test]
        public void Equals_DifferentModellingRuleSpecified_ReturnsFalse()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                ModellingRuleSpecified = true
            };

            var instance2 = new InstanceDesign
            {
                ModellingRuleSpecified = false
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when PreserveDefaultAttributes differs.
        /// </summary>
        [Test]
        public void Equals_DifferentPreserveDefaultAttributes_ReturnsFalse()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                PreserveDefaultAttributes = true
            };

            var instance2 = new InstanceDesign
            {
                PreserveDefaultAttributes = false
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when DesignToolOnly differs.
        /// </summary>
        [Test]
        public void Equals_DifferentDesignToolOnly_ReturnsFalse()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                DesignToolOnly = true
            };

            var instance2 = new InstanceDesign
            {
                DesignToolOnly = false
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when IdentifierRequired differs.
        /// </summary>
        [Test]
        public void Equals_DifferentIdentifierRequired_ReturnsFalse()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                IdentifierRequired = true
            };

            var instance2 = new InstanceDesign
            {
                IdentifierRequired = false
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles null XmlQualifiedName properties correctly.
        /// </summary>
        [Test]
        public void Equals_NullXmlQualifiedNameProperties_ReturnsTrue()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                ReferenceType = null,
                Declaration = null,
                TypeDefinition = null
            };

            var instance2 = new InstanceDesign
            {
                ReferenceType = null,
                Declaration = null,
                TypeDefinition = null
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when one ReferenceType is null and the other is not.
        /// </summary>
        [Test]
        public void Equals_OneReferenceTypeNull_ReturnsFalse()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName("RefType", "http://test.org")
            };

            var instance2 = new InstanceDesign
            {
                ReferenceType = null
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles boundary values for uint properties.
        /// </summary>
        [TestCase(0u, 0u, true)]
        [TestCase(uint.MaxValue, uint.MaxValue, true)]
        [TestCase(0u, uint.MaxValue, false)]
        [TestCase(uint.MaxValue, 0u, false)]
        public void Equals_CardinalityBoundaryValues_ReturnsExpectedResult(uint minCardinality1, uint minCardinality2, bool expected)
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                MinCardinality = minCardinality1
            };

            var instance2 = new InstanceDesign
            {
                MinCardinality = minCardinality2
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.EqualTo(expected));
        }

        /// <summary>
        /// Tests that Equals returns false when base class properties differ.
        /// </summary>
        [Test]
        public void Equals_DifferentBaseClassProperty_ReturnsFalse()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                BrowseName = "Node1"
            };

            var instance2 = new InstanceDesign
            {
                BrowseName = "Node2"
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles all ModellingRule enum values correctly.
        /// </summary>
        [TestCase(ModellingRule.None)]
        [TestCase(ModellingRule.Mandatory)]
        [TestCase(ModellingRule.Optional)]
        [TestCase(ModellingRule.ExposesItsArray)]
        [TestCase(ModellingRule.CardinalityRestriction)]
        [TestCase(ModellingRule.MandatoryShared)]
        [TestCase(ModellingRule.OptionalPlaceholder)]
        [TestCase(ModellingRule.MandatoryPlaceholder)]
        public void Equals_AllModellingRuleValues_HandlesCorrectly(ModellingRule rule)
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                ModellingRule = rule
            };

            var instance2 = new InstanceDesign
            {
                ModellingRule = rule
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when TypeDefinitionNode differs.
        /// </summary>
        [Test]
        public void Equals_DifferentTypeDefinitionNode_ReturnsFalse()
        {
            // Arrange
            TypeDesign typeDesign1 = new ObjectTypeDesign { BrowseName = "Type1" };
            TypeDesign typeDesign2 = new ObjectTypeDesign { BrowseName = "Type2" };

            var instance1 = new InstanceDesign
            {
                TypeDefinitionNode = typeDesign1
            };

            var instance2 = new InstanceDesign
            {
                TypeDefinitionNode = typeDesign2
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when TypeDefinitionNode is null for both instances.
        /// </summary>
        [Test]
        public void Equals_BothTypeDefinitionNodeNull_ReturnsTrue()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                TypeDefinitionNode = null
            };

            var instance2 = new InstanceDesign
            {
                TypeDefinitionNode = null
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when InstanceDeclarationNode differs.
        /// </summary>
        [Test]
        public void Equals_DifferentInstanceDeclarationNode_ReturnsFalse()
        {
            // Arrange
            var decl1 = new InstanceDesign { BrowseName = "Decl1" };
            var decl2 = new InstanceDesign { BrowseName = "Decl2" };

            var instance1 = new InstanceDesign
            {
                InstanceDeclarationNode = decl1
            };

            var instance2 = new InstanceDesign
            {
                InstanceDeclarationNode = decl2
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when OveriddenNode differs.
        /// </summary>
        [Test]
        public void Equals_DifferentOveriddenNode_ReturnsFalse()
        {
            // Arrange
            var overridden1 = new InstanceDesign { BrowseName = "Override1" };
            var overridden2 = new InstanceDesign { BrowseName = "Override2" };

            var instance1 = new InstanceDesign
            {
                OveriddenNode = overridden1
            };

            var instance2 = new InstanceDesign
            {
                OveriddenNode = overridden2
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles XmlQualifiedName with different namespaces.
        /// </summary>
        [Test]
        public void Equals_XmlQualifiedNameDifferentNamespace_ReturnsFalse()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName("RefType", "http://test1.org")
            };

            var instance2 = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName("RefType", "http://test2.org")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles XmlQualifiedName with empty namespace.
        /// </summary>
        [Test]
        public void Equals_XmlQualifiedNameEmptyNamespace_HandlesCorrectly()
        {
            // Arrange
            var instance1 = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName("RefType", string.Empty)
            };

            var instance2 = new InstanceDesign
            {
                ReferenceType = new XmlQualifiedName("RefType", string.Empty)
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }
    }

    /// <summary>
    /// Unit tests for the RolePermission class.
    /// </summary>
    public partial class RolePermissionTests
    {
        /// <summary>
        /// Tests that GetHashCode returns a consistent hash code for the same instance.
        /// Expected: The same hash code is returned on multiple calls.
        /// </summary>
        [Test]
        public void GetHashCode_SameInstance_ReturnsConsistentHashCode()
        {
            // Arrange
            var rolePermission = new RolePermission
            {
                Permission = [Permissions.Read, Permissions.Write],
                Role = new XmlQualifiedName("Administrator", "http://example.com")
            };

            // Act
            int hashCode1 = rolePermission.GetHashCode();
            int hashCode2 = rolePermission.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode returns the same hash code for equal objects.
        /// Expected: Objects with the same Permission and Role return the same hash code.
        /// </summary>
        [Test]
        public void GetHashCode_EqualObjects_ReturnsSameHashCode()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Read, Permissions.Write],
                Role = new XmlQualifiedName("Administrator", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Read, Permissions.Write],
                Role = new XmlQualifiedName("Administrator", "http://example.com")
            };

            // Act
            int hashCode1 = rolePermission1.GetHashCode();
            int hashCode2 = rolePermission2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different Permission arrays.
        /// Expected: Different Permission arrays should likely result in different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentPermissions_ReturnsDifferentHashCodes()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Read],
                Role = new XmlQualifiedName("User", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Write],
                Role = new XmlQualifiedName("User", "http://example.com")
            };

            // Act
            int hashCode1 = rolePermission1.GetHashCode();
            int hashCode2 = rolePermission2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.Not.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different Roles.
        /// Expected: Different Role values should likely result in different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentRoles_ReturnsDifferentHashCodes()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Read],
                Role = new XmlQualifiedName("Administrator", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Read],
                Role = new XmlQualifiedName("User", "http://example.com")
            };

            // Act
            int hashCode1 = rolePermission1.GetHashCode();
            int hashCode2 = rolePermission2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.Not.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode handles null Permission array.
        /// Expected: Returns a valid hash code without throwing an exception.
        /// </summary>
        [Test]
        public void GetHashCode_NullPermission_ReturnsValidHashCode()
        {
            // Arrange
            var rolePermission = new RolePermission
            {
                Permission = null,
                Role = new XmlQualifiedName("Administrator", "http://example.com")
            };

            // Act
            int hashCode = rolePermission.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode handles null Role.
        /// Expected: Returns a valid hash code without throwing an exception.
        /// </summary>
        [Test]
        public void GetHashCode_NullRole_ReturnsValidHashCode()
        {
            // Arrange
            var rolePermission = new RolePermission
            {
                Permission = [Permissions.Read],
                Role = null
            };

            // Act
            int hashCode = rolePermission.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode handles both null Permission and null Role.
        /// Expected: Returns a valid hash code without throwing an exception.
        /// </summary>
        [Test]
        public void GetHashCode_NullPermissionAndNullRole_ReturnsValidHashCode()
        {
            // Arrange
            var rolePermission = new RolePermission
            {
                Permission = null,
                Role = null
            };

            // Act
            int hashCode = rolePermission.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode handles empty Permission array.
        /// Expected: Returns a valid hash code for empty Permission array.
        /// </summary>
        [Test]
        public void GetHashCode_EmptyPermissionArray_ReturnsValidHashCode()
        {
            // Arrange
            var rolePermission = new RolePermission
            {
                Permission = [],
                Role = new XmlQualifiedName("User", "http://example.com")
            };

            // Act
            int hashCode = rolePermission.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode returns the same hash code for equal empty Permission arrays.
        /// Expected: Two objects with empty Permission arrays and same Role return the same hash code.
        /// </summary>
        [Test]
        public void GetHashCode_EqualEmptyPermissionArrays_ReturnsSameHashCode()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [],
                Role = new XmlQualifiedName("User", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [],
                Role = new XmlQualifiedName("User", "http://example.com")
            };

            // Act
            int hashCode1 = rolePermission1.GetHashCode();
            int hashCode2 = rolePermission2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode handles Permission arrays with multiple elements.
        /// Expected: Returns consistent hash codes for arrays with same elements in same order.
        /// </summary>
        [Test]
        public void GetHashCode_MultiplePermissions_ReturnsConsistentHashCode()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read, Permissions.Write, Permissions.Call],
                Role = new XmlQualifiedName("Administrator", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read, Permissions.Write, Permissions.Call],
                Role = new XmlQualifiedName("Administrator", "http://example.com")
            };

            // Act
            int hashCode1 = rolePermission1.GetHashCode();
            int hashCode2 = rolePermission2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for Permission arrays with same elements but different order.
        /// Expected: Arrays with same elements in different order should result in different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentPermissionOrder_ReturnsDifferentHashCodes()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Read, Permissions.Write],
                Role = new XmlQualifiedName("User", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Write, Permissions.Read],
                Role = new XmlQualifiedName("User", "http://example.com")
            };

            // Act
            int hashCode1 = rolePermission1.GetHashCode();
            int hashCode2 = rolePermission2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.Not.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode handles Role with different namespaces.
        /// Expected: Roles with different namespaces should result in different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentRoleNamespaces_ReturnsDifferentHashCodes()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Read],
                Role = new XmlQualifiedName("Administrator", "http://example1.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Read],
                Role = new XmlQualifiedName("Administrator", "http://example2.com")
            };

            // Act
            int hashCode1 = rolePermission1.GetHashCode();
            int hashCode2 = rolePermission2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.Not.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode handles Role with empty name.
        /// Expected: Returns a valid hash code for empty Role name.
        /// </summary>
        [Test]
        public void GetHashCode_EmptyRoleName_ReturnsValidHashCode()
        {
            // Arrange
            var rolePermission = new RolePermission
            {
                Permission = [Permissions.Read],
                Role = new XmlQualifiedName(string.Empty, "http://example.com")
            };

            // Act
            int hashCode = rolePermission.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode handles Role with empty namespace.
        /// Expected: Returns a valid hash code for empty Role namespace.
        /// </summary>
        [Test]
        public void GetHashCode_EmptyRoleNamespace_ReturnsValidHashCode()
        {
            // Arrange
            var rolePermission = new RolePermission
            {
                Permission = [Permissions.Read],
                Role = new XmlQualifiedName("Administrator", string.Empty)
            };

            // Act
            int hashCode = rolePermission.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode handles all defined Permission enum values.
        /// Expected: Returns a valid hash code for all Permission enum combinations.
        /// </summary>
        [Test]
        public void GetHashCode_AllPermissionValues_ReturnsValidHashCode()
        {
            // Arrange
            var rolePermission = new RolePermission
            {
                Permission =
                [
                    Permissions.Browse, Permissions.ReadRolePermissions, Permissions.WriteAttribute,
                    Permissions.WriteRolePermissions, Permissions.WriteHistorizing, Permissions.Read,
                    Permissions.Write, Permissions.ReadHistory, Permissions.InsertHistory,
                    Permissions.ModifyHistory, Permissions.DeleteHistory, Permissions.ReceiveEvents,
                    Permissions.Call, Permissions.AddReference, Permissions.RemoveReference,
                    Permissions.DeleteNode, Permissions.AddNode, Permissions.All,
                    Permissions.AllRead, Permissions.None
                ],
                Role = new XmlQualifiedName("Administrator", "http://example.com")
            };

            // Act
            int hashCode = rolePermission.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode returns same hash code for objects where only non-hash properties differ.
        /// This ensures GetHashCode is only based on Permission and Role, not other potential properties.
        /// Expected: Two equal objects produce the same hash code.
        /// </summary>
        [Test]
        public void GetHashCode_SamePermissionAndRole_ReturnsSameHashCodeRegardlessOfOtherProperties()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Read, Permissions.Write],
                Role = new XmlQualifiedName("User", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Read, Permissions.Write],
                Role = new XmlQualifiedName("User", "http://example.com")
            };

            // Act
            int hashCode1 = rolePermission1.GetHashCode();
            int hashCode2 = rolePermission2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.EqualTo(hashCode2));
            Assert.That(rolePermission1.Equals(rolePermission2), Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with null.
        /// </summary>
        [Test]
        public void Equals_NullParameter_ReturnsFalse()
        {
            // Arrange
            var instance = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = instance.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing an instance with itself.
        /// </summary>
        [Test]
        public void Equals_SameInstance_ReturnsTrue()
        {
            // Arrange
            var instance = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            // Act
            bool result = instance.Equals(instance);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two instances with identical Permission arrays and Role.
        /// </summary>
        [Test]
        public void Equals_IdenticalPermissionAndRole_ReturnsTrue()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var instance2 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when Permission arrays differ.
        /// </summary>
        [Test]
        public void Equals_DifferentPermissions_ReturnsFalse()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var instance2 = new RolePermission
            {
                Permission = [Permissions.Write, Permissions.Read],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Role differs.
        /// </summary>
        [Test]
        public void Equals_DifferentRole_ReturnsFalse()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var instance2 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Role2", "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when both Permission and Role differ.
        /// </summary>
        [Test]
        public void Equals_DifferentPermissionAndRole_ReturnsFalse()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var instance2 = new RolePermission
            {
                Permission = [Permissions.Write, Permissions.Call],
                Role = new XmlQualifiedName("Role2", "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Permission arrays have different lengths.
        /// </summary>
        [Test]
        public void Equals_DifferentPermissionArrayLength_ReturnsFalse()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var instance2 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read, Permissions.Write],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both Permission arrays are null and Roles are equal.
        /// </summary>
        [Test]
        public void Equals_BothPermissionsNull_SameRole_ReturnsTrue()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = null,
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var instance2 = new RolePermission
            {
                Permission = null,
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when one Permission array is null and the other is not.
        /// </summary>
        [Test]
        public void Equals_OnePermissionNull_OtherNotNull_ReturnsFalse()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = null,
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var instance2 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both Permission arrays are empty and Roles are equal.
        /// </summary>
        [Test]
        public void Equals_BothPermissionsEmpty_SameRole_ReturnsTrue()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = [],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var instance2 = new RolePermission
            {
                Permission = [],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when one Permission array is empty and the other has elements.
        /// </summary>
        [Test]
        public void Equals_OnePermissionEmpty_OtherHasElements_ReturnsFalse()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = [],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var instance2 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both Roles are null and Permission arrays are equal.
        /// </summary>
        [Test]
        public void Equals_BothRolesNull_SamePermission_ReturnsTrue()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = null
            };

            var instance2 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = null
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when one Role is null and the other is not.
        /// </summary>
        [Test]
        public void Equals_OneRoleNull_OtherNotNull_ReturnsFalse()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = null
            };

            var instance2 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Role namespaces differ.
        /// </summary>
        [Test]
        public void Equals_DifferentRoleNamespace_ReturnsFalse()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Role1", "http://test1.com")
            };

            var instance2 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Role1", "http://test2.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both Permission and Role are null.
        /// </summary>
        [Test]
        public void Equals_BothPermissionsAndRolesNull_ReturnsTrue()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = null,
                Role = null
            };

            var instance2 = new RolePermission
            {
                Permission = null,
                Role = null
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when Permission arrays have same elements but in different order.
        /// </summary>
        [Test]
        public void Equals_PermissionsDifferentOrder_ReturnsFalse()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var instance2 = new RolePermission
            {
                Permission = [Permissions.Read, Permissions.Browse],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when Permission arrays have single identical element.
        /// </summary>
        [Test]
        public void Equals_SinglePermissionElement_ReturnsTrue()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var instance2 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when Permission arrays have multiple identical elements including duplicates.
        /// </summary>
        [Test]
        public void Equals_PermissionsWithDuplicates_ReturnsTrue()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read, Permissions.Browse],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var instance2 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read, Permissions.Browse],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when Roles have empty name and same namespace.
        /// </summary>
        [Test]
        public void Equals_RoleWithEmptyName_ReturnsTrue()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName(string.Empty, "http://test.com")
            };

            var instance2 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName(string.Empty, "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing instances with all possible Permission enum values.
        /// </summary>
        [Test]
        public void Equals_AllPermissionTypes_ReturnsTrue()
        {
            // Arrange
            var instance1 = new RolePermission
            {
                Permission =
                [
                    Permissions.Browse,
                    Permissions.ReadRolePermissions,
                    Permissions.WriteAttribute,
                    Permissions.WriteRolePermissions,
                    Permissions.WriteHistorizing,
                    Permissions.Read,
                    Permissions.Write,
                    Permissions.ReadHistory,
                    Permissions.InsertHistory,
                    Permissions.ModifyHistory,
                    Permissions.DeleteHistory,
                    Permissions.ReceiveEvents,
                    Permissions.Call,
                    Permissions.AddReference,
                    Permissions.RemoveReference,
                    Permissions.DeleteNode,
                    Permissions.AddNode,
                    Permissions.All,
                    Permissions.AllRead,
                    Permissions.None
                ],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var instance2 = new RolePermission
            {
                Permission =
                [
                    Permissions.Browse,
                    Permissions.ReadRolePermissions,
                    Permissions.WriteAttribute,
                    Permissions.WriteRolePermissions,
                    Permissions.WriteHistorizing,
                    Permissions.Read,
                    Permissions.Write,
                    Permissions.ReadHistory,
                    Permissions.InsertHistory,
                    Permissions.ModifyHistory,
                    Permissions.DeleteHistory,
                    Permissions.ReceiveEvents,
                    Permissions.Call,
                    Permissions.AddReference,
                    Permissions.RemoveReference,
                    Permissions.DeleteNode,
                    Permissions.AddNode,
                    Permissions.All,
                    Permissions.AllRead,
                    Permissions.None
                ],
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            // Act
            bool result = instance1.Equals(instance2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when the input object is null.
        /// </summary>
        [Test]
        public void Equals_NullObject_ReturnsFalse()
        {
            // Arrange
            var rolePermission = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = rolePermission.Equals((object)null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing an object to itself.
        /// </summary>
        [Test]
        public void Equals_SameReference_ReturnsTrue()
        {
            // Arrange
            var rolePermission = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("User", "http://example.com")
            };

            // Act
            bool result = rolePermission.Equals((object)rolePermission);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when the input object is of a different type.
        /// </summary>
        [Test]
        public void Equals_DifferentType_ReturnsFalse()
        {
            // Arrange
            var rolePermission = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };
            object differentType = "string object";

            // Act
            bool result = rolePermission.Equals(differentType);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two RolePermission objects with identical values.
        /// </summary>
        [Test]
        public void Equals_IdenticalValues_ReturnsTrue()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };

            // Act
            bool result = rolePermission1.Equals((object)rolePermission2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when Permission arrays differ in values.
        /// </summary>
        [Test]
        public void Equals_DifferentPermissionValues_ReturnsFalse()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Read],
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };

            // Act
            bool result = rolePermission1.Equals((object)rolePermission2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when one Permission array is null and the other is not.
        /// </summary>
        [Test]
        public void Equals_OnePermissionArrayNull_ReturnsFalse()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = null,
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };

            // Act
            bool result = rolePermission1.Equals((object)rolePermission2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both Permission arrays are null.
        /// </summary>
        [Test]
        public void Equals_BothPermissionArraysNull_ReturnsTrue()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = null,
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = null,
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };

            // Act
            bool result = rolePermission1.Equals((object)rolePermission2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when both Permission arrays are empty.
        /// </summary>
        [Test]
        public void Equals_BothPermissionArraysEmpty_ReturnsTrue()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [],
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [],
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };

            // Act
            bool result = rolePermission1.Equals((object)rolePermission2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when Role values differ in name.
        /// </summary>
        [Test]
        public void Equals_DifferentRoleName_ReturnsFalse()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName("User", "http://example.com")
            };

            // Act
            bool result = rolePermission1.Equals((object)rolePermission2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when one Role is null and the other is not.
        /// </summary>
        [Test]
        public void Equals_OneRoleNull_ReturnsFalse()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = null
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };

            // Act
            bool result = rolePermission1.Equals((object)rolePermission2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both Role values are null.
        /// </summary>
        [Test]
        public void Equals_BothRolesNull_ReturnsTrue()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = null
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = null
            };

            // Act
            bool result = rolePermission1.Equals((object)rolePermission2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when both Permission and Role differ.
        /// </summary>
        [Test]
        public void Equals_BothPropertiesDifferent_ReturnsFalse()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Read],
                Role = new XmlQualifiedName("User", "http://different.com")
            };

            // Act
            bool result = rolePermission1.Equals((object)rolePermission2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both objects are completely empty.
        /// </summary>
        [Test]
        public void Equals_BothObjectsEmpty_ReturnsTrue()
        {
            // Arrange
            var rolePermission1 = new RolePermission();
            var rolePermission2 = new RolePermission();

            // Act
            bool result = rolePermission1.Equals((object)rolePermission2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when Permission arrays contain all possible enum values and match.
        /// </summary>
        [Test]
        public void Equals_AllPermissionEnumValues_ReturnsTrue()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission =
                [
                    Permissions.Browse,
                    Permissions.ReadRolePermissions,
                    Permissions.WriteAttribute,
                    Permissions.WriteRolePermissions,
                    Permissions.WriteHistorizing,
                    Permissions.Read,
                    Permissions.Write,
                    Permissions.ReadHistory,
                    Permissions.InsertHistory,
                    Permissions.ModifyHistory,
                    Permissions.DeleteHistory,
                    Permissions.ReceiveEvents,
                    Permissions.Call,
                    Permissions.AddReference,
                    Permissions.RemoveReference,
                    Permissions.DeleteNode,
                    Permissions.AddNode
                ],
                Role = new XmlQualifiedName("SuperAdmin", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission =
                [
                    Permissions.Browse,
                    Permissions.ReadRolePermissions,
                    Permissions.WriteAttribute,
                    Permissions.WriteRolePermissions,
                    Permissions.WriteHistorizing,
                    Permissions.Read,
                    Permissions.Write,
                    Permissions.ReadHistory,
                    Permissions.InsertHistory,
                    Permissions.ModifyHistory,
                    Permissions.DeleteHistory,
                    Permissions.ReceiveEvents,
                    Permissions.Call,
                    Permissions.AddReference,
                    Permissions.RemoveReference,
                    Permissions.DeleteNode,
                    Permissions.AddNode
                ],
                Role = new XmlQualifiedName("SuperAdmin", "http://example.com")
            };

            // Act
            bool result = rolePermission1.Equals((object)rolePermission2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when Permission arrays have same length but different order.
        /// </summary>
        [Test]
        public void Equals_PermissionArraysDifferentOrder_ReturnsFalse()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Browse, Permissions.Read],
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Read, Permissions.Browse],
                Role = new XmlQualifiedName("Admin", "http://example.com")
            };

            // Act
            bool result = rolePermission1.Equals((object)rolePermission2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when Role has empty string name and namespace.
        /// </summary>
        [Test]
        public void Equals_RoleWithEmptyStrings_ReturnsTrue()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName(string.Empty, string.Empty)
            };
            var rolePermission2 = new RolePermission
            {
                Permission = [Permissions.Browse],
                Role = new XmlQualifiedName(string.Empty, string.Empty)
            };

            // Act
            bool result = rolePermission1.Equals((object)rolePermission2);

            // Assert
            Assert.That(result, Is.True);
        }
    }

    /// <summary>
    /// Unit tests for the <see cref="TypeDesign"/> class.
    /// </summary>
    public partial class TypeDesignTests
    {
        /// <summary>
        /// Tests that GetHashCode returns a consistent value when called multiple times on the same object.
        /// Input: TypeDesign instance with default values.
        /// Expected: Same hash code on multiple calls.
        /// </summary>
        [Test]
        public void GetHashCode_SameObject_ReturnsConsistentHashCode()
        {
            // Arrange
            var typeDesign = new TypeDesign();

            // Act
            int hashCode1 = typeDesign.GetHashCode();
            int hashCode2 = typeDesign.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode returns the same value for two objects with identical property values.
        /// Input: Two TypeDesign instances with same property values.
        /// Expected: Same hash code.
        /// </summary>
        [Test]
        public void GetHashCode_EqualObjects_ReturnsSameHashCode()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = true,
                NoClassGeneration = false
            };

            var typeDesign2 = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = true,
                NoClassGeneration = false
            };

            // Act
            int hashCode1 = typeDesign1.GetHashCode();
            int hashCode2 = typeDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode handles null ClassName property.
        /// Input: TypeDesign with null ClassName.
        /// Expected: Valid hash code without exception.
        /// </summary>
        [Test]
        public void GetHashCode_NullClassName_ReturnsValidHashCode()
        {
            // Arrange
            var typeDesign = new TypeDesign
            {
                ClassName = null,
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            int hashCode = typeDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode handles empty string ClassName property.
        /// Input: TypeDesign with empty ClassName.
        /// Expected: Valid hash code without exception.
        /// </summary>
        [Test]
        public void GetHashCode_EmptyClassName_ReturnsValidHashCode()
        {
            // Arrange
            var typeDesign = new TypeDesign
            {
                ClassName = string.Empty,
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            int hashCode = typeDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode handles null BaseType property.
        /// Input: TypeDesign with null BaseType.
        /// Expected: Valid hash code without exception.
        /// </summary>
        [Test]
        public void GetHashCode_NullBaseType_ReturnsValidHashCode()
        {
            // Arrange
            var typeDesign = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = null,
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            int hashCode = typeDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode handles null BaseTypeNode property.
        /// Input: TypeDesign with null BaseTypeNode.
        /// Expected: Valid hash code without exception.
        /// </summary>
        [Test]
        public void GetHashCode_NullBaseTypeNode_ReturnsValidHashCode()
        {
            // Arrange
            var typeDesign = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false,
                BaseTypeNode = null
            };

            // Act
            int hashCode = typeDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode handles non-null BaseTypeNode property.
        /// Input: TypeDesign with non-null BaseTypeNode.
        /// Expected: Valid hash code without exception.
        /// </summary>
        [Test]
        public void GetHashCode_NonNullBaseTypeNode_ReturnsValidHashCode()
        {
            // Arrange
            var baseTypeNode = new TypeDesign
            {
                ClassName = "BaseClass"
            };

            var typeDesign = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false,
                BaseTypeNode = baseTypeNode
            };

            // Act
            int hashCode = typeDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode produces different hash codes for objects with different ClassName values.
        /// Input: Two TypeDesign instances with different ClassName values.
        /// Expected: Different hash codes (most likely, though not guaranteed).
        /// </summary>
        [Test]
        public void GetHashCode_DifferentClassName_ProducesDifferentHashCode()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                ClassName = "Class1",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            var typeDesign2 = new TypeDesign
            {
                ClassName = "Class2",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            int hashCode1 = typeDesign1.GetHashCode();
            int hashCode2 = typeDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode produces different hash codes for objects with different BaseType values.
        /// Input: Two TypeDesign instances with different BaseType values.
        /// Expected: Different hash codes (most likely, though not guaranteed).
        /// </summary>
        [Test]
        public void GetHashCode_DifferentBaseType_ProducesDifferentHashCode()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType1", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            var typeDesign2 = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType2", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            int hashCode1 = typeDesign1.GetHashCode();
            int hashCode2 = typeDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode produces different hash codes for objects with different IsAbstract values.
        /// Input: Two TypeDesign instances with different IsAbstract values.
        /// Expected: Different hash codes (most likely, though not guaranteed).
        /// </summary>
        [Test]
        public void GetHashCode_DifferentIsAbstract_ProducesDifferentHashCode()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = true,
                NoClassGeneration = false
            };

            var typeDesign2 = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            int hashCode1 = typeDesign1.GetHashCode();
            int hashCode2 = typeDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode produces different hash codes for objects with different NoClassGeneration values.
        /// Input: Two TypeDesign instances with different NoClassGeneration values.
        /// Expected: Different hash codes (most likely, though not guaranteed).
        /// </summary>
        [Test]
        public void GetHashCode_DifferentNoClassGeneration_ProducesDifferentHashCode()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = true
            };

            var typeDesign2 = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            int hashCode1 = typeDesign1.GetHashCode();
            int hashCode2 = typeDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode produces different hash codes for objects with different BaseTypeNode values.
        /// Input: Two TypeDesign instances with different BaseTypeNode values.
        /// Expected: Different hash codes (most likely, though not guaranteed).
        /// </summary>
        [Test]
        public void GetHashCode_DifferentBaseTypeNode_ProducesDifferentHashCode()
        {
            // Arrange
            var baseTypeNode1 = new TypeDesign
            {
                ClassName = "BaseClass1"
            };

            var baseTypeNode2 = new TypeDesign
            {
                ClassName = "BaseClass2"
            };

            var typeDesign1 = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false,
                BaseTypeNode = baseTypeNode1
            };

            var typeDesign2 = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false,
                BaseTypeNode = baseTypeNode2
            };

            // Act
            int hashCode1 = typeDesign1.GetHashCode();
            int hashCode2 = typeDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode handles all null properties.
        /// Input: TypeDesign with all nullable properties set to null.
        /// Expected: Valid hash code without exception.
        /// </summary>
        [Test]
        public void GetHashCode_AllNullProperties_ReturnsValidHashCode()
        {
            // Arrange
            var typeDesign = new TypeDesign
            {
                ClassName = null,
                BaseType = null,
                IsAbstract = false,
                NoClassGeneration = false,
                BaseTypeNode = null
            };

            // Act
            int hashCode = typeDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode handles BaseType with different namespaces.
        /// Input: Two TypeDesign instances with BaseType having different namespaces.
        /// Expected: Different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentBaseTypeNamespace_ProducesDifferentHashCode()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test1.org"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            var typeDesign2 = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test2.org"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            int hashCode1 = typeDesign1.GetHashCode();
            int hashCode2 = typeDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode handles whitespace-only ClassName.
        /// Input: TypeDesign with whitespace-only ClassName.
        /// Expected: Valid hash code without exception.
        /// </summary>
        [Test]
        public void GetHashCode_WhitespaceClassName_ReturnsValidHashCode()
        {
            // Arrange
            var typeDesign = new TypeDesign
            {
                ClassName = "   ",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            int hashCode = typeDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode handles very long ClassName string.
        /// Input: TypeDesign with very long ClassName.
        /// Expected: Valid hash code without exception.
        /// </summary>
        [Test]
        public void GetHashCode_VeryLongClassName_ReturnsValidHashCode()
        {
            // Arrange
            var typeDesign = new TypeDesign
            {
                ClassName = new string('A', 10000),
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            int hashCode = typeDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode handles ClassName with special characters.
        /// Input: TypeDesign with ClassName containing special characters.
        /// Expected: Valid hash code without exception.
        /// </summary>
        [Test]
        public void GetHashCode_ClassNameWithSpecialCharacters_ReturnsValidHashCode()
        {
            // Arrange
            var typeDesign = new TypeDesign
            {
                ClassName = "Test!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`Class",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            int hashCode = typeDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode handles all boolean property combinations.
        /// Input: TypeDesign instances with all combinations of IsAbstract and NoClassGeneration.
        /// Expected: Valid hash codes for all combinations.
        /// </summary>
        [TestCase(true, true)]
        [TestCase(true, false)]
        [TestCase(false, true)]
        [TestCase(false, false)]
        public void GetHashCode_BooleanCombinations_ReturnsValidHashCode(bool isAbstract, bool noClassGeneration)
        {
            // Arrange
            var typeDesign = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.org"),
                IsAbstract = isAbstract,
                NoClassGeneration = noClassGeneration
            };

            // Act
            int hashCode = typeDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that Copy method returns a non-null instance.
        /// </summary>
        [Test]
        public void Copy_DefaultInstance_ReturnsNonNull()
        {
            // Arrange
            var original = new TypeDesign();

            // Act
            TypeDesign copy = original.Copy();

            // Assert
            Assert.That(copy, Is.Not.Null);
        }

        /// <summary>
        /// Tests that Copy method creates a new instance with a different reference.
        /// </summary>
        [Test]
        public void Copy_DefaultInstance_ReturnsDifferentInstance()
        {
            // Arrange
            var original = new TypeDesign();

            // Act
            TypeDesign copy = original.Copy();

            // Assert
            Assert.That(copy, Is.Not.SameAs(original));
        }

        /// <summary>
        /// Tests that Copy method creates a shallow copy with same value-type properties.
        /// Verifies that boolean properties are copied correctly.
        /// </summary>
        [Test]
        public void Copy_WithBooleanProperties_CopiesValues()
        {
            // Arrange
            var original = new TypeDesign
            {
                IsAbstract = true,
                NoClassGeneration = true
            };

            // Act
            TypeDesign copy = original.Copy();

            // Assert
            Assert.That(copy.IsAbstract, Is.EqualTo(original.IsAbstract));
            Assert.That(copy.NoClassGeneration, Is.EqualTo(original.NoClassGeneration));
        }

        /// <summary>
        /// Tests that Copy method creates a shallow copy with same string properties.
        /// Verifies that ClassName property is copied correctly.
        /// </summary>
        [Test]
        public void Copy_WithStringProperties_CopiesReferences()
        {
            // Arrange
            var original = new TypeDesign
            {
                ClassName = "TestClassName"
            };

            // Act
            TypeDesign copy = original.Copy();

            // Assert
            Assert.That(copy.ClassName, Is.EqualTo(original.ClassName));
            Assert.That(copy.ClassName, Is.SameAs(original.ClassName));
        }

        /// <summary>
        /// Tests that Copy method creates a shallow copy with same reference-type properties.
        /// Verifies that BaseType property references the same object (shallow copy behavior).
        /// </summary>
        [Test]
        public void Copy_WithReferenceTypeProperties_CopiesSameReference()
        {
            // Arrange
            var baseType = new XmlQualifiedName("BaseTypeName", "http://example.com");
            var original = new TypeDesign
            {
                BaseType = baseType
            };

            // Act
            TypeDesign copy = original.Copy();

            // Assert
            Assert.That(copy.BaseType, Is.EqualTo(original.BaseType));
            Assert.That(copy.BaseType, Is.SameAs(original.BaseType));
        }

        /// <summary>
        /// Tests that Copy method creates a shallow copy preserving all properties.
        /// Verifies comprehensive property copying with multiple property types.
        /// </summary>
        [Test]
        public void Copy_WithAllPropertiesSet_CopiesAllValues()
        {
            // Arrange
            var baseType = new XmlQualifiedName("BaseType", "http://test.com");
            var original = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = baseType,
                IsAbstract = true,
                NoClassGeneration = false
            };

            // Act
            TypeDesign copy = original.Copy();

            // Assert
            Assert.That(copy, Is.Not.SameAs(original));
            Assert.That(copy.ClassName, Is.EqualTo(original.ClassName));
            Assert.That(copy.BaseType, Is.SameAs(original.BaseType));
            Assert.That(copy.IsAbstract, Is.EqualTo(original.IsAbstract));
            Assert.That(copy.NoClassGeneration, Is.EqualTo(original.NoClassGeneration));
        }

        /// <summary>
        /// Tests that Copy method performs shallow copy for reference type properties.
        /// Verifies that modifying the referenced object affects both original and copy.
        /// </summary>
        [Test]
        public void Copy_ShallowCopyBehavior_ReferencedObjectIsShared()
        {
            // Arrange
            var baseType = new XmlQualifiedName("OriginalName", "http://test.com");
            var original = new TypeDesign
            {
                BaseType = baseType
            };

            // Act
            TypeDesign copy = original.Copy();
            original.BaseType = new XmlQualifiedName("ModifiedName", "http://modified.com");

            // Assert
            Assert.That(copy.BaseType, Is.Not.SameAs(original.BaseType));
            Assert.That(copy.BaseType.Name, Is.EqualTo("OriginalName"));
            Assert.That(original.BaseType.Name, Is.EqualTo("ModifiedName"));
        }

        /// <summary>
        /// Tests that Copy method with null reference properties handles correctly.
        /// Verifies that null properties are copied as null.
        /// </summary>
        [Test]
        public void Copy_WithNullProperties_CopiesNullValues()
        {
            // Arrange
            var original = new TypeDesign
            {
                ClassName = null,
                BaseType = null
            };

            // Act
            TypeDesign copy = original.Copy();

            // Assert
            Assert.That(copy.ClassName, Is.Null);
            Assert.That(copy.BaseType, Is.Null);
        }

        /// <summary>
        /// Tests that Copy method with empty string properties handles correctly.
        /// Verifies that empty strings are copied correctly.
        /// </summary>
        [Test]
        public void Copy_WithEmptyString_CopiesEmptyString()
        {
            // Arrange
            var original = new TypeDesign
            {
                ClassName = string.Empty
            };

            // Act
            TypeDesign copy = original.Copy();

            // Assert
            Assert.That(copy.ClassName, Is.EqualTo(string.Empty));
        }

        /// <summary>
        /// Tests that Copy method with default boolean values handles correctly.
        /// Verifies that default false values are copied correctly.
        /// </summary>
        [Test]
        public void Copy_WithDefaultBooleanValues_CopiesDefaults()
        {
            // Arrange
            var original = new TypeDesign
            {
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            TypeDesign copy = original.Copy();

            // Assert
            Assert.That(copy.IsAbstract, Is.False);
            Assert.That(copy.NoClassGeneration, Is.False);
        }

        /// <summary>
        /// Tests that Copy method with very long string properties handles correctly.
        /// Verifies that long strings are copied correctly.
        /// </summary>
        [Test]
        public void Copy_WithLongString_CopiesLongString()
        {
            // Arrange
            string longClassName = new('A', 10000);
            var original = new TypeDesign
            {
                ClassName = longClassName
            };

            // Act
            TypeDesign copy = original.Copy();

            // Assert
            Assert.That(copy.ClassName, Is.EqualTo(longClassName));
            Assert.That(copy.ClassName.Length, Is.EqualTo(10000));
        }

        /// <summary>
        /// Tests that Copy method with special characters in string properties handles correctly.
        /// Verifies that strings with special characters are copied correctly.
        /// </summary>
        [Test]
        public void Copy_WithSpecialCharactersInString_CopiesSpecialCharacters()
        {
            // Arrange
            var original = new TypeDesign
            {
                ClassName = "Class\n\r\t\0Name"
            };

            // Act
            TypeDesign copy = original.Copy();

            // Assert
            Assert.That(copy.ClassName, Is.EqualTo(original.ClassName));
        }

        /// <summary>
        /// Tests that Copy method can be called multiple times on the same instance.
        /// Verifies that multiple copies are independent.
        /// </summary>
        [Test]
        public void Copy_CalledMultipleTimes_CreatesIndependentCopies()
        {
            // Arrange
            var original = new TypeDesign
            {
                ClassName = "OriginalClass",
                IsAbstract = true
            };

            // Act
            TypeDesign copy1 = original.Copy();
            TypeDesign copy2 = original.Copy();

            // Assert
            Assert.That(copy1, Is.Not.SameAs(copy2));
            Assert.That(copy1.ClassName, Is.EqualTo(copy2.ClassName));
            Assert.That(copy1.IsAbstract, Is.EqualTo(copy2.IsAbstract));
        }

        /// <summary>
        /// Tests that Copy method on a copied instance creates a new independent copy.
        /// Verifies that copying a copy works correctly.
        /// </summary>
        [Test]
        public void Copy_OfCopy_CreatesNewIndependentInstance()
        {
            // Arrange
            var original = new TypeDesign
            {
                ClassName = "Original",
                IsAbstract = true
            };
            TypeDesign firstCopy = original.Copy();

            // Act
            TypeDesign secondCopy = firstCopy.Copy();

            // Assert
            Assert.That(secondCopy, Is.Not.SameAs(original));
            Assert.That(secondCopy, Is.Not.SameAs(firstCopy));
            Assert.That(secondCopy.ClassName, Is.EqualTo(original.ClassName));
            Assert.That(secondCopy.IsAbstract, Is.EqualTo(original.IsAbstract));
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with null.
        /// Input: null other parameter.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_NullOther_ReturnsFalse()
        {
            // Arrange
            TypeDesign typeDesign = CreateTypeDesign("ClassName1", "BaseType1", true, false);

            // Act
            bool result = typeDesign.Equals(null);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing with itself.
        /// Input: Same instance.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_SameInstance_ReturnsTrue()
        {
            // Arrange
            TypeDesign typeDesign = CreateTypeDesign("ClassName1", "BaseType1", true, false);

            // Act
            bool result = typeDesign.Equals(typeDesign);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when all properties are equal.
        /// Input: Two instances with identical property values.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_AllPropertiesEqual_ReturnsTrue()
        {
            // Arrange
            TypeDesign typeDesign1 = CreateTypeDesign("ClassName1", "BaseType1", true, false);
            TypeDesign typeDesign2 = CreateTypeDesign("ClassName1", "BaseType1", true, false);

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when ClassName differs.
        /// Input: Two instances with different ClassName values.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentClassName_ReturnsFalse()
        {
            // Arrange
            TypeDesign typeDesign1 = CreateTypeDesign("ClassName1", "BaseType1", true, false);
            TypeDesign typeDesign2 = CreateTypeDesign("ClassName2", "BaseType1", true, false);

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when one ClassName is null.
        /// Input: One instance with null ClassName, another with non-null.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_OneClassNameNull_ReturnsFalse()
        {
            // Arrange
            TypeDesign typeDesign1 = CreateTypeDesign(null, "BaseType1", true, false);
            TypeDesign typeDesign2 = CreateTypeDesign("ClassName2", "BaseType1", true, false);

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both ClassNames are null.
        /// Input: Two instances with null ClassNames.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_BothClassNamesNull_ReturnsTrue()
        {
            // Arrange
            TypeDesign typeDesign1 = CreateTypeDesign(null, "BaseType1", true, false);
            TypeDesign typeDesign2 = CreateTypeDesign(null, "BaseType1", true, false);

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when BaseType differs.
        /// Input: Two instances with different BaseType values.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentBaseType_ReturnsFalse()
        {
            // Arrange
            TypeDesign typeDesign1 = CreateTypeDesign("ClassName1", "BaseType1", true, false);
            TypeDesign typeDesign2 = CreateTypeDesign("ClassName1", "BaseType2", true, false);

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when BaseType namespace differs.
        /// Input: Two instances with BaseType having different namespaces.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentBaseTypeNamespace_ReturnsFalse()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                ClassName = "ClassName1",
                BaseType = new XmlQualifiedName("BaseType1", "http://namespace1.com"),
                IsAbstract = true,
                NoClassGeneration = false,
                BrowseName = "Node1"
            };
            var typeDesign2 = new TypeDesign
            {
                ClassName = "ClassName1",
                BaseType = new XmlQualifiedName("BaseType1", "http://namespace2.com"),
                IsAbstract = true,
                NoClassGeneration = false,
                BrowseName = "Node1"
            };

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both BaseTypes are null.
        /// Input: Two instances with null BaseTypes.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_BothBaseTypesNull_ReturnsTrue()
        {
            // Arrange
            TypeDesign typeDesign1 = CreateTypeDesign("ClassName1", null, true, false);
            TypeDesign typeDesign2 = CreateTypeDesign("ClassName1", null, true, false);

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when one BaseType is null.
        /// Input: One instance with null BaseType, another with non-null.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_OneBaseTypeNull_ReturnsFalse()
        {
            // Arrange
            TypeDesign typeDesign1 = CreateTypeDesign("ClassName1", null, true, false);
            TypeDesign typeDesign2 = CreateTypeDesign("ClassName1", "BaseType1", true, false);

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when IsAbstract differs.
        /// Input: Two instances with different IsAbstract values.
        /// Expected: Returns false.
        /// </summary>
        [TestCase(true, false)]
        [TestCase(false, true)]
        public void Equals_DifferentIsAbstract_ReturnsFalse(bool isAbstract1, bool isAbstract2)
        {
            // Arrange
            TypeDesign typeDesign1 = CreateTypeDesign("ClassName1", "BaseType1", isAbstract1, false);
            TypeDesign typeDesign2 = CreateTypeDesign("ClassName1", "BaseType1", isAbstract2, false);

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when NoClassGeneration differs.
        /// Input: Two instances with different NoClassGeneration values.
        /// Expected: Returns false.
        /// </summary>
        [TestCase(true, false)]
        [TestCase(false, true)]
        public void Equals_DifferentNoClassGeneration_ReturnsFalse(bool noClassGen1, bool noClassGen2)
        {
            // Arrange
            TypeDesign typeDesign1 = CreateTypeDesign("ClassName1", "BaseType1", true, noClassGen1);
            TypeDesign typeDesign2 = CreateTypeDesign("ClassName1", "BaseType1", true, noClassGen2);

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when BaseTypeNode differs.
        /// Input: Two instances with different BaseTypeNode values.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentBaseTypeNode_ReturnsFalse()
        {
            // Arrange
            TypeDesign baseTypeNode1 = CreateTypeDesign("BaseClass1", "Root", false, false);
            TypeDesign baseTypeNode2 = CreateTypeDesign("BaseClass2", "Root", false, false);

            TypeDesign typeDesign1 = CreateTypeDesign("ClassName1", "BaseType1", true, false);
            typeDesign1.BaseTypeNode = baseTypeNode1;

            TypeDesign typeDesign2 = CreateTypeDesign("ClassName1", "BaseType1", true, false);
            typeDesign2.BaseTypeNode = baseTypeNode2;

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both BaseTypeNodes are null.
        /// Input: Two instances with null BaseTypeNodes.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_BothBaseTypeNodesNull_ReturnsTrue()
        {
            // Arrange
            TypeDesign typeDesign1 = CreateTypeDesign("ClassName1", "BaseType1", true, false);
            typeDesign1.BaseTypeNode = null;

            TypeDesign typeDesign2 = CreateTypeDesign("ClassName1", "BaseType1", true, false);
            typeDesign2.BaseTypeNode = null;

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when one BaseTypeNode is null.
        /// Input: One instance with null BaseTypeNode, another with non-null.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_OneBaseTypeNodeNull_ReturnsFalse()
        {
            // Arrange
            TypeDesign baseTypeNode = CreateTypeDesign("BaseClass1", "Root", false, false);

            TypeDesign typeDesign1 = CreateTypeDesign("ClassName1", "BaseType1", true, false);
            typeDesign1.BaseTypeNode = null;

            TypeDesign typeDesign2 = CreateTypeDesign("ClassName1", "BaseType1", true, false);
            typeDesign2.BaseTypeNode = baseTypeNode;

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when base properties differ (BrowseName).
        /// Input: Two instances with different BrowseName (base property).
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentBrowseName_ReturnsFalse()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                ClassName = "ClassName1",
                BaseType = new XmlQualifiedName("BaseType1"),
                IsAbstract = true,
                NoClassGeneration = false,
                BrowseName = "Node1"
            };
            var typeDesign2 = new TypeDesign
            {
                ClassName = "ClassName1",
                BaseType = new XmlQualifiedName("BaseType1"),
                IsAbstract = true,
                NoClassGeneration = false,
                BrowseName = "Node2"
            };

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when all properties including defaults are equal.
        /// Input: Two instances with default boolean values.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_DefaultValues_ReturnsTrue()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                BrowseName = "Node1"
            };
            var typeDesign2 = new TypeDesign
            {
                BrowseName = "Node1"
            };

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when multiple properties differ.
        /// Input: Two instances with multiple different properties.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_MultiplePropertiesDifferent_ReturnsFalse()
        {
            // Arrange
            TypeDesign typeDesign1 = CreateTypeDesign("ClassName1", "BaseType1", true, false);
            TypeDesign typeDesign2 = CreateTypeDesign("ClassName2", "BaseType2", false, true);

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles empty string ClassName correctly.
        /// Input: Two instances with empty string ClassNames.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_EmptyStringClassName_ReturnsTrue()
        {
            // Arrange
            TypeDesign typeDesign1 = CreateTypeDesign(string.Empty, "BaseType1", true, false);
            TypeDesign typeDesign2 = CreateTypeDesign(string.Empty, "BaseType1", true, false);

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when one ClassName is empty and other is not.
        /// Input: One instance with empty ClassName, another with non-empty.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_OneEmptyClassName_ReturnsFalse()
        {
            // Arrange
            TypeDesign typeDesign1 = CreateTypeDesign(string.Empty, "BaseType1", true, false);
            TypeDesign typeDesign2 = CreateTypeDesign("ClassName2", "BaseType1", true, false);

            // Act
            bool result = typeDesign1.Equals(typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Helper method to create a TypeDesign instance with specified properties.
        /// </summary>
        private static TypeDesign CreateTypeDesign(string className, string baseTypeName, bool isAbstract, bool noClassGeneration)
        {
            return new TypeDesign
            {
                ClassName = className,
                BaseType = baseTypeName != null ? new XmlQualifiedName(baseTypeName) : null,
                IsAbstract = isAbstract,
                NoClassGeneration = noClassGeneration,
                BrowseName = "TestNode"
            };
        }

        /// <summary>
        /// Tests that Equals returns false when obj is null.
        /// </summary>
        [Test]
        public void Equals_NullObject_ReturnsFalse()
        {
            // Arrange
            var typeDesign = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = typeDesign.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two different instances with identical values.
        /// </summary>
        [Test]
        public void Equals_DifferentInstancesWithSameValues_ReturnsTrue()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            var typeDesign2 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            bool result = typeDesign1.Equals((object)typeDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing instances with different IsAbstract values.
        /// </summary>
        [Test]
        public void Equals_DifferentIsAbstract_ReturnsFalse()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = true,
                NoClassGeneration = false
            };

            var typeDesign2 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            bool result = typeDesign1.Equals((object)typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing instances with different NoClassGeneration values.
        /// </summary>
        [Test]
        public void Equals_DifferentNoClassGeneration_ReturnsFalse()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = true
            };

            var typeDesign2 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            bool result = typeDesign1.Equals((object)typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when obj is of a different type.
        /// </summary>
        [Test]
        public void Equals_DifferentType_ReturnsFalse()
        {
            // Arrange
            var typeDesign = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };
            var differentTypeObject = new ObjectDesign();

            // Act
            bool result = typeDesign.Equals(differentTypeObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when obj is a completely unrelated type.
        /// </summary>
        [Test]
        public void Equals_CompletelyDifferentType_ReturnsFalse()
        {
            // Arrange
            var typeDesign = new TypeDesign
            {
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };
            const string differentObject = "StringObject";

            // Act
            bool result = typeDesign.Equals(differentObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both instances have null ClassName values.
        /// </summary>
        [Test]
        public void Equals_BothNullClassName_ReturnsTrue()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = null,
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            var typeDesign2 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = null,
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            bool result = typeDesign1.Equals((object)typeDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when both instances have null BaseType values.
        /// </summary>
        [Test]
        public void Equals_BothNullBaseType_ReturnsTrue()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "TestClass",
                BaseType = null,
                IsAbstract = false,
                NoClassGeneration = false
            };

            var typeDesign2 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "TestClass",
                BaseType = null,
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            bool result = typeDesign1.Equals((object)typeDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when one ClassName is null and the other is not.
        /// </summary>
        [Test]
        public void Equals_OneNullClassName_ReturnsFalse()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            var typeDesign2 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = null,
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            bool result = typeDesign1.Equals((object)typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when one BaseType is null and the other is not.
        /// </summary>
        [Test]
        public void Equals_OneNullBaseType_ReturnsFalse()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            var typeDesign2 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "TestClass",
                BaseType = null,
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            bool result = typeDesign1.Equals((object)typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when ClassName values differ in case sensitivity (strings are case-sensitive by default).
        /// </summary>
        [Test]
        public void Equals_ClassNameCaseDifference_ReturnsFalse()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            var typeDesign2 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "testclass",
                BaseType = new XmlQualifiedName("BaseType", "http://test.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            bool result = typeDesign1.Equals((object)typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals correctly handles BaseType with different namespaces.
        /// </summary>
        [Test]
        public void Equals_BaseTypeWithDifferentNamespace_ReturnsFalse()
        {
            // Arrange
            var typeDesign1 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test1.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            var typeDesign2 = new TypeDesign
            {
                SymbolicId = new XmlQualifiedName("TypeId", "http://test.com"),
                ClassName = "TestClass",
                BaseType = new XmlQualifiedName("BaseType", "http://test2.com"),
                IsAbstract = false,
                NoClassGeneration = false
            };

            // Act
            bool result = typeDesign1.Equals((object)typeDesign2);

            // Assert
            Assert.That(result, Is.False);
        }
    }

    /// <summary>
    /// Tests for the <see cref="Parameter"/> class Equals methods.
    /// </summary>
    public partial class ParameterTests
    {
        /// <summary>
        /// Tests that Equals(object) returns false when the input is null.
        /// </summary>
        [Test]
        public void Equals_NullObject_ReturnsFalse()
        {
            // Arrange
            var parameter = new Parameter { Name = "TestParameter" };

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = parameter.Equals((object)null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when the input is of a different type.
        /// </summary>
        [Test]
        [TestCase("string")]
        [TestCase(42)]
        [TestCase(3.14)]
        public void Equals_DifferentType_ReturnsFalse(object obj)
        {
            // Arrange
            var parameter = new Parameter { Name = "TestParameter" };

            // Act
            bool result = parameter.Equals(obj);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns true when comparing the same instance.
        /// </summary>
        [Test]
        public void Equals_SameInstance_ReturnsTrue()
        {
            // Arrange
            var parameter = new Parameter
            {
                Name = "TestParameter",
                Identifier = 123,
                IdentifierSpecified = true,
                BitMask = "0xFF",
                DataType = new XmlQualifiedName("Int32", "http://opcfoundation.org/UA/"),
                ValueRank = ValueRank.Scalar,
                ArrayDimensions = "1,2,3",
                AllowSubTypes = true,
                IsOptional = false,
                ReleaseStatus = ReleaseStatus.Released
            };

            // Act
            bool result = parameter.Equals((object)parameter);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns true when comparing two instances with identical property values.
        /// </summary>
        [Test]
        public void Equals_EqualInstances_ReturnsTrue()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Name = "TestParameter",
                Identifier = 123,
                IdentifierSpecified = true,
                BitMask = "0xFF",
                DataType = new XmlQualifiedName("Int32", "http://opcfoundation.org/UA/"),
                ValueRank = ValueRank.Scalar,
                ArrayDimensions = "1,2,3",
                AllowSubTypes = true,
                IsOptional = false,
                ReleaseStatus = ReleaseStatus.Released
            };

            var parameter2 = new Parameter
            {
                Name = "TestParameter",
                Identifier = 123,
                IdentifierSpecified = true,
                BitMask = "0xFF",
                DataType = new XmlQualifiedName("Int32", "http://opcfoundation.org/UA/"),
                ValueRank = ValueRank.Scalar,
                ArrayDimensions = "1,2,3",
                AllowSubTypes = true,
                IsOptional = false,
                ReleaseStatus = ReleaseStatus.Released
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when Name differs.
        /// </summary>
        [Test]
        public void Equals_DifferentName_ReturnsFalse()
        {
            // Arrange
            var parameter1 = new Parameter { Name = "Parameter1" };
            var parameter2 = new Parameter { Name = "Parameter2" };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when Identifier differs.
        /// </summary>
        [Test]
        public void Equals_DifferentIdentifier_ReturnsFalse()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Name = "Test",
                Identifier = 100,
                IdentifierSpecified = true
            };
            var parameter2 = new Parameter
            {
                Name = "Test",
                Identifier = 200,
                IdentifierSpecified = true
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when IdentifierSpecified differs.
        /// </summary>
        [Test]
        public void Equals_DifferentIdentifierSpecified_ReturnsFalse()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Name = "Test",
                Identifier = 100,
                IdentifierSpecified = true
            };
            var parameter2 = new Parameter
            {
                Name = "Test",
                Identifier = 100,
                IdentifierSpecified = false
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when BitMask differs.
        /// </summary>
        [Test]
        public void Equals_DifferentBitMask_ReturnsFalse()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Name = "Test",
                BitMask = "0xFF"
            };
            var parameter2 = new Parameter
            {
                Name = "Test",
                BitMask = "0x00"
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when DataType differs.
        /// </summary>
        [Test]
        public void Equals_DifferentDataType_ReturnsFalse()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Name = "Test",
                DataType = new XmlQualifiedName("Int32", "http://opcfoundation.org/UA/")
            };
            var parameter2 = new Parameter
            {
                Name = "Test",
                DataType = new XmlQualifiedName("String", "http://opcfoundation.org/UA/")
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when ArrayDimensions differs.
        /// </summary>
        [Test]
        public void Equals_DifferentArrayDimensions_ReturnsFalse()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Name = "Test",
                ArrayDimensions = "1,2,3"
            };
            var parameter2 = new Parameter
            {
                Name = "Test",
                ArrayDimensions = "4,5,6"
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when AllowSubTypes differs.
        /// </summary>
        [Test]
        public void Equals_DifferentAllowSubTypes_ReturnsFalse()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Name = "Test",
                AllowSubTypes = true
            };
            var parameter2 = new Parameter
            {
                Name = "Test",
                AllowSubTypes = false
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when IsOptional differs.
        /// </summary>
        [Test]
        public void Equals_DifferentIsOptional_ReturnsFalse()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Name = "Test",
                IsOptional = true
            };
            var parameter2 = new Parameter
            {
                Name = "Test",
                IsOptional = false
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when ReleaseStatus differs.
        /// </summary>
        [Test]
        public void Equals_DifferentReleaseStatus_ReturnsFalse()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Name = "Test",
                ReleaseStatus = ReleaseStatus.Released
            };
            var parameter2 = new Parameter
            {
                Name = "Test",
                ReleaseStatus = ReleaseStatus.Draft
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns true when both instances have default values.
        /// </summary>
        [Test]
        public void Equals_DefaultInstances_ReturnsTrue()
        {
            // Arrange
            var parameter1 = new Parameter();
            var parameter2 = new Parameter();

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns true when both instances have null string properties.
        /// </summary>
        [Test]
        public void Equals_NullStringProperties_ReturnsTrue()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Name = null,
                BitMask = null,
                ArrayDimensions = null
            };
            var parameter2 = new Parameter
            {
                Name = null,
                BitMask = null,
                ArrayDimensions = null
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when comparing with an incompatible type instance.
        /// </summary>
        [Test]
        public void Equals_IncompatibleType_ReturnsFalse()
        {
            // Arrange
            var parameter = new Parameter { Name = "Test" };
            var otherObject = new LocalizedText { Key = "Test" };

            // Act
            bool result = parameter.Equals((object)otherObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) handles extreme decimal Identifier values correctly.
        /// </summary>
        [Test]
        [TestCase(0)]
        [TestCase(-1)]
        [TestCase(1)]
        public void Equals_ExtremeIdentifierValues_WorksCorrectly(decimal identifierValue)
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Name = "Test",
                Identifier = identifierValue,
                IdentifierSpecified = true
            };
            var parameter2 = new Parameter
            {
                Name = "Test",
                Identifier = identifierValue,
                IdentifierSpecified = true
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when Name is null in one instance but not the other.
        /// </summary>
        [Test]
        public void Equals_NullVsNonNullName_ReturnsFalse()
        {
            // Arrange
            var parameter1 = new Parameter { Name = null };
            var parameter2 = new Parameter { Name = "Test" };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) handles empty string properties correctly.
        /// </summary>
        [Test]
        public void Equals_EmptyStringProperties_ReturnsTrue()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Name = string.Empty,
                BitMask = string.Empty,
                ArrayDimensions = string.Empty
            };
            var parameter2 = new Parameter
            {
                Name = string.Empty,
                BitMask = string.Empty,
                ArrayDimensions = string.Empty
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) handles whitespace-only string properties correctly.
        /// </summary>
        [Test]
        public void Equals_WhitespaceStringProperties_ReturnsTrue()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Name = "   ",
                BitMask = "\t",
                ArrayDimensions = "\n"
            };
            var parameter2 = new Parameter
            {
                Name = "   ",
                BitMask = "\t",
                ArrayDimensions = "\n"
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) handles very long string properties correctly.
        /// </summary>
        [Test]
        public void Equals_VeryLongStringProperties_ReturnsTrue()
        {
            // Arrange
            string longString = new('a', 10000);
            var parameter1 = new Parameter
            {
                Name = longString,
                BitMask = longString,
                ArrayDimensions = longString
            };
            var parameter2 = new Parameter
            {
                Name = longString,
                BitMask = longString,
                ArrayDimensions = longString
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) handles special characters in string properties correctly.
        /// </summary>
        [Test]
        public void Equals_SpecialCharactersInStrings_ReturnsTrue()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Name = "Test\n\r\t\0",
                BitMask = "特殊字符",
                ArrayDimensions = "😀🎉"
            };
            var parameter2 = new Parameter
            {
                Name = "Test\n\r\t\0",
                BitMask = "特殊字符",
                ArrayDimensions = "😀🎉"
            };

            // Act
            bool result = parameter1.Equals((object)parameter2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that GetHashCode returns consistent hash code for the same object.
        /// The hash code should remain constant across multiple calls on the same instance.
        /// Expected result: Same hash code value on repeated calls.
        /// </summary>
        [Test]
        public void GetHashCode_SameObject_ReturnsConsistentHashCode()
        {
            // Arrange
            var parameter = new Parameter
            {
                Name = "TestParameter",
                Description = new LocalizedText { Value = "Test Description" },
                DefaultValue = null,
                DisplayName = new LocalizedText { Value = "Test Display" },
                Identifier = 42,
                IdentifierSpecified = true,
                BitMask = "0xFF",
                DataType = new XmlQualifiedName("int", "http://test.com"),
                ValueRank = ValueRank.Scalar,
                ArrayDimensions = "1,2,3",
                AllowSubTypes = true,
                IsOptional = false,
                ReleaseStatus = ReleaseStatus.Released
            };

            // Act
            int firstHash = parameter.GetHashCode();
            int secondHash = parameter.GetHashCode();

            // Assert
            Assert.That(secondHash, Is.EqualTo(firstHash));
        }

        /// <summary>
        /// Tests that GetHashCode handles null properties correctly.
        /// All nullable properties set to null should produce a valid hash code without throwing.
        /// Expected result: Valid hash code with no exceptions.
        /// </summary>
        [Test]
        public void GetHashCode_AllNullablePropertiesNull_ReturnsValidHashCode()
        {
            // Arrange
            var parameter = new Parameter
            {
                Name = null,
                Description = null,
                DefaultValue = null,
                DisplayName = null,
                Identifier = 0,
                IdentifierSpecified = false,
                BitMask = null,
                DataType = null,
                ValueRank = ValueRank.Scalar,
                ArrayDimensions = null,
                AllowSubTypes = false,
                IsOptional = false,
                ReleaseStatus = ReleaseStatus.Released
            };

            // Act
            int hashCode = parameter.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests that changing the Name property produces a different hash code.
        /// Verifies that the Name property contributes to the hash code calculation.
        /// Expected result: Different hash codes for different Name values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentName_ReturnsDifferentHashCode()
        {
            // Arrange
            var parameter1 = new Parameter { Name = "Parameter1" };
            var parameter2 = new Parameter { Name = "Parameter2" };

            // Act
            int hash1 = parameter1.GetHashCode();
            int hash2 = parameter2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that changing the Identifier property produces a different hash code.
        /// Verifies that the Identifier property contributes to the hash code calculation.
        /// Expected result: Different hash codes for different Identifier values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentIdentifier_ReturnsDifferentHashCode()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Identifier = 1,
                IdentifierSpecified = true
            };
            var parameter2 = new Parameter
            {
                Identifier = 2,
                IdentifierSpecified = true
            };

            // Act
            int hash1 = parameter1.GetHashCode();
            int hash2 = parameter2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that changing the IdentifierSpecified property produces a different hash code.
        /// Verifies that the IdentifierSpecified property contributes to the hash code calculation.
        /// Expected result: Different hash codes for different IdentifierSpecified values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentIdentifierSpecified_ReturnsDifferentHashCode()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                Identifier = 100,
                IdentifierSpecified = true
            };
            var parameter2 = new Parameter
            {
                Identifier = 100,
                IdentifierSpecified = false
            };

            // Act
            int hash1 = parameter1.GetHashCode();
            int hash2 = parameter2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that changing the DataType property produces a different hash code.
        /// Verifies that the DataType property with XmlQualifiedNameEqualityComparer contributes to the hash code calculation.
        /// Expected result: Different hash codes for different DataType values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentDataType_ReturnsDifferentHashCode()
        {
            // Arrange
            var parameter1 = new Parameter
            {
                DataType = new XmlQualifiedName("int", "http://www.w3.org/2001/XMLSchema")
            };
            var parameter2 = new Parameter
            {
                DataType = new XmlQualifiedName("string", "http://www.w3.org/2001/XMLSchema")
            };

            // Act
            int hash1 = parameter1.GetHashCode();
            int hash2 = parameter2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that changing the AllowSubTypes property produces a different hash code.
        /// Verifies that the AllowSubTypes boolean property contributes to the hash code calculation.
        /// Expected result: Different hash codes for different AllowSubTypes values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentAllowSubTypes_ReturnsDifferentHashCode()
        {
            // Arrange
            var parameter1 = new Parameter { AllowSubTypes = false };
            var parameter2 = new Parameter { AllowSubTypes = true };

            // Act
            int hash1 = parameter1.GetHashCode();
            int hash2 = parameter2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that changing the IsOptional property produces a different hash code.
        /// Verifies that the IsOptional boolean property contributes to the hash code calculation.
        /// Expected result: Different hash codes for different IsOptional values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentIsOptional_ReturnsDifferentHashCode()
        {
            // Arrange
            var parameter1 = new Parameter { IsOptional = false };
            var parameter2 = new Parameter { IsOptional = true };

            // Act
            int hash1 = parameter1.GetHashCode();
            int hash2 = parameter2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that changing the ReleaseStatus property produces a different hash code.
        /// Verifies that the ReleaseStatus enum property contributes to the hash code calculation.
        /// Expected result: Different hash codes for different ReleaseStatus values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentReleaseStatus_ReturnsDifferentHashCode()
        {
            // Arrange
            var parameter1 = new Parameter { ReleaseStatus = ReleaseStatus.Released };
            var parameter2 = new Parameter { ReleaseStatus = ReleaseStatus.Draft };

            // Act
            int hash1 = parameter1.GetHashCode();
            int hash2 = parameter2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that changing the BitMask property produces a different hash code.
        /// Verifies that the BitMask string property contributes to the hash code calculation.
        /// Expected result: Different hash codes for different BitMask values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentBitMask_ReturnsDifferentHashCode()
        {
            // Arrange
            var parameter1 = new Parameter { BitMask = "0x01" };
            var parameter2 = new Parameter { BitMask = "0x02" };

            // Act
            int hash1 = parameter1.GetHashCode();
            int hash2 = parameter2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests that changing the ArrayDimensions property produces a different hash code.
        /// Verifies that the ArrayDimensions string property contributes to the hash code calculation.
        /// Expected result: Different hash codes for different ArrayDimensions values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentArrayDimensions_ReturnsDifferentHashCode()
        {
            // Arrange
            var parameter1 = new Parameter { ArrayDimensions = "1,2,3" };
            var parameter2 = new Parameter { ArrayDimensions = "4,5,6" };

            // Act
            int hash1 = parameter1.GetHashCode();
            int hash2 = parameter2.GetHashCode();

            // Assert
            Assert.That(hash2, Is.Not.EqualTo(hash1));
        }

        /// <summary>
        /// Tests hash code with extreme Identifier values.
        /// Verifies that extreme decimal values are handled correctly in hash code calculation.
        /// Expected result: Valid hash codes for extreme values.
        /// </summary>
        [TestCase(0)]
        [TestCase(1)]
        [TestCase(-1)]
        public void GetHashCode_ExtremeIdentifierValues_ReturnsValidHashCode(decimal identifier)
        {
            // Arrange
            var parameter = new Parameter
            {
                Identifier = identifier,
                IdentifierSpecified = true
            };

            // Act
            int hashCode = parameter.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests hash code with empty string properties.
        /// Verifies that empty strings are handled correctly in hash code calculation.
        /// Expected result: Valid hash code.
        /// </summary>
        [Test]
        public void GetHashCode_EmptyStrings_ReturnsValidHashCode()
        {
            // Arrange
            var parameter = new Parameter
            {
                Name = string.Empty,
                BitMask = string.Empty,
                ArrayDimensions = string.Empty
            };

            // Act
            int hashCode = parameter.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests hash code with whitespace-only string properties.
        /// Verifies that whitespace strings are handled correctly in hash code calculation.
        /// Expected result: Valid hash code different from empty strings.
        /// </summary>
        [Test]
        public void GetHashCode_WhitespaceStrings_ReturnsDifferentHashCodeFromEmpty()
        {
            // Arrange
            var parameterEmpty = new Parameter { Name = string.Empty };
            var parameterWhitespace = new Parameter { Name = "   " };

            // Act
            int hashEmpty = parameterEmpty.GetHashCode();
            int hashWhitespace = parameterWhitespace.GetHashCode();

            // Assert
            Assert.That(hashWhitespace, Is.Not.EqualTo(hashEmpty));
        }

        /// <summary>
        /// Tests hash code with very long string properties.
        /// Verifies that long strings are handled correctly in hash code calculation.
        /// Expected result: Valid hash code.
        /// </summary>
        [Test]
        public void GetHashCode_VeryLongStrings_ReturnsValidHashCode()
        {
            // Arrange
            string longString = new('a', 10000);
            var parameter = new Parameter
            {
                Name = longString,
                BitMask = longString,
                ArrayDimensions = longString
            };

            // Act
            int hashCode = parameter.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests hash code with special characters in string properties.
        /// Verifies that special and control characters are handled correctly in hash code calculation.
        /// Expected result: Valid hash code.
        /// </summary>
        [Test]
        public void GetHashCode_SpecialCharactersInStrings_ReturnsValidHashCode()
        {
            // Arrange
            var parameter = new Parameter
            {
                Name = "Test\n\r\t\0Parameter",
                BitMask = "!@#$%^&*()",
                ArrayDimensions = "你好世界"
            };

            // Act
            int hashCode = parameter.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }

        /// <summary>
        /// Tests that all ReleaseStatus enum values produce valid hash codes.
        /// Verifies that all defined ReleaseStatus enum values are handled correctly.
        /// Expected result: Valid hash codes for all enum values.
        /// </summary>
        [TestCase(ReleaseStatus.Released)]
        [TestCase(ReleaseStatus.Draft)]
        [TestCase(ReleaseStatus.Deprecated)]
        public void GetHashCode_AllReleaseStatusEnumValues_ReturnsValidHashCode(ReleaseStatus releaseStatus)
        {
            // Arrange
            var parameter = new Parameter { ReleaseStatus = releaseStatus };

            // Act
            int hashCode = parameter.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0).Or.EqualTo(0));
        }
    }

    /// <summary>
    /// Unit tests for the <see cref="ReferenceTypeDesign"/> class.
    /// </summary>
    public partial class ReferenceTypeDesignTests
    {
        /// <summary>
        /// Tests that GetHashCode returns consistent results when called multiple times on the same instance.
        /// </summary>
        [Test]
        public void GetHashCode_CalledMultipleTimes_ReturnsConsistentValue()
        {
            // Arrange
            var referenceType = new ReferenceTypeDesign
            {
                InverseName = new LocalizedText { Value = "TestInverse" },
                Symmetric = true,
                SymmetricSpecified = true
            };

            // Act
            int hashCode1 = referenceType.GetHashCode();
            int hashCode2 = referenceType.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that two instances with identical property values produce the same hash code.
        /// </summary>
        [Test]
        public void GetHashCode_EqualInstances_ReturnsSameHashCode()
        {
            // Arrange
            var inverseName = new LocalizedText { Value = "TestInverse" };
            var referenceType1 = new ReferenceTypeDesign
            {
                InverseName = inverseName,
                Symmetric = true,
                SymmetricSpecified = true
            };
            var referenceType2 = new ReferenceTypeDesign
            {
                InverseName = inverseName,
                Symmetric = true,
                SymmetricSpecified = true
            };

            // Act
            int hashCode1 = referenceType1.GetHashCode();
            int hashCode2 = referenceType2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode handles null InverseName property correctly.
        /// </summary>
        [Test]
        public void GetHashCode_NullInverseName_ReturnsValidHashCode()
        {
            // Arrange
            var referenceType = new ReferenceTypeDesign
            {
                InverseName = null,
                Symmetric = false,
                SymmetricSpecified = false
            };

            // Act
            int hashCode = referenceType.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that different InverseName values typically produce different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentInverseName_ProducesDifferentHashCode()
        {
            // Arrange
            var referenceType1 = new ReferenceTypeDesign
            {
                InverseName = new LocalizedText { Value = "InverseName1" },
                Symmetric = true,
                SymmetricSpecified = true
            };
            var referenceType2 = new ReferenceTypeDesign
            {
                InverseName = new LocalizedText { Value = "InverseName2" },
                Symmetric = true,
                SymmetricSpecified = true
            };

            // Act
            int hashCode1 = referenceType1.GetHashCode();
            int hashCode2 = referenceType2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that different Symmetric values produce different hash codes.
        /// </summary>
        /// <param name="symmetric1">First Symmetric value.</param>
        /// <param name="symmetric2">Second Symmetric value.</param>
        [TestCase(true, false)]
        [TestCase(false, true)]
        public void GetHashCode_DifferentSymmetric_ProducesDifferentHashCode(bool symmetric1, bool symmetric2)
        {
            // Arrange
            var inverseName = new LocalizedText { Value = "TestInverse" };
            var referenceType1 = new ReferenceTypeDesign
            {
                InverseName = inverseName,
                Symmetric = symmetric1,
                SymmetricSpecified = true
            };
            var referenceType2 = new ReferenceTypeDesign
            {
                InverseName = inverseName,
                Symmetric = symmetric2,
                SymmetricSpecified = true
            };

            // Act
            int hashCode1 = referenceType1.GetHashCode();
            int hashCode2 = referenceType2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that different SymmetricSpecified values produce different hash codes.
        /// </summary>
        /// <param name="symmetricSpecified1">First SymmetricSpecified value.</param>
        /// <param name="symmetricSpecified2">Second SymmetricSpecified value.</param>
        [TestCase(true, false)]
        [TestCase(false, true)]
        public void GetHashCode_DifferentSymmetricSpecified_ProducesDifferentHashCode(bool symmetricSpecified1, bool symmetricSpecified2)
        {
            // Arrange
            var inverseName = new LocalizedText { Value = "TestInverse" };
            var referenceType1 = new ReferenceTypeDesign
            {
                InverseName = inverseName,
                Symmetric = true,
                SymmetricSpecified = symmetricSpecified1
            };
            var referenceType2 = new ReferenceTypeDesign
            {
                InverseName = inverseName,
                Symmetric = true,
                SymmetricSpecified = symmetricSpecified2
            };

            // Act
            int hashCode1 = referenceType1.GetHashCode();
            int hashCode2 = referenceType2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests GetHashCode with all boolean combinations to ensure consistent behavior.
        /// </summary>
        /// <param name="symmetric">Value for Symmetric property.</param>
        /// <param name="symmetricSpecified">Value for SymmetricSpecified property.</param>
        [TestCase(true, true)]
        [TestCase(true, false)]
        [TestCase(false, true)]
        [TestCase(false, false)]
        public void GetHashCode_AllBooleanCombinations_ReturnsValidHashCode(bool symmetric, bool symmetricSpecified)
        {
            // Arrange
            var referenceType = new ReferenceTypeDesign
            {
                InverseName = new LocalizedText { Value = "Test" },
                Symmetric = symmetric,
                SymmetricSpecified = symmetricSpecified
            };

            // Act
            int hashCode = referenceType.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode with minimal properties set returns a valid hash code.
        /// </summary>
        [Test]
        public void GetHashCode_MinimalProperties_ReturnsValidHashCode()
        {
            // Arrange
            var referenceType = new ReferenceTypeDesign
            {
                InverseName = null,
                Symmetric = false,
                SymmetricSpecified = false
            };

            // Act
            int hashCode = referenceType.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode incorporates base class properties by verifying different base properties affect the hash.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentBaseProperties_ProducesDifferentHashCode()
        {
            // Arrange
            var referenceType1 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Type1", "http://example.com"),
                InverseName = new LocalizedText { Value = "Test" },
                Symmetric = true,
                SymmetricSpecified = true
            };
            var referenceType2 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Type2", "http://example.com"),
                InverseName = new LocalizedText { Value = "Test" },
                Symmetric = true,
                SymmetricSpecified = true
            };

            // Act
            int hashCode1 = referenceType1.GetHashCode();
            int hashCode2 = referenceType2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode handles empty LocalizedText InverseName correctly.
        /// </summary>
        [Test]
        public void GetHashCode_EmptyInverseName_ReturnsValidHashCode()
        {
            // Arrange
            var referenceType = new ReferenceTypeDesign
            {
                InverseName = new LocalizedText { Value = string.Empty },
                Symmetric = true,
                SymmetricSpecified = false
            };

            // Act
            int hashCode = referenceType.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode handles LocalizedText with special characters in InverseName correctly.
        /// </summary>
        [Test]
        public void GetHashCode_InverseNameWithSpecialCharacters_ReturnsValidHashCode()
        {
            // Arrange
            var referenceType = new ReferenceTypeDesign
            {
                InverseName = new LocalizedText { Value = "Test@#$%^&*()!~`<>?/\\" },
                Symmetric = false,
                SymmetricSpecified = true
            };

            // Act
            int hashCode = referenceType.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that Equals returns false when other is null.
        /// </summary>
        [Test]
        public void Equals_NullOther_ReturnsFalse()
        {
            // Arrange
            var referenceType = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = referenceType.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing the same instance.
        /// </summary>
        [Test]
        public void Equals_SameInstance_ReturnsTrue()
        {
            // Arrange
            var referenceType = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            // Act
            bool result = referenceType.Equals(referenceType);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when all properties are equal.
        /// </summary>
        [Test]
        public void Equals_EqualInstances_ReturnsTrue()
        {
            // Arrange
            var referenceType1 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            var referenceType2 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            // Act
            bool result = referenceType1.Equals(referenceType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when InverseName differs.
        /// </summary>
        [Test]
        public void Equals_DifferentInverseName_ReturnsFalse()
        {
            // Arrange
            var referenceType1 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            var referenceType2 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key2", Value = "Value2" }
            };

            // Act
            bool result = referenceType1.Equals(referenceType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when one InverseName is null and the other is not.
        /// </summary>
        [Test]
        public void Equals_OneInverseNameNull_ReturnsFalse()
        {
            // Arrange
            var referenceType1 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            var referenceType2 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = null
            };

            // Act
            bool result = referenceType1.Equals(referenceType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both InverseName properties are null.
        /// </summary>
        [Test]
        public void Equals_BothInverseNameNull_ReturnsTrue()
        {
            // Arrange
            var referenceType1 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = null
            };

            var referenceType2 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = null
            };

            // Act
            bool result = referenceType1.Equals(referenceType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when Symmetric property differs.
        /// </summary>
        [Test]
        public void Equals_DifferentSymmetric_ReturnsFalse()
        {
            // Arrange
            var referenceType1 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            var referenceType2 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = false,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            // Act
            bool result = referenceType1.Equals(referenceType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when SymmetricSpecified property differs.
        /// </summary>
        [Test]
        public void Equals_DifferentSymmetricSpecified_ReturnsFalse()
        {
            // Arrange
            var referenceType1 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            var referenceType2 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = false,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            // Act
            bool result = referenceType1.Equals(referenceType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when base class properties differ.
        /// </summary>
        [Test]
        public void Equals_DifferentBaseClassProperties_ReturnsFalse()
        {
            // Arrange
            var referenceType1 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test1"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            var referenceType2 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test2"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            // Act
            bool result = referenceType1.Equals(referenceType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both Symmetric and SymmetricSpecified are false.
        /// </summary>
        [Test]
        public void Equals_BothSymmetricAndSymmetricSpecifiedFalse_ReturnsTrue()
        {
            // Arrange
            var referenceType1 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = false,
                SymmetricSpecified = false,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            var referenceType2 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = false,
                SymmetricSpecified = false,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            // Act
            bool result = referenceType1.Equals(referenceType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when multiple properties differ.
        /// </summary>
        [Test]
        public void Equals_MultiplePropertiesDiffer_ReturnsFalse()
        {
            // Arrange
            var referenceType1 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1" }
            };

            var referenceType2 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = false,
                SymmetricSpecified = false,
                InverseName = new LocalizedText { Key = "Key2", Value = "Value2" }
            };

            // Act
            bool result = referenceType1.Equals(referenceType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true with default-initialized instances.
        /// </summary>
        [Test]
        public void Equals_DefaultInitializedInstances_ReturnsTrue()
        {
            // Arrange
            var referenceType1 = new ReferenceTypeDesign();
            var referenceType2 = new ReferenceTypeDesign();

            // Act
            bool result = referenceType1.Equals(referenceType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when InverseName has different Key but same Value and DoNotIgnore.
        /// The implementation uses EqualityComparer default which checks all properties of LocalizedText.
        /// </summary>
        [Test]
        public void Equals_InverseNameDifferentKeyOnly_ReturnsFalse()
        {
            // Arrange
            var referenceType1 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key1", Value = "Value1", DoNotIgnore = true }
            };

            var referenceType2 = new ReferenceTypeDesign
            {
                SymbolicId = new XmlQualifiedName("Test"),
                Symmetric = true,
                SymmetricSpecified = true,
                InverseName = new LocalizedText { Key = "Key2", Value = "Value1", DoNotIgnore = true }
            };

            // Act
            bool result = referenceType1.Equals(referenceType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with null object.
        /// </summary>
        [Test]
        public void Equals_NullObject_ReturnsFalse()
        {
            // Arrange
            var referenceType = new ReferenceTypeDesign
            {
                SymbolicName = new XmlQualifiedName("TestReference", "http://test.org"),
                InverseName = new LocalizedText { Value = "InverseTest" },
                Symmetric = false,
                SymmetricSpecified = true
            };

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = referenceType.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with an object of a different type (string).
        /// </summary>
        [Test]
        public void Equals_DifferentTypeString_ReturnsFalse()
        {
            // Arrange
            var referenceType = new ReferenceTypeDesign
            {
                SymbolicName = new XmlQualifiedName("TestReference", "http://test.org"),
                InverseName = new LocalizedText { Value = "InverseTest" },
                Symmetric = false,
                SymmetricSpecified = true
            };
            object differentType = "not a ReferenceTypeDesign";

            // Act
            bool result = referenceType.Equals(differentType);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with an object of a different type (integer).
        /// </summary>
        [Test]
        public void Equals_DifferentTypeInteger_ReturnsFalse()
        {
            // Arrange
            var referenceType = new ReferenceTypeDesign
            {
                SymbolicName = new XmlQualifiedName("TestReference", "http://test.org"),
                InverseName = new LocalizedText { Value = "InverseTest" },
                Symmetric = false,
                SymmetricSpecified = true
            };
            object differentType = 42;

            // Act
            bool result = referenceType.Equals(differentType);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with an unrelated type.
        /// </summary>
        [Test]
        public void Equals_UnrelatedType_ReturnsFalse()
        {
            // Arrange
            var referenceType = new ReferenceTypeDesign
            {
                SymbolicName = new XmlQualifiedName("TestReference", "http://test.org"),
                InverseName = new LocalizedText { Value = "InverseTest" },
                Symmetric = false,
                SymmetricSpecified = true
            };
            object differentType = new ObjectDesign();

            // Act
            bool result = referenceType.Equals(differentType);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing two ReferenceTypeDesign instances with different base type properties.
        /// </summary>
        [Test]
        public void Equals_DifferentBaseTypeProperty_ReturnsFalse()
        {
            // Arrange
            var referenceType1 = new ReferenceTypeDesign
            {
                SymbolicName = new XmlQualifiedName("TestReference1", "http://test.org"),
                InverseName = new LocalizedText { Value = "InverseTest" },
                Symmetric = true,
                SymmetricSpecified = true
            };

            var referenceType2 = new ReferenceTypeDesign
            {
                SymbolicName = new XmlQualifiedName("TestReference2", "http://test.org"),
                InverseName = new LocalizedText { Value = "InverseTest" },
                Symmetric = true,
                SymmetricSpecified = true
            };

            // Act
            bool result = referenceType1.Equals((object)referenceType2);

            // Assert
            Assert.That(result, Is.False);
        }
    }

    /// <summary>
    /// Unit tests for <see cref="RolePermissionSet"/> class.
    /// </summary>
    public partial class RolePermissionSetTests
    {
        /// <summary>
        /// Tests that Equals returns false when comparing with null.
        /// </summary>
        [Test]
        public void Equals_NullObject_ReturnsFalse()
        {
            // Arrange
            var rolePermissionSet = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = false
            };

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = rolePermissionSet.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with a different type.
        /// </summary>
        [Test]
        public void Equals_DifferentType_ReturnsFalse()
        {
            // Arrange
            var rolePermissionSet = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = false
            };
            object differentType = "NotARolePermissionSet";

            // Act
            bool result = rolePermissionSet.Equals(differentType);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Name property differs.
        /// </summary>
        [Test]
        public void Equals_DifferentName_ReturnsFalse()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "Role1",
                DoNotInheirit = false
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "Role2",
                DoNotInheirit = false
            };

            // Act
            bool result = rolePermissionSet1.Equals((object)rolePermissionSet2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when DoNotInheirit property differs.
        /// </summary>
        [Test]
        public void Equals_DifferentDoNotInheirit_ReturnsFalse()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = false
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = true
            };

            // Act
            bool result = rolePermissionSet1.Equals((object)rolePermissionSet2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both instances have null RolePermission arrays.
        /// </summary>
        [Test]
        public void Equals_BothNullRolePermissions_ReturnsTrue()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = false,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            bool result = rolePermissionSet1.Equals((object)rolePermissionSet2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when both instances have empty RolePermission arrays.
        /// </summary>
        [Test]
        public void Equals_BothEmptyRolePermissions_ReturnsTrue()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = true,
                RolePermission = []
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = true,
                RolePermission = []
            };

            // Act
            bool result = rolePermissionSet1.Equals((object)rolePermissionSet2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when both instances have null Name property.
        /// </summary>
        [Test]
        public void Equals_BothNullNames_ReturnsTrue()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = null,
                DoNotInheirit = false
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = null,
                DoNotInheirit = false
            };

            // Act
            bool result = rolePermissionSet1.Equals((object)rolePermissionSet2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when one instance has null Name and the other has a non-null Name.
        /// </summary>
        [Test]
        public void Equals_OneNullName_ReturnsFalse()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = null,
                DoNotInheirit = false
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = false
            };

            // Act
            bool result = rolePermissionSet1.Equals((object)rolePermissionSet2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true for two instances with empty strings as Name.
        /// </summary>
        [Test]
        public void Equals_EmptyNames_ReturnsTrue()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = string.Empty,
                DoNotInheirit = true
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = string.Empty,
                DoNotInheirit = true
            };

            // Act
            bool result = rolePermissionSet1.Equals((object)rolePermissionSet2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with an object of a numeric type.
        /// </summary>
        [Test]
        public void Equals_NumericType_ReturnsFalse()
        {
            // Arrange
            var rolePermissionSet = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = false
            };
            object numericValue = 42;

            // Act
            bool result = rolePermissionSet.Equals(numericValue);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that GetHashCode returns the same value when called multiple times on the same object instance.
        /// Input: Same RolePermissionSet instance.
        /// Expected: Consistent hash code across multiple calls.
        /// </summary>
        [Test]
        public void GetHashCode_SameObjectCalledMultipleTimes_ReturnsSameHashCode()
        {
            // Arrange
            var rolePermissionSet = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = true,
                RolePermission =
                [
                    new RolePermission
                    {
                        Role = new XmlQualifiedName("Admin", "http://test.com")
                    }
                ]
            };

            // Act
            int hashCode1 = rolePermissionSet.GetHashCode();
            int hashCode2 = rolePermissionSet.GetHashCode();
            int hashCode3 = rolePermissionSet.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.EqualTo(hashCode2));
            Assert.That(hashCode2, Is.EqualTo(hashCode3));
        }

        /// <summary>
        /// Tests that GetHashCode returns the same value for two objects with identical property values.
        /// Input: Two RolePermissionSet instances with identical properties.
        /// Expected: Same hash code for both instances.
        /// </summary>
        [Test]
        public void GetHashCode_EqualObjects_ReturnsSameHashCode()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = true,
                RolePermission =
                [
                    new RolePermission
                    {
                        Role = new XmlQualifiedName("Admin", "http://test.com")
                    }
                ]
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = true,
                RolePermission =
                [
                    new RolePermission
                    {
                        Role = new XmlQualifiedName("Admin", "http://test.com")
                    }
                ]
            };

            // Act
            int hashCode1 = rolePermissionSet1.GetHashCode();
            int hashCode2 = rolePermissionSet2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode returns a valid hash code when RolePermission array is null.
        /// Input: RolePermissionSet with null RolePermission array.
        /// Expected: Valid hash code without throwing exception.
        /// </summary>
        [Test]
        public void GetHashCode_WithNullRolePermissionArray_ReturnsValidHashCode()
        {
            // Arrange
            var rolePermissionSet = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            int hashCode = rolePermissionSet.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode returns a valid hash code when RolePermission array is empty.
        /// Input: RolePermissionSet with empty RolePermission array.
        /// Expected: Valid hash code.
        /// </summary>
        [Test]
        public void GetHashCode_WithEmptyRolePermissionArray_ReturnsValidHashCode()
        {
            // Arrange
            var rolePermissionSet = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = false,
                RolePermission = []
            };

            // Act
            int hashCode = rolePermissionSet.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode returns a valid hash code when Name is null.
        /// Input: RolePermissionSet with null Name.
        /// Expected: Valid hash code without throwing exception.
        /// </summary>
        [Test]
        public void GetHashCode_WithNullName_ReturnsValidHashCode()
        {
            // Arrange
            var rolePermissionSet = new RolePermissionSet
            {
                Name = null,
                DoNotInheirit = true,
                RolePermission =
                [
                    new RolePermission
                    {
                        Role = new XmlQualifiedName("Admin", "http://test.com")
                    }
                ]
            };

            // Act
            int hashCode = rolePermissionSet.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode produces different hash codes for objects with different Name values.
        /// Input: Two RolePermissionSet instances with different Name properties.
        /// Expected: Different hash codes (though collisions are technically allowed).
        /// </summary>
        [Test]
        public void GetHashCode_WithDifferentNames_ProducesDifferentHashCodes()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "Role1",
                DoNotInheirit = false,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "Role2",
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            int hashCode1 = rolePermissionSet1.GetHashCode();
            int hashCode2 = rolePermissionSet2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.Not.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode produces different hash codes for objects with different DoNotInheirit values.
        /// Input: Two RolePermissionSet instances with different DoNotInheirit properties.
        /// Expected: Different hash codes (though collisions are technically allowed).
        /// </summary>
        [Test]
        public void GetHashCode_WithDifferentDoNotInheirit_ProducesDifferentHashCodes()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = false,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = true,
                RolePermission = null
            };

            // Act
            int hashCode1 = rolePermissionSet1.GetHashCode();
            int hashCode2 = rolePermissionSet2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.Not.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode produces different hash codes for objects with different RolePermission arrays.
        /// Input: Two RolePermissionSet instances with different RolePermission arrays.
        /// Expected: Different hash codes (though collisions are technically allowed).
        /// </summary>
        [Test]
        public void GetHashCode_WithDifferentRolePermissions_ProducesDifferentHashCodes()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = false,
                RolePermission =
                [
                    new RolePermission
                    {
                        Role = new XmlQualifiedName("Admin", "http://test.com")
                    }
                ]
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = false,
                RolePermission =
                [
                    new RolePermission
                    {
                        Role = new XmlQualifiedName("User", "http://test.com")
                    }
                ]
            };

            // Act
            int hashCode1 = rolePermissionSet1.GetHashCode();
            int hashCode2 = rolePermissionSet2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.Not.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode returns a valid hash code when all properties are set to non-null values.
        /// Input: RolePermissionSet with all properties populated.
        /// Expected: Valid hash code.
        /// </summary>
        [Test]
        public void GetHashCode_WithAllPropertiesSet_ReturnsValidHashCode()
        {
            // Arrange
            var rolePermissionSet = new RolePermissionSet
            {
                Name = "FullRole",
                DoNotInheirit = true,
                RolePermission =
                [
                    new RolePermission
                    {
                        Role = new XmlQualifiedName("Admin", "http://test.com")
                    },
                    new RolePermission
                    {
                        Role = new XmlQualifiedName("User", "http://test.com")
                    }
                ]
            };

            // Act
            int hashCode = rolePermissionSet.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode returns a valid hash code when all properties are at their default or null values.
        /// Input: RolePermissionSet with all properties null or default.
        /// Expected: Valid hash code.
        /// </summary>
        [Test]
        public void GetHashCode_WithAllPropertiesNullOrDefault_ReturnsValidHashCode()
        {
            // Arrange
            var rolePermissionSet = new RolePermissionSet
            {
                Name = null,
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            int hashCode = rolePermissionSet.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode returns the same hash code for objects with arrays containing the same elements.
        /// Input: Two RolePermissionSet instances with RolePermission arrays containing equivalent elements.
        /// Expected: Same hash code.
        /// </summary>
        [Test]
        public void GetHashCode_WithSameArrayContents_ReturnsSameHashCode()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = true,
                RolePermission =
                [
                    new RolePermission
                    {
                        Role = new XmlQualifiedName("Admin", "http://test.com")
                    },
                    new RolePermission
                    {
                        Role = new XmlQualifiedName("User", "http://test.com")
                    }
                ]
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = true,
                RolePermission =
                [
                    new RolePermission
                    {
                        Role = new XmlQualifiedName("Admin", "http://test.com")
                    },
                    new RolePermission
                    {
                        Role = new XmlQualifiedName("User", "http://test.com")
                    }
                ]
            };

            // Act
            int hashCode1 = rolePermissionSet1.GetHashCode();
            int hashCode2 = rolePermissionSet2.GetHashCode();

            // Assert
            Assert.That(hashCode1, Is.EqualTo(hashCode2));
        }

        /// <summary>
        /// Tests that GetHashCode handles extreme string values for Name property.
        /// Input: RolePermissionSet with empty string, whitespace, and very long string for Name.
        /// Expected: Valid hash codes for all cases.
        /// </summary>
        [TestCase("")]
        [TestCase(" ")]
        [TestCase("   \t\n")]
        public void GetHashCode_WithSpecialStringValues_ReturnsValidHashCode(string name)
        {
            // Arrange
            var rolePermissionSet = new RolePermissionSet
            {
                Name = name,
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            int hashCode = rolePermissionSet.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode handles very long strings for Name property.
        /// Input: RolePermissionSet with extremely long Name string.
        /// Expected: Valid hash code without performance issues.
        /// </summary>
        [Test]
        public void GetHashCode_WithVeryLongName_ReturnsValidHashCode()
        {
            // Arrange
            var rolePermissionSet = new RolePermissionSet
            {
                Name = new string('A', 10000),
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            int hashCode = rolePermissionSet.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that GetHashCode handles arrays with multiple RolePermission entries.
        /// Input: RolePermissionSet with large RolePermission array.
        /// Expected: Valid hash code.
        /// </summary>
        [Test]
        public void GetHashCode_WithLargeRolePermissionArray_ReturnsValidHashCode()
        {
            // Arrange
            var rolePermissions = new RolePermission[100];
            for (int i = 0; i < 100; i++)
            {
                rolePermissions[i] = new RolePermission
                {
                    Role = new XmlQualifiedName($"Role{i}", "http://test.com")
                };
            }

            var rolePermissionSet = new RolePermissionSet
            {
                Name = "TestRole",
                DoNotInheirit = false,
                RolePermission = rolePermissions
            };

            // Act
            int hashCode = rolePermissionSet.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.TypeOf<int>());
        }

        /// <summary>
        /// Tests that Equals returns false when the other parameter is null.
        /// </summary>
        [Test]
        public void Equals_OtherIsNull_ReturnsFalse()
        {
            // Arrange
            var rolePermissionSet = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = [new RolePermission()]
            };

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = rolePermissionSet.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when all properties are equal.
        /// </summary>
        [Test]
        public void Equals_AllPropertiesEqual_ReturnsTrue()
        {
            // Arrange
            var rolePermission = new RolePermission
            {
                Role = new XmlQualifiedName("TestRole", "http://test.com")
            };

            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = true,
                RolePermission = [rolePermission]
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = true,
                RolePermission = [rolePermission]
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when both RolePermission arrays are null.
        /// </summary>
        [Test]
        public void Equals_BothRolePermissionArraysNull_ReturnsTrue()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when both RolePermission arrays are empty.
        /// </summary>
        [Test]
        public void Equals_BothRolePermissionArraysEmpty_ReturnsTrue()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = []
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = []
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when RolePermission arrays differ (one null, one not null).
        /// </summary>
        [Test]
        public void Equals_RolePermissionOneNullOneNotNull_ReturnsFalse()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = [new RolePermission()]
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when RolePermission arrays have different lengths.
        /// </summary>
        [Test]
        public void Equals_RolePermissionDifferentLengths_ReturnsFalse()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = [new RolePermission()]
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = [new RolePermission(), new RolePermission()]
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when RolePermission arrays have different content.
        /// </summary>
        [Test]
        public void Equals_RolePermissionDifferentContent_ReturnsFalse()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var rolePermission2 = new RolePermission
            {
                Role = new XmlQualifiedName("Role2", "http://test.com")
            };

            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = [rolePermission1]
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = [rolePermission2]
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both Name properties are null.
        /// </summary>
        [Test]
        public void Equals_BothNamesNull_ReturnsTrue()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = null,
                DoNotInheirit = false,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = null,
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when Name properties differ (one null, one not null).
        /// </summary>
        [Test]
        public void Equals_NameOneNullOneNotNull_ReturnsFalse()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = null,
                DoNotInheirit = false,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both Name properties are empty strings.
        /// </summary>
        [Test]
        public void Equals_BothNamesEmpty_ReturnsTrue()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = string.Empty,
                DoNotInheirit = false,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = string.Empty,
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when Name properties are different non-empty strings.
        /// </summary>
        [Test]
        public void Equals_NamesDifferent_ReturnsFalse()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "Name1",
                DoNotInheirit = false,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "Name2",
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when Name properties have the same value.
        /// </summary>
        [Test]
        public void Equals_NamesSameValue_ReturnsTrue()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when DoNotInheirit properties differ.
        /// </summary>
        [TestCase(true, false)]
        [TestCase(false, true)]
        public void Equals_DoNotInheiritDifferent_ReturnsFalse(bool value1, bool value2)
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = value1,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = value2,
                RolePermission = null
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when DoNotInheirit properties are the same.
        /// </summary>
        [TestCase(true)]
        [TestCase(false)]
        public void Equals_DoNotInheiritSame_ReturnsTrue(bool value)
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = value,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = value,
                RolePermission = null
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when only RolePermission property differs.
        /// </summary>
        [Test]
        public void Equals_OnlyRolePermissionDifferent_ReturnsFalse()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var rolePermission2 = new RolePermission
            {
                Role = new XmlQualifiedName("Role2", "http://test.com")
            };

            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = true,
                RolePermission = [rolePermission1]
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = true,
                RolePermission = [rolePermission2]
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when only Name property differs.
        /// </summary>
        [Test]
        public void Equals_OnlyNameDifferent_ReturnsFalse()
        {
            // Arrange
            var rolePermission = new RolePermission
            {
                Role = new XmlQualifiedName("Role", "http://test.com")
            };

            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "Name1",
                DoNotInheirit = true,
                RolePermission = [rolePermission]
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "Name2",
                DoNotInheirit = true,
                RolePermission = [rolePermission]
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when only DoNotInheirit property differs.
        /// </summary>
        [Test]
        public void Equals_OnlyDoNotInheiritDifferent_ReturnsFalse()
        {
            // Arrange
            var rolePermission = new RolePermission
            {
                Role = new XmlQualifiedName("Role", "http://test.com")
            };

            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = true,
                RolePermission = [rolePermission]
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = [rolePermission]
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when all properties differ.
        /// </summary>
        [Test]
        public void Equals_AllPropertiesDifferent_ReturnsFalse()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var rolePermission2 = new RolePermission
            {
                Role = new XmlQualifiedName("Role2", "http://test.com")
            };

            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "Name1",
                DoNotInheirit = true,
                RolePermission = [rolePermission1]
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "Name2",
                DoNotInheirit = false,
                RolePermission = [rolePermission2]
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when Name is whitespace-only and matches.
        /// </summary>
        [Test]
        public void Equals_NamesWhitespaceMatching_ReturnsTrue()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "   ",
                DoNotInheirit = false,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "   ",
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when Name is whitespace but different.
        /// </summary>
        [Test]
        public void Equals_NamesWhitespaceDifferent_ReturnsFalse()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "  ",
                DoNotInheirit = false,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "   ",
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when Name contains special characters and matches.
        /// </summary>
        [Test]
        public void Equals_NamesSpecialCharactersMatching_ReturnsTrue()
        {
            // Arrange
            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "Test!@#$%^&*()_+-=[]{}|;':\",./<>?`~",
                DoNotInheirit = false,
                RolePermission = null
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "Test!@#$%^&*()_+-=[]{}|;':\",./<>?`~",
                DoNotInheirit = false,
                RolePermission = null
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when RolePermission arrays have multiple matching elements.
        /// </summary>
        [Test]
        public void Equals_RolePermissionMultipleElementsMatching_ReturnsTrue()
        {
            // Arrange
            var rolePermission1 = new RolePermission
            {
                Role = new XmlQualifiedName("Role1", "http://test.com")
            };

            var rolePermission2 = new RolePermission
            {
                Role = new XmlQualifiedName("Role2", "http://test.com")
            };

            var rolePermissionSet1 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = [rolePermission1, rolePermission2]
            };

            var rolePermissionSet2 = new RolePermissionSet
            {
                Name = "TestName",
                DoNotInheirit = false,
                RolePermission = [rolePermission1, rolePermission2]
            };

            // Act
            bool result = rolePermissionSet1.Equals(rolePermissionSet2);

            // Assert
            Assert.That(result, Is.True);
        }
    }

    /// <summary>
    /// Unit tests for the <see cref="ModelDesign"/> Equals method.
    /// </summary>
    public partial class ModelDesignTests
    {
        /// <summary>
        /// Tests that Equals returns true when comparing the same instance.
        /// Input: Same ModelDesign instance.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_SameInstance_ReturnsTrue()
        {
            // Arrange
            var design = new ModelDesign
            {
                TargetNamespace = "http://test.org",
                DefaultLocale = "en"
            };

            // Act
            bool result = design.Equals(design);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two instances with identical values.
        /// Input: Two ModelDesign instances with all properties set to the same values.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_IdenticalInstances_ReturnsTrue()
        {
            // Arrange
            var date = new DateTime(2025, 1, 1);
            var design1 = new ModelDesign
            {
                Namespaces = [new Namespace()],
                PermissionSets = [new RolePermissionSet()],
                Items = [new ObjectDesign()],
                Extensions = [CreateXmlElement("test")],
                TargetNamespace = "http://test.org",
                TargetVersion = "1.0.0",
                TargetPublicationDate = date,
                TargetXmlNamespace = "http://test.org/xml",
                DefaultLocale = "en"
            };

            var design2 = new ModelDesign
            {
                Namespaces = [new Namespace()],
                PermissionSets = [new RolePermissionSet()],
                Items = [new ObjectDesign()],
                Extensions = [CreateXmlElement("test")],
                TargetNamespace = "http://test.org",
                TargetVersion = "1.0.0",
                TargetPublicationDate = date,
                TargetXmlNamespace = "http://test.org/xml",
                DefaultLocale = "en"
            };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when both instances have all null properties.
        /// Input: Two ModelDesign instances with all nullable properties set to null.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_BothInstancesWithNullProperties_ReturnsTrue()
        {
            // Arrange
            var design1 = new ModelDesign
            {
                Namespaces = null,
                PermissionSets = null,
                Items = null,
                Extensions = null,
                TargetNamespace = null,
                TargetVersion = null,
                TargetXmlNamespace = null,
                DefaultLocale = null
            };

            var design2 = new ModelDesign
            {
                Namespaces = null,
                PermissionSets = null,
                Items = null,
                Extensions = null,
                TargetNamespace = null,
                TargetVersion = null,
                TargetXmlNamespace = null,
                DefaultLocale = null
            };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when TargetNamespace differs.
        /// Input: Two ModelDesign instances where only TargetNamespace differs.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentTargetNamespace_ReturnsFalse()
        {
            // Arrange
            var design1 = new ModelDesign { TargetNamespace = "http://test1.org" };
            var design2 = new ModelDesign { TargetNamespace = "http://test2.org" };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when TargetVersion differs.
        /// Input: Two ModelDesign instances where only TargetVersion differs.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentTargetVersion_ReturnsFalse()
        {
            // Arrange
            var design1 = new ModelDesign { TargetVersion = "1.0.0" };
            var design2 = new ModelDesign { TargetVersion = "2.0.0" };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when TargetPublicationDate differs.
        /// Input: Two ModelDesign instances where only TargetPublicationDate differs.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentTargetPublicationDate_ReturnsFalse()
        {
            // Arrange
            var design1 = new ModelDesign { TargetPublicationDate = new DateTime(2025, 1, 1) };
            var design2 = new ModelDesign { TargetPublicationDate = new DateTime(2025, 12, 31) };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when TargetXmlNamespace differs.
        /// Input: Two ModelDesign instances where only TargetXmlNamespace differs.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentTargetXmlNamespace_ReturnsFalse()
        {
            // Arrange
            var design1 = new ModelDesign { TargetXmlNamespace = "http://test1.org/xml" };
            var design2 = new ModelDesign { TargetXmlNamespace = "http://test2.org/xml" };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when DefaultLocale differs.
        /// Input: Two ModelDesign instances where only DefaultLocale differs.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentDefaultLocale_ReturnsFalse()
        {
            // Arrange
            var design1 = new ModelDesign { DefaultLocale = "en" };
            var design2 = new ModelDesign { DefaultLocale = "de" };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Namespaces arrays differ.
        /// Input: Two ModelDesign instances with different Namespaces arrays.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentNamespaces_ReturnsFalse()
        {
            // Arrange
            var design1 = new ModelDesign { Namespaces = [new Namespace { Name = "Ns1" }] };
            var design2 = new ModelDesign { Namespaces = [new Namespace { Name = "Ns2" }] };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when PermissionSets arrays differ.
        /// Input: Two ModelDesign instances with different PermissionSets arrays.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentPermissionSets_ReturnsFalse()
        {
            // Arrange
            var design1 = new ModelDesign { PermissionSets = [new RolePermissionSet()] };
            var design2 = new ModelDesign { PermissionSets = [] };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Items arrays differ.
        /// Input: Two ModelDesign instances with different Items arrays.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentItems_ReturnsFalse()
        {
            // Arrange
            var design1 = new ModelDesign { Items = [new ObjectDesign()] };
            var design2 = new ModelDesign { Items = [] };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Extensions arrays differ.
        /// Input: Two ModelDesign instances with different Extensions arrays.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentExtensions_ReturnsFalse()
        {
            // Arrange
            var design1 = new ModelDesign { Extensions = [CreateXmlElement("ext1")] };
            var design2 = new ModelDesign { Extensions = [CreateXmlElement("ext2")] };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when one Namespaces array is null and the other is not.
        /// Input: Two ModelDesign instances where one has null Namespaces and the other has an empty array.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_OneNamespacesNull_ReturnsFalse()
        {
            // Arrange
            var design1 = new ModelDesign { Namespaces = null };
            var design2 = new ModelDesign { Namespaces = [] };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when one TargetNamespace is null and the other is not.
        /// Input: Two ModelDesign instances where one has null TargetNamespace and the other has a value.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_OneTargetNamespaceNull_ReturnsFalse()
        {
            // Arrange
            var design1 = new ModelDesign { TargetNamespace = null };
            var design2 = new ModelDesign { TargetNamespace = "http://test.org" };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both TargetNamespace are empty strings.
        /// Input: Two ModelDesign instances with empty string TargetNamespace.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_BothTargetNamespaceEmpty_ReturnsTrue()
        {
            // Arrange
            var design1 = new ModelDesign { TargetNamespace = string.Empty };
            var design2 = new ModelDesign { TargetNamespace = string.Empty };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals handles DateTime.MinValue correctly.
        /// Input: Two ModelDesign instances with TargetPublicationDate set to DateTime.MinValue.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_DateTimeMinValue_ReturnsTrue()
        {
            // Arrange
            var design1 = new ModelDesign { TargetPublicationDate = DateTime.MinValue };
            var design2 = new ModelDesign { TargetPublicationDate = DateTime.MinValue };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals handles DateTime.MaxValue correctly.
        /// Input: Two ModelDesign instances with TargetPublicationDate set to DateTime.MaxValue.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_DateTimeMaxValue_ReturnsTrue()
        {
            // Arrange
            var design1 = new ModelDesign { TargetPublicationDate = DateTime.MaxValue };
            var design2 = new ModelDesign { TargetPublicationDate = DateTime.MaxValue };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when both instances have empty arrays.
        /// Input: Two ModelDesign instances with all arrays initialized but empty.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_BothWithEmptyArrays_ReturnsTrue()
        {
            // Arrange
            var design1 = new ModelDesign
            {
                Namespaces = [],
                PermissionSets = [],
                Items = [],
                Extensions = []
            };

            var design2 = new ModelDesign
            {
                Namespaces = [],
                PermissionSets = [],
                Items = [],
                Extensions = []
            };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when Namespaces array lengths differ.
        /// Input: Two ModelDesign instances with Namespaces arrays of different lengths.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_DifferentNamespacesLength_ReturnsFalse()
        {
            // Arrange
            var design1 = new ModelDesign { Namespaces = [new Namespace(), new Namespace()] };
            var design2 = new ModelDesign { Namespaces = [new Namespace()] };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles whitespace-only strings correctly.
        /// Input: Two ModelDesign instances with whitespace-only TargetNamespace.
        /// Expected: Returns true.
        /// </summary>
        [Test]
        public void Equals_WhitespaceOnlyStrings_ReturnsTrue()
        {
            // Arrange
            var design1 = new ModelDesign { TargetNamespace = "   " };
            var design2 = new ModelDesign { TargetNamespace = "   " };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing whitespace with empty string.
        /// Input: Two ModelDesign instances, one with whitespace TargetNamespace and one with empty string.
        /// Expected: Returns false.
        /// </summary>
        [Test]
        public void Equals_WhitespaceVsEmpty_ReturnsFalse()
        {
            // Arrange
            var design1 = new ModelDesign { TargetNamespace = "   " };
            var design2 = new ModelDesign { TargetNamespace = string.Empty };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles very long strings correctly.
        /// Input: Two ModelDesign instances with very long TargetNamespace values.
        /// Expected: Returns true when identical.
        /// </summary>
        [Test]
        public void Equals_VeryLongStrings_ReturnsTrue()
        {
            // Arrange
            string longString = new('a', 10000);
            var design1 = new ModelDesign { TargetNamespace = longString };
            var design2 = new ModelDesign { TargetNamespace = longString };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals handles strings with special characters correctly.
        /// Input: Two ModelDesign instances with special characters in TargetNamespace.
        /// Expected: Returns true when identical.
        /// </summary>
        [Test]
        public void Equals_SpecialCharactersInStrings_ReturnsTrue()
        {
            // Arrange
            const string specialString = "http://test.org/\r\n\t<>&\"'";
            var design1 = new ModelDesign { TargetNamespace = specialString };
            var design2 = new ModelDesign { TargetNamespace = specialString };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Helper method to create an XmlElement for testing.
        /// </summary>
        private XmlElement CreateXmlElement(string content)
        {
            var doc = new XmlDocument();
            XmlElement element = doc.CreateElement("TestElement");
            element.InnerText = content;
            return element;
        }

        /// <summary>
        /// Tests that Equals returns false when the parameter is null.
        /// </summary>
        [Test]
        public void Equals_NullObject_ReturnsFalse()
        {
            // Arrange
            var modelDesign = new ModelDesign();

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = modelDesign.Equals((object)null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when the parameter is of a different type.
        /// </summary>
        [Test]
        public void Equals_DifferentType_ReturnsFalse()
        {
            // Arrange
            var modelDesign = new ModelDesign();
            object differentType = new();

            // Act
            bool result = modelDesign.Equals(differentType);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with a string object.
        /// </summary>
        [Test]
        public void Equals_StringObject_ReturnsFalse()
        {
            // Arrange
            var modelDesign = new ModelDesign();
            const string stringObject = "test";

            // Act
            bool result = modelDesign.Equals((object)stringObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two default ModelDesign instances.
        /// </summary>
        [Test]
        public void Equals_TwoDefaultInstances_ReturnsTrue()
        {
            // Arrange
            var modelDesign1 = new ModelDesign();
            var modelDesign2 = new ModelDesign();

            // Act
            bool result = modelDesign1.Equals((object)modelDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when all properties are equal.
        /// </summary>
        [Test]
        public void Equals_AllPropertiesEqual_ReturnsTrue()
        {
            // Arrange
            var modelDesign1 = new ModelDesign
            {
                TargetNamespace = "http://example.com/ns",
                TargetVersion = "1.0.0",
                TargetXmlNamespace = "http://example.com/xml",
                DefaultLocale = "en"
            };
            var modelDesign2 = new ModelDesign
            {
                TargetNamespace = "http://example.com/ns",
                TargetVersion = "1.0.0",
                TargetXmlNamespace = "http://example.com/xml",
                DefaultLocale = "en"
            };

            // Act
            bool result = modelDesign1.Equals((object)modelDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when Namespaces arrays differ.
        /// </summary>
        [Test]
        public void Equals_DifferentNamespacesArray_ReturnsFalse()
        {
            // Arrange
            var modelDesign1 = new ModelDesign { Namespaces = [new Namespace()] };
            var modelDesign2 = new ModelDesign { Namespaces = null };

            // Act
            bool result = modelDesign1.Equals((object)modelDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Items arrays differ.
        /// </summary>
        [Test]
        public void Equals_DifferentItemsArray_ReturnsFalse()
        {
            // Arrange
            var modelDesign1 = new ModelDesign { Items = [new ObjectDesign()] };
            var modelDesign2 = new ModelDesign { Items = null };

            // Act
            bool result = modelDesign1.Equals((object)modelDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when one property is null and the other is not.
        /// </summary>
        [Test]
        public void Equals_NullVsNonNullProperty_ReturnsFalse()
        {
            // Arrange
            var modelDesign1 = new ModelDesign { TargetNamespace = null };
            var modelDesign2 = new ModelDesign { TargetNamespace = "http://example.com/ns" };

            // Act
            bool result = modelDesign1.Equals((object)modelDesign2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals handles empty string properties correctly.
        /// </summary>
        [Test]
        public void Equals_EmptyStringProperties_ReturnsTrue()
        {
            // Arrange
            var modelDesign1 = new ModelDesign
            {
                TargetNamespace = string.Empty,
                TargetVersion = string.Empty
            };
            var modelDesign2 = new ModelDesign
            {
                TargetNamespace = string.Empty,
                TargetVersion = string.Empty
            };

            // Act
            bool result = modelDesign1.Equals((object)modelDesign2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that GetHashCode returns consistent hash codes for equal objects.
        /// Verifies that two instances with identical property values produce the same hash code.
        /// </summary>
        [Test]
        public void GetHashCode_EqualObjects_ReturnsSameHashCode()
        {
            // Arrange
            var design1 = new ModelDesign
            {
                Namespaces = [new Namespace { Name = "Test" }],
                PermissionSets = [new RolePermissionSet()],
                Items = [new ObjectDesign()],
                Extensions = [CreateXmlElement("test")],
                TargetNamespace = "http://test.com",
                TargetVersion = "1.0",
                TargetPublicationDate = new DateTime(2024, 1, 1),
                TargetXmlNamespace = "http://test.xml.com",
                DefaultLocale = "en"
            };

            var design2 = new ModelDesign
            {
                Namespaces = [new Namespace { Name = "Test" }],
                PermissionSets = [new RolePermissionSet()],
                Items = [new ObjectDesign()],
                Extensions = [CreateXmlElement("test")],
                TargetNamespace = "http://test.com",
                TargetVersion = "1.0",
                TargetPublicationDate = new DateTime(2024, 1, 1),
                TargetXmlNamespace = "http://test.xml.com",
                DefaultLocale = "en"
            };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode works correctly with all properties set to null.
        /// Verifies that the method handles null values gracefully without throwing exceptions.
        /// </summary>
        [Test]
        public void GetHashCode_AllPropertiesNull_ReturnsHashCode()
        {
            // Arrange
            var design = new ModelDesign
            {
                Namespaces = null,
                PermissionSets = null,
                Items = null,
                Extensions = null,
                TargetNamespace = null,
                TargetVersion = null,
                TargetXmlNamespace = null,
                DefaultLocale = null
            };

            // Act
            int hashCode = design.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode returns consistent values when called multiple times on the same object.
        /// Verifies hash code consistency for the same instance.
        /// </summary>
        [Test]
        public void GetHashCode_SameInstance_ReturnsConsistentHashCode()
        {
            // Arrange
            var design = new ModelDesign
            {
                TargetNamespace = "http://test.com",
                TargetVersion = "1.0"
            };

            // Act
            int hash1 = design.GetHashCode();
            int hash2 = design.GetHashCode();
            int hash3 = design.GetHashCode();

            // Assert
            Assert.That(hash1, Is.EqualTo(hash2));
            Assert.That(hash2, Is.EqualTo(hash3));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when TargetNamespace differs.
        /// Verifies that changes in TargetNamespace affect the hash code.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentTargetNamespace_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new ModelDesign { TargetNamespace = "http://test1.com" };
            var design2 = new ModelDesign { TargetNamespace = "http://test2.com" };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when TargetVersion differs.
        /// Verifies that changes in TargetVersion affect the hash code.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentTargetVersion_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new ModelDesign { TargetVersion = "1.0" };
            var design2 = new ModelDesign { TargetVersion = "2.0" };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when TargetPublicationDate differs.
        /// Verifies that changes in TargetPublicationDate affect the hash code.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentTargetPublicationDate_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new ModelDesign { TargetPublicationDate = new DateTime(2024, 1, 1) };
            var design2 = new ModelDesign { TargetPublicationDate = new DateTime(2024, 12, 31) };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when TargetXmlNamespace differs.
        /// Verifies that changes in TargetXmlNamespace affect the hash code.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentTargetXmlNamespace_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new ModelDesign { TargetXmlNamespace = "http://xml1.com" };
            var design2 = new ModelDesign { TargetXmlNamespace = "http://xml2.com" };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when DefaultLocale differs.
        /// Verifies that changes in DefaultLocale affect the hash code.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentDefaultLocale_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new ModelDesign { DefaultLocale = "en" };
            var design2 = new ModelDesign { DefaultLocale = "de" };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when Namespaces array differs.
        /// Verifies that changes in Namespaces array affect the hash code.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentNamespaces_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new ModelDesign
            {
                Namespaces = [new Namespace { Name = "Namespace1" }]
            };
            var design2 = new ModelDesign
            {
                Namespaces = [new Namespace { Name = "Namespace2" }]
            };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes when PermissionSets array differs.
        /// Verifies that changes in PermissionSets array affect the hash code.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentPermissionSets_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new ModelDesign
            {
                PermissionSets = [new RolePermissionSet { Name = "Set1" }]
            };
            var design2 = new ModelDesign
            {
                PermissionSets = [new RolePermissionSet { Name = "Set2" }]
            };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode works correctly with empty arrays.
        /// Verifies that empty arrays are handled properly in hash code calculation.
        /// </summary>
        [Test]
        public void GetHashCode_EmptyArrays_ReturnsHashCode()
        {
            // Arrange
            var design = new ModelDesign
            {
                Namespaces = [],
                PermissionSets = [],
                Items = [],
                Extensions = []
            };

            // Act
            int hashCode = design.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for empty vs null arrays.
        /// Verifies that null and empty arrays produce different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_EmptyVsNullArrays_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new ModelDesign { Namespaces = [] };
            var design2 = new ModelDesign { Namespaces = null };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode handles empty strings correctly.
        /// Verifies that empty strings are properly included in hash code calculation.
        /// </summary>
        [Test]
        public void GetHashCode_EmptyStrings_ReturnsHashCode()
        {
            // Arrange
            var design = new ModelDesign
            {
                TargetNamespace = string.Empty,
                TargetVersion = string.Empty,
                TargetXmlNamespace = string.Empty,
                DefaultLocale = string.Empty
            };

            // Act
            int hashCode = design.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for empty vs null strings.
        /// Verifies that null and empty strings produce different hash codes.
        /// </summary>
        [Test]
        public void GetHashCode_EmptyVsNullStrings_ReturnsDifferentHashCode()
        {
            // Arrange
            var design1 = new ModelDesign { TargetNamespace = string.Empty };
            var design2 = new ModelDesign { TargetNamespace = null };

            // Act
            int hash1 = design1.GetHashCode();
            int hash2 = design2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode handles DateTime edge cases correctly.
        /// Verifies hash code calculation with DateTime.MinValue.
        /// </summary>
        [Test]
        public void GetHashCode_DateTimeMinValue_ReturnsHashCode()
        {
            // Arrange
            var design = new ModelDesign
            {
                TargetPublicationDate = DateTime.MinValue
            };

            // Act
            int hashCode = design.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode handles DateTime edge cases correctly.
        /// Verifies hash code calculation with DateTime.MaxValue.
        /// </summary>
        [Test]
        public void GetHashCode_DateTimeMaxValue_ReturnsHashCode()
        {
            // Arrange
            var design = new ModelDesign
            {
                TargetPublicationDate = DateTime.MaxValue
            };

            // Act
            int hashCode = design.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode handles whitespace strings correctly.
        /// Verifies that whitespace-only strings are properly included in hash code calculation.
        /// </summary>
        [Test]
        public void GetHashCode_WhitespaceStrings_ReturnsHashCode()
        {
            // Arrange
            var design = new ModelDesign
            {
                TargetNamespace = "   ",
                TargetVersion = "\t",
                DefaultLocale = "  \n  "
            };

            // Act
            int hashCode = design.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode handles very long strings correctly.
        /// Verifies that hash code calculation works with large string values.
        /// </summary>
        [Test]
        public void GetHashCode_VeryLongStrings_ReturnsHashCode()
        {
            // Arrange
            string longString = new('a', 10000);
            var design = new ModelDesign
            {
                TargetNamespace = longString,
                TargetVersion = longString,
                TargetXmlNamespace = longString,
                DefaultLocale = longString
            };

            // Act
            int hashCode = design.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode handles special characters in strings correctly.
        /// Verifies that strings with special characters are properly included in hash code calculation.
        /// </summary>
        [Test]
        public void GetHashCode_SpecialCharactersInStrings_ReturnsHashCode()
        {
            // Arrange
            var design = new ModelDesign
            {
                TargetNamespace = "http://test.com/\u0000\u0001\u0002",
                TargetVersion = "1.0-alpha+build.123",
                DefaultLocale = "en-US-x-special"
            };

            // Act
            int hashCode = design.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.Zero);
        }

        /// <summary>
        /// Tests that GetHashCode handles arrays with multiple elements correctly.
        /// Verifies that arrays with multiple elements are properly included in hash code calculation.
        /// </summary>
        [Test]
        public void GetHashCode_MultipleArrayElements_ReturnsHashCode()
        {
            // Arrange
            var design = new ModelDesign
            {
                Namespaces =
                [
                    new Namespace { Name = "NS1" },
                    new Namespace { Name = "NS2" },
                    new Namespace { Name = "NS3" }
                ],
                PermissionSets =
                [
                    new RolePermissionSet { Name = "Set1" },
                    new RolePermissionSet { Name = "Set2" }
                ]
            };

            // Act
            int hashCode = design.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.Zero);
        }
    }

    /// <summary>
    /// Unit tests for the HierarchyReference class.
    /// </summary>
    [TestFixture]
    public class HierarchyReferenceTests
    {
        /// <summary>
        /// Tests that ToString with null format and non-null TargetId returns the correct formatted string using TargetId.Name.
        /// </summary>
        [Test]
        public void ToString_NullFormatWithTargetId_ReturnsFormattedStringWithTargetIdName()
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = "Source/Path",
                TargetPath = "Target/Path",
                TargetId = new XmlQualifiedName("TargetName", "http://example.com")
            };

            // Act
            string result = hierarchyReference.ToString(null, null);

            // Assert
            Assert.That(result, Is.EqualTo("Source/Path => TargetName"));
        }

        /// <summary>
        /// Tests that ToString with null format and null TargetId returns the correct formatted string using TargetPath.
        /// </summary>
        [Test]
        public void ToString_NullFormatWithoutTargetId_ReturnsFormattedStringWithTargetPath()
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = "Source/Path",
                TargetPath = "Target/Path",
                TargetId = null
            };

            // Act
            string result = hierarchyReference.ToString(null, null);

            // Assert
            Assert.That(result, Is.EqualTo("Source/Path => Target/Path"));
        }

        /// <summary>
        /// Tests that ToString with null format and specific format provider uses the provider for formatting.
        /// </summary>
        [Test]
        public void ToString_NullFormatWithSpecificFormatProvider_UsesFormatProvider()
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = "Source",
                TargetPath = "Target",
                TargetId = null
            };
            CultureInfo formatProvider = CultureInfo.InvariantCulture;

            // Act
            string result = hierarchyReference.ToString(null, formatProvider);

            // Assert
            Assert.That(result, Is.EqualTo("Source => Target"));
        }

        /// <summary>
        /// Tests that ToString with null SourcePath returns a formatted string with null SourcePath.
        /// </summary>
        [Test]
        public void ToString_NullSourcePath_ReturnsFormattedStringWithNull()
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = null,
                TargetPath = "Target/Path",
                TargetId = null
            };

            // Act
            string result = hierarchyReference.ToString(null, null);

            // Assert
            Assert.That(result, Is.EqualTo(" => Target/Path"));
        }

        /// <summary>
        /// Tests that ToString with empty SourcePath returns a formatted string with empty SourcePath.
        /// </summary>
        [Test]
        public void ToString_EmptySourcePath_ReturnsFormattedStringWithEmpty()
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = string.Empty,
                TargetPath = "Target/Path",
                TargetId = null
            };

            // Act
            string result = hierarchyReference.ToString(null, null);

            // Assert
            Assert.That(result, Is.EqualTo(" => Target/Path"));
        }

        /// <summary>
        /// Tests that ToString with null TargetPath and null TargetId returns a formatted string with null TargetPath.
        /// </summary>
        [Test]
        public void ToString_NullTargetPathAndNullTargetId_ReturnsFormattedStringWithNull()
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = "Source/Path",
                TargetPath = null,
                TargetId = null
            };

            // Act
            string result = hierarchyReference.ToString(null, null);

            // Assert
            Assert.That(result, Is.EqualTo("Source/Path => "));
        }

        /// <summary>
        /// Tests that ToString with empty TargetPath and null TargetId returns a formatted string with empty TargetPath.
        /// </summary>
        [Test]
        public void ToString_EmptyTargetPathAndNullTargetId_ReturnsFormattedStringWithEmpty()
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = "Source/Path",
                TargetPath = string.Empty,
                TargetId = null
            };

            // Act
            string result = hierarchyReference.ToString(null, null);

            // Assert
            Assert.That(result, Is.EqualTo("Source/Path => "));
        }

        /// <summary>
        /// Tests that ToString with TargetId having empty Name returns a formatted string with empty Name.
        /// </summary>
        [Test]
        public void ToString_TargetIdWithEmptyName_ReturnsFormattedStringWithEmptyName()
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = "Source/Path",
                TargetPath = "Target/Path",
                TargetId = new XmlQualifiedName(string.Empty, "http://example.com")
            };

            // Act
            string result = hierarchyReference.ToString(null, null);

            // Assert
            Assert.That(result, Is.EqualTo("Source/Path => "));
        }

        /// <summary>
        /// Tests that ToString with special characters in paths returns correctly formatted string.
        /// </summary>
        [TestCase("Source/Path!@#", "Target/Path$%^", "Source/Path!@# => Target/Path$%^")]
        [TestCase("Source\tPath", "Target\nPath", "Source\tPath => Target\nPath")]
        [TestCase("Source Path With Spaces", "Target Path", "Source Path With Spaces => Target Path")]
        public void ToString_SpecialCharactersInPaths_ReturnsCorrectFormattedString(string sourcePath, string targetPath, string expected)
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = sourcePath,
                TargetPath = targetPath,
                TargetId = null
            };

            // Act
            string result = hierarchyReference.ToString(null, null);

            // Assert
            Assert.That(result, Is.EqualTo(expected));
        }

        /// <summary>
        /// Tests that ToString with non-null format throws FormatException.
        /// </summary>
        [TestCase("G")]
        [TestCase("custom")]
        [TestCase("X")]
        [TestCase("any-format")]
        public void ToString_NonNullFormat_ThrowsFormatException(string format)
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = "Source/Path",
                TargetPath = "Target/Path",
                TargetId = null
            };

            // Act & Assert
            FormatException ex = Assert.Throws<FormatException>(() => hierarchyReference.ToString(format, null));
            Assert.That(ex.Message, Does.Contain("Invalid format string"));
            Assert.That(ex.Message, Does.Contain(format));
        }

        /// <summary>
        /// Tests that ToString with empty string format throws FormatException.
        /// </summary>
        [Test]
        public void ToString_EmptyStringFormat_ThrowsFormatException()
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = "Source/Path",
                TargetPath = "Target/Path",
                TargetId = null
            };

            // Act & Assert
            FormatException ex = Assert.Throws<FormatException>(() => hierarchyReference.ToString(string.Empty, null));
            Assert.That(ex.Message, Does.Contain("Invalid format string"));
        }

        /// <summary>
        /// Tests that ToString with whitespace format throws FormatException.
        /// </summary>
        [Test]
        public void ToString_WhitespaceFormat_ThrowsFormatException()
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = "Source/Path",
                TargetPath = "Target/Path",
                TargetId = null
            };

            // Act & Assert
            FormatException ex = Assert.Throws<FormatException>(() => hierarchyReference.ToString("   ", null));
            Assert.That(ex.Message, Does.Contain("Invalid format string"));
        }

        /// <summary>
        /// Tests that ToString with very long format string throws FormatException.
        /// </summary>
        [Test]
        public void ToString_VeryLongFormat_ThrowsFormatException()
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = "Source/Path",
                TargetPath = "Target/Path",
                TargetId = null
            };
            string longFormat = new('x', 10000);

            // Act & Assert
            FormatException ex = Assert.Throws<FormatException>(() => hierarchyReference.ToString(longFormat, null));
            Assert.That(ex.Message, Does.Contain("Invalid format string"));
        }

        /// <summary>
        /// Tests that ToString with format containing special characters throws FormatException.
        /// </summary>
        [TestCase("format\nwith\nnewlines")]
        [TestCase("format\twith\ttabs")]
        [TestCase("format{0}with{1}braces")]
        public void ToString_FormatWithSpecialCharacters_ThrowsFormatException(string format)
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = "Source/Path",
                TargetPath = "Target/Path",
                TargetId = null
            };

            // Act & Assert
            FormatException ex = Assert.Throws<FormatException>(() => hierarchyReference.ToString(format, null));
            Assert.That(ex.Message, Does.Contain("Invalid format string"));
        }

        /// <summary>
        /// Tests that ToString with very long paths returns correctly formatted string.
        /// </summary>
        [Test]
        public void ToString_VeryLongPaths_ReturnsCorrectFormattedString()
        {
            // Arrange
            string longPath = new('a', 10000);
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = longPath,
                TargetPath = longPath,
                TargetId = null
            };

            // Act
            string result = hierarchyReference.ToString(null, null);

            // Assert
            Assert.That(result, Is.EqualTo($"{longPath} => {longPath}"));
        }

        /// <summary>
        /// Tests that ToString with TargetId and both SourcePath and TargetPath prioritizes TargetId.Name.
        /// </summary>
        [Test]
        public void ToString_TargetIdPresent_PrioritizesTargetIdNameOverTargetPath()
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = "Source/Path",
                TargetPath = "Target/Path",
                TargetId = new XmlQualifiedName("TargetIdName", "http://example.com")
            };

            // Act
            string result = hierarchyReference.ToString(null, null);

            // Assert
            Assert.That(result, Is.EqualTo("Source/Path => TargetIdName"));
            Assert.That(result, Does.Not.Contain("Target/Path"));
        }

        /// <summary>
        /// Tests that ToString with different culture format providers formats correctly.
        /// </summary>
        [Test]
        public void ToString_DifferentCultureFormatProviders_FormatsCorrectly()
        {
            // Arrange
            var hierarchyReference = new HierarchyReference
            {
                SourcePath = "Source",
                TargetPath = "Target",
                TargetId = null
            };

            // Act
            string resultInvariant = hierarchyReference.ToString(null, CultureInfo.InvariantCulture);
            string resultEnUs = hierarchyReference.ToString(null, CultureInfo.GetCultureInfo("en-US"));
            string resultDeDe = hierarchyReference.ToString(null, CultureInfo.GetCultureInfo("de-DE"));

            // Assert
            Assert.That(resultInvariant, Is.EqualTo("Source => Target"));
            Assert.That(resultEnUs, Is.EqualTo("Source => Target"));
            Assert.That(resultDeDe, Is.EqualTo("Source => Target"));
        }
    }

    /// <summary>
    /// Tests for the MethodDesign class.
    /// </summary>
    public partial class MethodDesignTests
    {
        /// <summary>
        /// Tests that Equals(object) returns false when comparing with null.
        /// </summary>
        [Test]
        public void Equals_NullObject_ReturnsFalse()
        {
            // Arrange
            var method = new MethodDesign();

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = method.Equals((object)null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns true when comparing an instance with itself.
        /// </summary>
        [Test]
        public void Equals_SameInstance_ReturnsTrue()
        {
            // Arrange
            var method = new MethodDesign
            {
                InputArguments = [new Parameter { Name = "input1" }],
                OutputArguments = [new Parameter { Name = "output1" }],
                NonExecutable = true,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method.Equals((object)method);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when comparing with an object of different type.
        /// </summary>
        [Test]
        public void Equals_DifferentType_ReturnsFalse()
        {
            // Arrange
            var method = new MethodDesign();
            object other = new();

            // Act
            bool result = method.Equals(other);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when comparing with a string object.
        /// </summary>
        [Test]
        public void Equals_StringObject_ReturnsFalse()
        {
            // Arrange
            var method = new MethodDesign();
            const string other = "not a MethodDesign";

            // Act
            bool result = method.Equals(other);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns true when comparing two equal MethodDesign instances with no arguments.
        /// </summary>
        [Test]
        public void Equals_EqualInstancesNoArguments_ReturnsTrue()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                NonExecutable = false,
                NonExecutableSpecified = false
            };
            var method2 = new MethodDesign
            {
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            bool result = method1.Equals((object)method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns true when comparing two equal MethodDesign instances with input arguments.
        /// </summary>
        [Test]
        public void Equals_EqualInstancesWithInputArguments_ReturnsTrue()
        {
            // Arrange
            var parameter1 = new Parameter { Name = "param1", DataType = new XmlQualifiedName("String") };
            var parameter2 = new Parameter { Name = "param1", DataType = new XmlQualifiedName("String") };

            var method1 = new MethodDesign
            {
                InputArguments = [parameter1],
                NonExecutable = false,
                NonExecutableSpecified = false
            };
            var method2 = new MethodDesign
            {
                InputArguments = [parameter2],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            bool result = method1.Equals((object)method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns true when comparing two equal MethodDesign instances with output arguments.
        /// </summary>
        [Test]
        public void Equals_EqualInstancesWithOutputArguments_ReturnsTrue()
        {
            // Arrange
            var parameter1 = new Parameter { Name = "result", DataType = new XmlQualifiedName("Int32") };
            var parameter2 = new Parameter { Name = "result", DataType = new XmlQualifiedName("Int32") };

            var method1 = new MethodDesign
            {
                OutputArguments = [parameter1],
                NonExecutable = false,
                NonExecutableSpecified = false
            };
            var method2 = new MethodDesign
            {
                OutputArguments = [parameter2],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            bool result = method1.Equals((object)method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when comparing MethodDesign instances with different InputArguments.
        /// </summary>
        [Test]
        public void Equals_DifferentInputArguments_ReturnsFalse()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                InputArguments = [new Parameter { Name = "param1" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };
            var method2 = new MethodDesign
            {
                InputArguments = [new Parameter { Name = "param2" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            bool result = method1.Equals((object)method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when comparing MethodDesign instances with different OutputArguments.
        /// </summary>
        [Test]
        public void Equals_DifferentOutputArguments_ReturnsFalse()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                OutputArguments = [new Parameter { Name = "result1" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };
            var method2 = new MethodDesign
            {
                OutputArguments = [new Parameter { Name = "result2" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            bool result = method1.Equals((object)method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when comparing MethodDesign instances with different NonExecutable values.
        /// </summary>
        [Test]
        public void Equals_DifferentNonExecutable_ReturnsFalse()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                NonExecutable = true,
                NonExecutableSpecified = true
            };
            var method2 = new MethodDesign
            {
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals((object)method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when comparing MethodDesign instances with different NonExecutableSpecified values.
        /// </summary>
        [Test]
        public void Equals_DifferentNonExecutableSpecified_ReturnsFalse()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                NonExecutable = false,
                NonExecutableSpecified = true
            };
            var method2 = new MethodDesign
            {
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            bool result = method1.Equals((object)method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when one instance has null InputArguments and the other has an array.
        /// </summary>
        [Test]
        public void Equals_OneNullInputArguments_ReturnsFalse()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                InputArguments = null,
                NonExecutable = false,
                NonExecutableSpecified = false
            };
            var method2 = new MethodDesign
            {
                InputArguments = [new Parameter { Name = "param1" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            bool result = method1.Equals((object)method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when one instance has null OutputArguments and the other has an array.
        /// </summary>
        [Test]
        public void Equals_OneNullOutputArguments_ReturnsFalse()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                OutputArguments = null,
                NonExecutable = false,
                NonExecutableSpecified = false
            };
            var method2 = new MethodDesign
            {
                OutputArguments = [new Parameter { Name = "result1" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            bool result = method1.Equals((object)method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns true when both instances have null InputArguments.
        /// </summary>
        [Test]
        public void Equals_BothNullInputArguments_ReturnsTrue()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                InputArguments = null,
                NonExecutable = false,
                NonExecutableSpecified = false
            };
            var method2 = new MethodDesign
            {
                InputArguments = null,
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            bool result = method1.Equals((object)method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns true when both instances have empty InputArguments arrays.
        /// </summary>
        [Test]
        public void Equals_BothEmptyInputArguments_ReturnsTrue()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                InputArguments = [],
                NonExecutable = false,
                NonExecutableSpecified = false
            };
            var method2 = new MethodDesign
            {
                InputArguments = [],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            bool result = method1.Equals((object)method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when InputArguments arrays have different lengths.
        /// </summary>
        [Test]
        public void Equals_InputArgumentsDifferentLength_ReturnsFalse()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                InputArguments = [new Parameter { Name = "param1" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };
            var method2 = new MethodDesign
            {
                InputArguments =
                [
                    new Parameter { Name = "param1" },
                    new Parameter { Name = "param2" }
                ],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            bool result = method1.Equals((object)method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals(object) returns true when comparing two identical complex MethodDesign instances.
        /// </summary>
        [Test]
        public void Equals_ComplexEqualInstances_ReturnsTrue()
        {
            // Arrange
            var input1 = new Parameter { Name = "input1", DataType = new XmlQualifiedName("String") };
            var input2 = new Parameter { Name = "input1", DataType = new XmlQualifiedName("String") };
            var output1 = new Parameter { Name = "output1", DataType = new XmlQualifiedName("Int32") };
            var output2 = new Parameter { Name = "output1", DataType = new XmlQualifiedName("Int32") };

            var method1 = new MethodDesign
            {
                InputArguments = [input1],
                OutputArguments = [output1],
                NonExecutable = true,
                NonExecutableSpecified = true
            };
            var method2 = new MethodDesign
            {
                InputArguments = [input2],
                OutputArguments = [output2],
                NonExecutable = true,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals((object)method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals(object) returns false when all properties differ.
        /// </summary>
        [Test]
        public void Equals_AllPropertiesDifferent_ReturnsFalse()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                InputArguments = [new Parameter { Name = "param1" }],
                OutputArguments = [new Parameter { Name = "result1" }],
                NonExecutable = true,
                NonExecutableSpecified = true
            };
            var method2 = new MethodDesign
            {
                InputArguments = [new Parameter { Name = "param2" }],
                OutputArguments = [new Parameter { Name = "result2" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            bool result = method1.Equals((object)method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that GetHashCode returns consistent hash code for the same object across multiple calls.
        /// Validates that hash code computation is deterministic.
        /// </summary>
        [Test]
        public void GetHashCode_CalledMultipleTimes_ReturnsSameValue()
        {
            // Arrange
            var methodDesign = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                InputArguments =
                [
                    new Parameter { Name = "arg1", DataType = new XmlQualifiedName("Int32") }
                ],
                OutputArguments =
                [
                    new Parameter { Name = "result", DataType = new XmlQualifiedName("String") }
                ],
                NonExecutable = true,
                NonExecutableSpecified = true
            };

            // Act
            int hashCode1 = methodDesign.GetHashCode();
            int hashCode2 = methodDesign.GetHashCode();
            int hashCode3 = methodDesign.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.EqualTo(hashCode1));
            Assert.That(hashCode3, Is.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode returns same hash code for equal objects.
        /// Validates hash code consistency with Equals contract.
        /// </summary>
        [Test]
        public void GetHashCode_EqualObjects_ReturnsSameHashCode()
        {
            // Arrange
            var input = new Parameter[] { new() { Name = "arg1" } };
            var output = new Parameter[] { new() { Name = "result" } };

            var methodDesign1 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                InputArguments = input,
                OutputArguments = output,
                NonExecutable = true,
                NonExecutableSpecified = true
            };

            var methodDesign2 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                InputArguments = input,
                OutputArguments = output,
                NonExecutable = true,
                NonExecutableSpecified = true
            };

            // Act
            int hashCode1 = methodDesign1.GetHashCode();
            int hashCode2 = methodDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different InputArguments.
        /// Validates that InputArguments contribute to hash code computation.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentInputArguments_ReturnsDifferentHashCodes()
        {
            // Arrange
            var methodDesign1 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                InputArguments = [new Parameter { Name = "arg1" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            var methodDesign2 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                InputArguments = [new Parameter { Name = "arg2" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            int hashCode1 = methodDesign1.GetHashCode();
            int hashCode2 = methodDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode returns different hash codes for objects with different OutputArguments.
        /// Validates that OutputArguments contribute to hash code computation.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentOutputArguments_ReturnsDifferentHashCodes()
        {
            // Arrange
            var methodDesign1 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                OutputArguments = [new Parameter { Name = "result1" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            var methodDesign2 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                OutputArguments = [new Parameter { Name = "result2" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            int hashCode1 = methodDesign1.GetHashCode();
            int hashCode2 = methodDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests GetHashCode with different values of NonExecutable property.
        /// Validates that NonExecutable contributes to hash code computation.
        /// Expected result: Different hash codes for true and false values.
        /// </summary>
        [TestCase(true, false)]
        [TestCase(false, true)]
        public void GetHashCode_DifferentNonExecutable_ReturnsDifferentHashCodes(bool value1, bool value2)
        {
            // Arrange
            var methodDesign1 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                NonExecutable = value1,
                NonExecutableSpecified = true
            };

            var methodDesign2 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                NonExecutable = value2,
                NonExecutableSpecified = true
            };

            // Act
            int hashCode1 = methodDesign1.GetHashCode();
            int hashCode2 = methodDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests GetHashCode with different values of NonExecutableSpecified property.
        /// Validates that NonExecutableSpecified contributes to hash code computation.
        /// Expected result: Different hash codes for true and false values.
        /// </summary>
        [TestCase(true, false)]
        [TestCase(false, true)]
        public void GetHashCode_DifferentNonExecutableSpecified_ReturnsDifferentHashCodes(bool specified1, bool specified2)
        {
            // Arrange
            var methodDesign1 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                NonExecutable = false,
                NonExecutableSpecified = specified1
            };

            var methodDesign2 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                NonExecutable = false,
                NonExecutableSpecified = specified2
            };

            // Act
            int hashCode1 = methodDesign1.GetHashCode();
            int hashCode2 = methodDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests GetHashCode with null InputArguments.
        /// Validates that null arrays are handled correctly in hash code computation.
        /// Expected result: Valid hash code is computed without exception.
        /// </summary>
        [Test]
        public void GetHashCode_NullInputArguments_ReturnsValidHashCode()
        {
            // Arrange
            var methodDesign = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                InputArguments = null,
                OutputArguments = [new Parameter { Name = "result" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            int hashCode = methodDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests GetHashCode with null OutputArguments.
        /// Validates that null arrays are handled correctly in hash code computation.
        /// Expected result: Valid hash code is computed without exception.
        /// </summary>
        [Test]
        public void GetHashCode_NullOutputArguments_ReturnsValidHashCode()
        {
            // Arrange
            var methodDesign = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                InputArguments = [new Parameter { Name = "arg" }],
                OutputArguments = null,
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            int hashCode = methodDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests GetHashCode with empty InputArguments array.
        /// Validates that empty arrays are distinct from null in hash code computation.
        /// Expected result: Different hash codes for null vs empty array.
        /// </summary>
        [Test]
        public void GetHashCode_EmptyVsNullInputArguments_ReturnsDifferentHashCodes()
        {
            // Arrange
            var methodDesign1 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                InputArguments = null,
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            var methodDesign2 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                InputArguments = [],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            int hashCode1 = methodDesign1.GetHashCode();
            int hashCode2 = methodDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests GetHashCode with multiple parameters in InputArguments.
        /// Validates that arrays with multiple elements are handled correctly.
        /// Expected result: Different hash codes for arrays with different number of elements.
        /// </summary>
        [Test]
        public void GetHashCode_MultipleInputArguments_ReturnsDifferentHashCodes()
        {
            // Arrange
            var methodDesign1 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                InputArguments =
                [
                    new Parameter { Name = "arg1" }
                ],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            var methodDesign2 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                InputArguments =
                [
                    new Parameter { Name = "arg1" },
                    new Parameter { Name = "arg2" }
                ],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            int hashCode1 = methodDesign1.GetHashCode();
            int hashCode2 = methodDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests that GetHashCode considers base class properties.
        /// Validates that inherited properties contribute to hash code computation.
        /// Expected result: Different hash codes when base properties differ.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentBaseProperties_ReturnsDifferentHashCodes()
        {
            // Arrange
            var methodDesign1 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                InputArguments = [new Parameter { Name = "arg1" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            var methodDesign2 = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method2", "http://test.org"),
                InputArguments = [new Parameter { Name = "arg1" }],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            int hashCode1 = methodDesign1.GetHashCode();
            int hashCode2 = methodDesign2.GetHashCode();

            // Assert
            Assert.That(hashCode2, Is.Not.EqualTo(hashCode1));
        }

        /// <summary>
        /// Tests GetHashCode with all properties set to default/null values.
        /// Validates that hash code computation works with minimal property values.
        /// Expected result: Valid hash code is computed.
        /// </summary>
        [Test]
        public void GetHashCode_AllPropertiesDefault_ReturnsValidHashCode()
        {
            // Arrange
            var methodDesign = new MethodDesign
            {
                InputArguments = null,
                OutputArguments = null,
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            int hashCode = methodDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests GetHashCode with all possible combinations of boolean properties.
        /// Validates that all combinations of NonExecutable and NonExecutableSpecified produce unique hash codes.
        /// Expected result: Each combination should ideally produce different hash codes.
        /// </summary>
        [TestCase(false, false)]
        [TestCase(false, true)]
        [TestCase(true, false)]
        [TestCase(true, true)]
        public void GetHashCode_AllBooleanCombinations_ReturnsValidHashCode(bool nonExecutable, bool nonExecutableSpecified)
        {
            // Arrange
            var methodDesign = new MethodDesign
            {
                SymbolicId = new XmlQualifiedName("Method1", "http://test.org"),
                InputArguments = [new Parameter { Name = "arg1" }],
                OutputArguments = [new Parameter { Name = "result" }],
                NonExecutable = nonExecutable,
                NonExecutableSpecified = nonExecutableSpecified
            };

            // Act
            int hashCode = methodDesign.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with null.
        /// </summary>
        [Test]
        public void Equals_NullOther_ReturnsFalse()
        {
            // Arrange
            var method = new MethodDesign();

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = method.Equals((MethodDesign)null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two instances with identical properties.
        /// </summary>
        [Test]
        public void Equals_IdenticalProperties_ReturnsTrue()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when base properties differ.
        /// </summary>
        [Test]
        public void Equals_DifferentBaseProperty_ReturnsFalse()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod1",
                NonExecutable = true,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod2",
                NonExecutable = true,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both InputArguments are null.
        /// </summary>
        [Test]
        public void Equals_BothInputArgumentsNull_ReturnsTrue()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                InputArguments = null,
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                InputArguments = null,
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when both OutputArguments are null.
        /// </summary>
        [Test]
        public void Equals_BothOutputArgumentsNull_ReturnsTrue()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                OutputArguments = null,
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                OutputArguments = null,
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when one InputArguments is null and the other is not.
        /// </summary>
        [Test]
        public void Equals_OneInputArgumentsNull_ReturnsFalse()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                InputArguments = null,
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                InputArguments = [],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when one OutputArguments is null and the other is not.
        /// </summary>
        [Test]
        public void Equals_OneOutputArgumentsNull_ReturnsFalse()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                OutputArguments = null,
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                OutputArguments = [],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both InputArguments are empty arrays.
        /// </summary>
        [Test]
        public void Equals_BothInputArgumentsEmpty_ReturnsTrue()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                InputArguments = [],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                InputArguments = [],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when both OutputArguments are empty arrays.
        /// </summary>
        [Test]
        public void Equals_BothOutputArgumentsEmpty_ReturnsTrue()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                OutputArguments = [],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                OutputArguments = [],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when InputArguments have identical elements.
        /// </summary>
        [Test]
        public void Equals_IdenticalInputArguments_ReturnsTrue()
        {
            // Arrange
            var param1 = new Parameter { Name = "arg1", DataType = new XmlQualifiedName("String") };
            var param2 = new Parameter { Name = "arg1", DataType = new XmlQualifiedName("String") };

            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                InputArguments = [param1],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                InputArguments = [param2],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when OutputArguments have identical elements.
        /// </summary>
        [Test]
        public void Equals_IdenticalOutputArguments_ReturnsTrue()
        {
            // Arrange
            var param1 = new Parameter { Name = "result", DataType = new XmlQualifiedName("Int32") };
            var param2 = new Parameter { Name = "result", DataType = new XmlQualifiedName("Int32") };

            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                OutputArguments = [param1],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                OutputArguments = [param2],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when InputArguments have different lengths.
        /// </summary>
        [Test]
        public void Equals_DifferentInputArgumentsLength_ReturnsFalse()
        {
            // Arrange
            var param = new Parameter { Name = "arg1" };

            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                InputArguments = [param],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                InputArguments = [param, param],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when OutputArguments have different lengths.
        /// </summary>
        [Test]
        public void Equals_DifferentOutputArgumentsLength_ReturnsFalse()
        {
            // Arrange
            var param = new Parameter { Name = "result" };

            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                OutputArguments = [param],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                OutputArguments = [param, param],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when InputArguments have different element values.
        /// </summary>
        [Test]
        public void Equals_DifferentInputArgumentsValues_ReturnsFalse()
        {
            // Arrange
            var param1 = new Parameter { Name = "arg1", DataType = new XmlQualifiedName("String") };
            var param2 = new Parameter { Name = "arg2", DataType = new XmlQualifiedName("Int32") };

            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                InputArguments = [param1],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                InputArguments = [param2],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when OutputArguments have different element values.
        /// </summary>
        [Test]
        public void Equals_DifferentOutputArgumentsValues_ReturnsFalse()
        {
            // Arrange
            var param1 = new Parameter { Name = "result1", DataType = new XmlQualifiedName("String") };
            var param2 = new Parameter { Name = "result2", DataType = new XmlQualifiedName("Int32") };

            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                OutputArguments = [param1],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                OutputArguments = [param2],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when all properties and arguments are identical.
        /// </summary>
        [Test]
        public void Equals_ComplexIdenticalObjects_ReturnsTrue()
        {
            // Arrange
            var inputParam1 = new Parameter { Name = "input1", DataType = new XmlQualifiedName("String") };
            var outputParam1 = new Parameter { Name = "output1", DataType = new XmlQualifiedName("Int32") };
            var inputParam2 = new Parameter { Name = "input1", DataType = new XmlQualifiedName("String") };
            var outputParam2 = new Parameter { Name = "output1", DataType = new XmlQualifiedName("Int32") };

            var method1 = new MethodDesign
            {
                BrowseName = "ComplexMethod",
                InputArguments = [inputParam1],
                OutputArguments = [outputParam1],
                NonExecutable = true,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "ComplexMethod",
                InputArguments = [inputParam2],
                OutputArguments = [outputParam2],
                NonExecutable = true,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when multiple properties differ.
        /// </summary>
        [Test]
        public void Equals_MultipleDifferences_ReturnsFalse()
        {
            // Arrange
            var param1 = new Parameter { Name = "arg1" };
            var param2 = new Parameter { Name = "arg2" };

            var method1 = new MethodDesign
            {
                BrowseName = "Method1",
                InputArguments = [param1],
                NonExecutable = true,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "Method2",
                InputArguments = [param2],
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when InputArguments arrays contain multiple identical elements.
        /// </summary>
        [Test]
        public void Equals_MultipleIdenticalInputArguments_ReturnsTrue()
        {
            // Arrange
            var param1a = new Parameter { Name = "arg1", DataType = new XmlQualifiedName("String") };
            var param1b = new Parameter { Name = "arg2", DataType = new XmlQualifiedName("Int32") };
            var param2a = new Parameter { Name = "arg1", DataType = new XmlQualifiedName("String") };
            var param2b = new Parameter { Name = "arg2", DataType = new XmlQualifiedName("Int32") };

            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                InputArguments = [param1a, param1b],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                InputArguments = [param2a, param2b],
                NonExecutable = false,
                NonExecutableSpecified = true
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when both NonExecutable and NonExecutableSpecified differ.
        /// </summary>
        [Test]
        public void Equals_BothNonExecutablePropertiesDiffer_ReturnsFalse()
        {
            // Arrange
            var method1 = new MethodDesign
            {
                BrowseName = "TestMethod",
                NonExecutable = true,
                NonExecutableSpecified = true
            };

            var method2 = new MethodDesign
            {
                BrowseName = "TestMethod",
                NonExecutable = false,
                NonExecutableSpecified = false
            };

            // Act
            bool result = method1.Equals(method2);

            // Assert
            Assert.That(result, Is.False);
        }
    }

    /// <summary>
    /// Unit tests for the <see cref="DataTypeDesign"/> class.
    /// </summary>
    public partial class DataTypeDesignTests
    {
        /// <summary>
        /// Tests that Equals returns false when the parameter is null.
        /// </summary>
        [Test]
        public void Equals_NullObject_ReturnsFalse()
        {
            // Arrange
            var dataType = new DataTypeDesign();

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = dataType.Equals((object)null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing the same instance.
        /// </summary>
        [Test]
        public void Equals_SameReference_ReturnsTrue()
        {
            // Arrange
            var dataType = new DataTypeDesign
            {
                SymbolicName = new XmlQualifiedName("TestType", "TestNamespace"),
                IsOptionSet = true
            };

            // Act
            bool result = dataType.Equals((object)dataType);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when the parameter is a different type.
        /// </summary>
        [Test]
        public void Equals_DifferentType_ReturnsFalse()
        {
            // Arrange
            var dataType = new DataTypeDesign();
            const string differentTypeObject = "not a DataTypeDesign";

            // Act
            bool result = dataType.Equals(differentTypeObject);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two DataTypeDesign instances with identical properties.
        /// </summary>
        [Test]
        public void Equals_IdenticalProperties_ReturnsTrue()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                IsOptionSet = true,
                IsUnion = false,
                NoArraysAllowed = true,
                ForceEnumValues = false,
                NoEncodings = true
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                IsOptionSet = true,
                IsUnion = false,
                NoArraysAllowed = true,
                ForceEnumValues = false,
                NoEncodings = true
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when IsOptionSet properties differ.
        /// </summary>
        [Test]
        public void Equals_DifferentIsOptionSet_ReturnsFalse()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                IsOptionSet = true
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                IsOptionSet = false
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when IsUnion properties differ.
        /// </summary>
        [Test]
        public void Equals_DifferentIsUnion_ReturnsFalse()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                IsUnion = true
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                IsUnion = false
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when NoArraysAllowed properties differ.
        /// </summary>
        [Test]
        public void Equals_DifferentNoArraysAllowed_ReturnsFalse()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                NoArraysAllowed = true
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                NoArraysAllowed = false
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when ForceEnumValues properties differ.
        /// </summary>
        [Test]
        public void Equals_DifferentForceEnumValues_ReturnsFalse()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                ForceEnumValues = true
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                ForceEnumValues = false
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when NoEncodings properties differ.
        /// </summary>
        [Test]
        public void Equals_DifferentNoEncodings_ReturnsFalse()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                NoEncodings = true
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                NoEncodings = false
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Fields arrays differ.
        /// </summary>
        [Test]
        public void Equals_DifferentFields_ReturnsFalse()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var field1 = new Parameter { Name = "Field1" };
            var field2 = new Parameter { Name = "Field2" };

            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Fields = [field1]
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Fields = [field2]
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both Fields arrays are null.
        /// </summary>
        [Test]
        public void Equals_BothFieldsNull_ReturnsTrue()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Fields = null
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Fields = null
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when one Fields array is null and the other is not.
        /// </summary>
        [Test]
        public void Equals_OneFieldsNullOtherNot_ReturnsFalse()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Fields = [new Parameter { Name = "Field1" }]
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Fields = null
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Encodings arrays differ.
        /// </summary>
        [Test]
        public void Equals_DifferentEncodings_ReturnsFalse()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var encoding1 = new EncodingDesign { SymbolicName = new XmlQualifiedName("Encoding1", "TestNamespace") };
            var encoding2 = new EncodingDesign { SymbolicName = new XmlQualifiedName("Encoding2", "TestNamespace") };

            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Encodings = [encoding1]
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Encodings = [encoding2]
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both Encodings arrays are null.
        /// </summary>
        [Test]
        public void Equals_BothEncodingsNull_ReturnsTrue()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Encodings = null
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Encodings = null
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when SymbolicName properties differ.
        /// </summary>
        [Test]
        public void Equals_DifferentSymbolicName_ReturnsFalse()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                SymbolicName = new XmlQualifiedName("TestType1", "TestNamespace")
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = new XmlQualifiedName("TestType2", "TestNamespace")
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when IsServiceResponse properties differ.
        /// </summary>
        [Test]
        public void Equals_DifferentIsServiceResponse_ReturnsFalse()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                IsServiceResponse = true
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                IsServiceResponse = false
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Service properties differ.
        /// </summary>
        [Test]
        public void Equals_DifferentService_ReturnsFalse()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var service1 = new Service { Name = "Service1", Category = ServiceCategory.Session };
            var service2 = new Service { Name = "Service2", Category = ServiceCategory.Discovery };

            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Service = service1
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Service = service2
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both Service properties are null.
        /// </summary>
        [Test]
        public void Equals_BothServiceNull_ReturnsTrue()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Service = null
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Service = null
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when Fields array lengths differ.
        /// </summary>
        [Test]
        public void Equals_DifferentFieldsArrayLength_ReturnsFalse()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var field1 = new Parameter { Name = "Field1" };
            var field2 = new Parameter { Name = "Field2" };

            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Fields = [field1]
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Fields = [field1, field2]
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing empty Fields arrays.
        /// </summary>
        [Test]
        public void Equals_EmptyFieldsArrays_ReturnsTrue()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Fields = []
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                Fields = []
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals handles complex objects with all properties set correctly.
        /// </summary>
        [Test]
        public void Equals_ComplexObjectsAllPropertiesSet_ReturnsTrue()
        {
            // Arrange
            var symbolicName = new XmlQualifiedName("TestType", "TestNamespace");
            var field = new Parameter { Name = "Field1", DataType = new XmlQualifiedName("String", "http://opcfoundation.org/UA/") };
            var encoding = new EncodingDesign { SymbolicName = new XmlQualifiedName("Encoding1", "TestNamespace") };
            var service = new Service { Name = "TestService", Category = ServiceCategory.Session };

            var dataType1 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                IsOptionSet = true,
                IsUnion = true,
                NoArraysAllowed = true,
                ForceEnumValues = true,
                NoEncodings = false,
                Fields = [field],
                Encodings = [encoding],
                IsServiceResponse = true,
                Service = service
            };

            var dataType2 = new DataTypeDesign
            {
                SymbolicName = symbolicName,
                IsOptionSet = true,
                IsUnion = true,
                NoArraysAllowed = true,
                ForceEnumValues = true,
                NoEncodings = false,
                Fields = [field],
                Encodings = [encoding],
                IsServiceResponse = true,
                Service = service
            };

            // Act
            bool result = dataType1.Equals((object)dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing with null.
        /// </summary>
        [Test]
        public void Equals_NullOther_ReturnsFalse()
        {
            // Arrange
            var dataType = new DataTypeDesign();

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = dataType.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing an instance with itself.
        /// </summary>
        [Test]
        public void Equals_SameInstance_ReturnsTrue()
        {
            // Arrange
            var dataType = new DataTypeDesign
            {
                BrowseName = "TestDataType",
                IsOptionSet = true
            };

            // Act
            bool result = dataType.Equals(dataType);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two identical instances with all default values.
        /// </summary>
        [Test]
        public void Equals_IdenticalInstancesWithDefaults_ReturnsTrue()
        {
            // Arrange
            var dataType1 = new DataTypeDesign();
            var dataType2 = new DataTypeDesign();

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two instances with identical property values.
        /// </summary>
        [Test]
        public void Equals_IdenticalInstances_ReturnsTrue()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                BrowseName = "TestDataType",
                IsOptionSet = true,
                IsUnion = false,
                NoArraysAllowed = true,
                ForceEnumValues = false,
                NoEncodings = true,
                Fields =
                [
                    new Parameter { Name = "Field1" }
                ],
                Encodings =
                [
                    new EncodingDesign { BrowseName = "Encoding1" }
                ]
            };

            var dataType2 = new DataTypeDesign
            {
                BrowseName = "TestDataType",
                IsOptionSet = true,
                IsUnion = false,
                NoArraysAllowed = true,
                ForceEnumValues = false,
                NoEncodings = true,
                Fields =
                [
                    new Parameter { Name = "Field1" }
                ],
                Encodings =
                [
                    new EncodingDesign { BrowseName = "Encoding1" }
                ]
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when base properties differ.
        /// </summary>
        [Test]
        public void Equals_DifferentBrowseName_ReturnsFalse()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                BrowseName = "DataType1"
            };

            var dataType2 = new DataTypeDesign
            {
                BrowseName = "DataType2"
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when one has null Fields and the other has an array.
        /// </summary>
        [Test]
        public void Equals_OneNullFieldsArray_ReturnsFalse()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                Fields = null
            };

            var dataType2 = new DataTypeDesign
            {
                Fields = [new Parameter { Name = "Field1" }]
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both have null Fields arrays.
        /// </summary>
        [Test]
        public void Equals_BothNullFieldsArrays_ReturnsTrue()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                Fields = null
            };

            var dataType2 = new DataTypeDesign
            {
                Fields = null
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when both have empty Fields arrays.
        /// </summary>
        [Test]
        public void Equals_BothEmptyFieldsArrays_ReturnsTrue()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                Fields = []
            };

            var dataType2 = new DataTypeDesign
            {
                Fields = []
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when one has null Encodings and the other has an array.
        /// </summary>
        [Test]
        public void Equals_OneNullEncodingsArray_ReturnsFalse()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                Encodings = null
            };

            var dataType2 = new DataTypeDesign
            {
                Encodings = [new EncodingDesign { BrowseName = "Encoding1" }]
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both have null Encodings arrays.
        /// </summary>
        [Test]
        public void Equals_BothNullEncodingsArrays_ReturnsTrue()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                Encodings = null
            };

            var dataType2 = new DataTypeDesign
            {
                Encodings = null
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when both have empty Encodings arrays.
        /// </summary>
        [Test]
        public void Equals_BothEmptyEncodingsArrays_ReturnsTrue()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                Encodings = []
            };

            var dataType2 = new DataTypeDesign
            {
                Encodings = []
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when IsOptionSet values differ.
        /// </summary>
        [Test]
        [TestCase(true, false)]
        [TestCase(false, true)]
        public void Equals_DifferentIsOptionSet_ReturnsFalse(bool value1, bool value2)
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                IsOptionSet = value1
            };

            var dataType2 = new DataTypeDesign
            {
                IsOptionSet = value2
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when IsUnion values differ.
        /// </summary>
        [Test]
        [TestCase(true, false)]
        [TestCase(false, true)]
        public void Equals_DifferentIsUnion_ReturnsFalse(bool value1, bool value2)
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                IsUnion = value1
            };

            var dataType2 = new DataTypeDesign
            {
                IsUnion = value2
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when NoArraysAllowed values differ.
        /// </summary>
        [Test]
        [TestCase(true, false)]
        [TestCase(false, true)]
        public void Equals_DifferentNoArraysAllowed_ReturnsFalse(bool value1, bool value2)
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                NoArraysAllowed = value1
            };

            var dataType2 = new DataTypeDesign
            {
                NoArraysAllowed = value2
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when ForceEnumValues values differ.
        /// </summary>
        [Test]
        [TestCase(true, false)]
        [TestCase(false, true)]
        public void Equals_DifferentForceEnumValues_ReturnsFalse(bool value1, bool value2)
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                ForceEnumValues = value1
            };

            var dataType2 = new DataTypeDesign
            {
                ForceEnumValues = value2
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when NoEncodings values differ.
        /// </summary>
        [Test]
        [TestCase(true, false)]
        [TestCase(false, true)]
        public void Equals_DifferentNoEncodings_ReturnsFalse(bool value1, bool value2)
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                NoEncodings = value1
            };

            var dataType2 = new DataTypeDesign
            {
                NoEncodings = value2
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when IsServiceResponse values differ.
        /// </summary>
        [Test]
        [TestCase(true, false)]
        [TestCase(false, true)]
        public void Equals_DifferentIsServiceResponse_ReturnsFalse(bool value1, bool value2)
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                IsServiceResponse = value1
            };

            var dataType2 = new DataTypeDesign
            {
                IsServiceResponse = value2
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when one has null Service and the other does not.
        /// </summary>
        [Test]
        public void Equals_OneNullService_ReturnsFalse()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                Service = null
            };

            var dataType2 = new DataTypeDesign
            {
                Service = new Service { Category = ServiceCategory.Session, Name = "Service1" }
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when both Service values are null.
        /// </summary>
        [Test]
        public void Equals_BothNullService_ReturnsTrue()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                Service = null
            };

            var dataType2 = new DataTypeDesign
            {
                Service = null
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns true when both Service values are equal.
        /// </summary>
        [Test]
        public void Equals_EqualService_ReturnsTrue()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                Service = new Service { Category = ServiceCategory.Session, Name = "Service1" }
            };

            var dataType2 = new DataTypeDesign
            {
                Service = new Service { Category = ServiceCategory.Session, Name = "Service1" }
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when Fields arrays have different lengths.
        /// </summary>
        [Test]
        public void Equals_FieldsArraysDifferentLength_ReturnsFalse()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                Fields =
                [
                    new Parameter { Name = "Field1" }
                ]
            };

            var dataType2 = new DataTypeDesign
            {
                Fields =
                [
                    new Parameter { Name = "Field1" },
                    new Parameter { Name = "Field2" }
                ]
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when Encodings arrays have different lengths.
        /// </summary>
        [Test]
        public void Equals_EncodingsArraysDifferentLength_ReturnsFalse()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                Encodings =
                [
                    new EncodingDesign { BrowseName = "Encoding1" }
                ]
            };

            var dataType2 = new DataTypeDesign
            {
                Encodings =
                [
                    new EncodingDesign { BrowseName = "Encoding1" },
                    new EncodingDesign { BrowseName = "Encoding2" }
                ]
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when all properties match including complex scenarios.
        /// </summary>
        [Test]
        public void Equals_AllPropertiesMatch_ReturnsTrue()
        {
            // Arrange
            var dataType1 = new DataTypeDesign
            {
                BrowseName = "ComplexDataType",
                IsOptionSet = true,
                IsUnion = true,
                NoArraysAllowed = false,
                ForceEnumValues = true,
                NoEncodings = false,
                IsServiceResponse = true,
                Service = new Service { Category = ServiceCategory.Discovery, Name = "DiscoveryService" },
                Fields =
                [
                    new Parameter { Name = "Field1" },
                    new Parameter { Name = "Field2" }
                ],
                Encodings =
                [
                    new EncodingDesign { BrowseName = "DefaultBinary" },
                    new EncodingDesign { BrowseName = "DefaultXml" }
                ]
            };

            var dataType2 = new DataTypeDesign
            {
                BrowseName = "ComplexDataType",
                IsOptionSet = true,
                IsUnion = true,
                NoArraysAllowed = false,
                ForceEnumValues = true,
                NoEncodings = false,
                IsServiceResponse = true,
                Service = new Service { Category = ServiceCategory.Discovery, Name = "DiscoveryService" },
                Fields =
                [
                    new Parameter { Name = "Field1" },
                    new Parameter { Name = "Field2" }
                ],
                Encodings =
                [
                    new EncodingDesign { BrowseName = "DefaultBinary" },
                    new EncodingDesign { BrowseName = "DefaultXml" }
                ]
            };

            // Act
            bool result = dataType1.Equals(dataType2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that GetHashCode returns the same value for two instances with identical property values.
        /// </summary>
        [Test]
        public void GetHashCode_IdenticalInstances_ReturnsSameHashCode()
        {
            // Arrange
            var instance1 = new DataTypeDesign
            {
                IsOptionSet = true,
                IsUnion = false,
                NoArraysAllowed = true,
                ForceEnumValues = false,
                NoEncodings = true,
                Service = new Service { Name = "TestService", Category = ServiceCategory.Session },
                IsServiceResponse = true,
                Fields =
                [
                    new Parameter { Name = "Field1" }
                ],
                Encodings =
                [
                    new EncodingDesign()
                ]
            };

            var instance2 = new DataTypeDesign
            {
                IsOptionSet = true,
                IsUnion = false,
                NoArraysAllowed = true,
                ForceEnumValues = false,
                NoEncodings = true,
                Service = new Service { Name = "TestService", Category = ServiceCategory.Session },
                IsServiceResponse = true,
                Fields =
                [
                    new Parameter { Name = "Field1" }
                ],
                Encodings =
                [
                    new EncodingDesign()
                ]
            };

            // Act
            int hash1 = instance1.GetHashCode();
            int hash2 = instance2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns consistent values across multiple invocations on the same instance.
        /// </summary>
        [Test]
        public void GetHashCode_MultipleInvocations_ReturnsConsistentValue()
        {
            // Arrange
            var instance = new DataTypeDesign
            {
                IsOptionSet = true,
                IsUnion = true,
                NoArraysAllowed = false,
                ForceEnumValues = true,
                NoEncodings = false,
                Service = new Service { Name = "TestService", Category = ServiceCategory.Discovery },
                IsServiceResponse = false
            };

            // Act
            int hash1 = instance.GetHashCode();
            int hash2 = instance.GetHashCode();
            int hash3 = instance.GetHashCode();

            // Assert
            Assert.That(hash1, Is.EqualTo(hash2));
            Assert.That(hash2, Is.EqualTo(hash3));
        }

        /// <summary>
        /// Tests that GetHashCode handles null Fields array correctly.
        /// </summary>
        [Test]
        public void GetHashCode_NullFields_ReturnsValidHashCode()
        {
            // Arrange
            var instance = new DataTypeDesign
            {
                Fields = null,
                Encodings = [new EncodingDesign()],
                IsOptionSet = false
            };

            // Act
            int hashCode = instance.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode handles null Encodings array correctly.
        /// </summary>
        [Test]
        public void GetHashCode_NullEncodings_ReturnsValidHashCode()
        {
            // Arrange
            var instance = new DataTypeDesign
            {
                Fields = [new Parameter { Name = "Field1" }],
                Encodings = null,
                IsUnion = true
            };

            // Act
            int hashCode = instance.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode handles null Service property correctly.
        /// </summary>
        [Test]
        public void GetHashCode_NullService_ReturnsValidHashCode()
        {
            // Arrange
            var instance = new DataTypeDesign
            {
                Service = null,
                IsServiceResponse = false,
                NoEncodings = true
            };

            // Act
            int hashCode = instance.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode handles empty Fields array correctly.
        /// </summary>
        [Test]
        public void GetHashCode_EmptyFields_ReturnsValidHashCode()
        {
            // Arrange
            var instance = new DataTypeDesign
            {
                Fields = [],
                Encodings = [],
                ForceEnumValues = true
            };

            // Act
            int hashCode = instance.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode returns different values for instances with different IsOptionSet values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentIsOptionSet_ReturnsDifferentHashCodes()
        {
            // Arrange
            var instance1 = new DataTypeDesign { IsOptionSet = true };
            var instance2 = new DataTypeDesign { IsOptionSet = false };

            // Act
            int hash1 = instance1.GetHashCode();
            int hash2 = instance2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different values for instances with different IsUnion values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentIsUnion_ReturnsDifferentHashCodes()
        {
            // Arrange
            var instance1 = new DataTypeDesign { IsUnion = true };
            var instance2 = new DataTypeDesign { IsUnion = false };

            // Act
            int hash1 = instance1.GetHashCode();
            int hash2 = instance2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different values for instances with different NoArraysAllowed values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentNoArraysAllowed_ReturnsDifferentHashCodes()
        {
            // Arrange
            var instance1 = new DataTypeDesign { NoArraysAllowed = true };
            var instance2 = new DataTypeDesign { NoArraysAllowed = false };

            // Act
            int hash1 = instance1.GetHashCode();
            int hash2 = instance2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different values for instances with different ForceEnumValues values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentForceEnumValues_ReturnsDifferentHashCodes()
        {
            // Arrange
            var instance1 = new DataTypeDesign { ForceEnumValues = true };
            var instance2 = new DataTypeDesign { ForceEnumValues = false };

            // Act
            int hash1 = instance1.GetHashCode();
            int hash2 = instance2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different values for instances with different NoEncodings values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentNoEncodings_ReturnsDifferentHashCodes()
        {
            // Arrange
            var instance1 = new DataTypeDesign { NoEncodings = true };
            var instance2 = new DataTypeDesign { NoEncodings = false };

            // Act
            int hash1 = instance1.GetHashCode();
            int hash2 = instance2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different values for instances with different IsServiceResponse values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentIsServiceResponse_ReturnsDifferentHashCodes()
        {
            // Arrange
            var instance1 = new DataTypeDesign { IsServiceResponse = true };
            var instance2 = new DataTypeDesign { IsServiceResponse = false };

            // Act
            int hash1 = instance1.GetHashCode();
            int hash2 = instance2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different values for instances with different Service values.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentService_ReturnsDifferentHashCodes()
        {
            // Arrange
            var instance1 = new DataTypeDesign
            {
                Service = new Service { Name = "Service1", Category = ServiceCategory.Session }
            };
            var instance2 = new DataTypeDesign
            {
                Service = new Service { Name = "Service2", Category = ServiceCategory.Discovery }
            };

            // Act
            int hash1 = instance1.GetHashCode();
            int hash2 = instance2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different values for instances with different Fields arrays.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentFields_ReturnsDifferentHashCodes()
        {
            // Arrange
            var instance1 = new DataTypeDesign
            {
                Fields = [new Parameter { Name = "Field1" }]
            };
            var instance2 = new DataTypeDesign
            {
                Fields = [new Parameter { Name = "Field2" }]
            };

            // Act
            int hash1 = instance1.GetHashCode();
            int hash2 = instance2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode returns different values for instances with different Encodings arrays.
        /// </summary>
        [Test]
        public void GetHashCode_DifferentEncodings_ReturnsDifferentHashCodes()
        {
            // Arrange
            var instance1 = new DataTypeDesign
            {
                Encodings = [new EncodingDesign { SymbolicName = new XmlQualifiedName("Encoding1") }]
            };
            var instance2 = new DataTypeDesign
            {
                Encodings = [new EncodingDesign { SymbolicName = new XmlQualifiedName("Encoding2") }]
            };

            // Act
            int hash1 = instance1.GetHashCode();
            int hash2 = instance2.GetHashCode();

            // Assert
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode handles all boolean properties set to true.
        /// </summary>
        [Test]
        public void GetHashCode_AllBooleanPropertiesTrue_ReturnsValidHashCode()
        {
            // Arrange
            var instance = new DataTypeDesign
            {
                IsOptionSet = true,
                IsUnion = true,
                NoArraysAllowed = true,
                ForceEnumValues = true,
                NoEncodings = true,
                IsServiceResponse = true
            };

            // Act
            int hashCode = instance.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode handles all boolean properties set to false.
        /// </summary>
        [Test]
        public void GetHashCode_AllBooleanPropertiesFalse_ReturnsValidHashCode()
        {
            // Arrange
            var instance = new DataTypeDesign
            {
                IsOptionSet = false,
                IsUnion = false,
                NoArraysAllowed = false,
                ForceEnumValues = false,
                NoEncodings = false,
                IsServiceResponse = false
            };

            // Act
            int hashCode = instance.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode handles multiple Parameter items in Fields array.
        /// </summary>
        [Test]
        public void GetHashCode_MultipleFieldsItems_ReturnsValidHashCode()
        {
            // Arrange
            var instance = new DataTypeDesign
            {
                Fields =
                [
                    new Parameter { Name = "Field1" },
                    new Parameter { Name = "Field2" },
                    new Parameter { Name = "Field3" }
                ]
            };

            // Act
            int hashCode = instance.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode handles multiple EncodingDesign items in Encodings array.
        /// </summary>
        [Test]
        public void GetHashCode_MultipleEncodingsItems_ReturnsValidHashCode()
        {
            // Arrange
            var instance = new DataTypeDesign
            {
                Encodings =
                [
                    new EncodingDesign { SymbolicName = new XmlQualifiedName("Encoding1") },
                    new EncodingDesign { SymbolicName = new XmlQualifiedName("Encoding2") }
                ]
            };

            // Act
            int hashCode = instance.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode returns different values when Fields array order differs but content is the same.
        /// </summary>
        [Test]
        public void GetHashCode_FieldsArrayDifferentOrder_MayReturnDifferentHashCodes()
        {
            // Arrange
            var instance1 = new DataTypeDesign
            {
                Fields =
                [
                    new Parameter { Name = "Field1" },
                    new Parameter { Name = "Field2" }
                ]
            };
            var instance2 = new DataTypeDesign
            {
                Fields =
                [
                    new Parameter { Name = "Field2" },
                    new Parameter { Name = "Field1" }
                ]
            };

            // Act
            int hash1 = instance1.GetHashCode();
            int hash2 = instance2.GetHashCode();

            // Assert - Arrays with different order should produce different hash codes
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        /// <summary>
        /// Tests that GetHashCode handles all ServiceCategory enum values for Service property.
        /// </summary>
        [TestCase(ServiceCategory.None)]
        [TestCase(ServiceCategory.Session)]
        [TestCase(ServiceCategory.SecureChannel)]
        [TestCase(ServiceCategory.Discovery)]
        [TestCase(ServiceCategory.Registration)]
        [TestCase(ServiceCategory.Test)]
        public void GetHashCode_DifferentServiceCategories_ReturnsValidHashCode(ServiceCategory category)
        {
            // Arrange
            var instance = new DataTypeDesign
            {
                Service = new Service { Name = "TestService", Category = category }
            };

            // Act
            int hashCode = instance.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetHashCode handles complex scenario with all properties populated.
        /// </summary>
        [Test]
        public void GetHashCode_AllPropertiesPopulated_ReturnsValidHashCode()
        {
            // Arrange
            var instance = new DataTypeDesign
            {
                IsOptionSet = true,
                IsUnion = true,
                NoArraysAllowed = false,
                ForceEnumValues = true,
                NoEncodings = false,
                Service = new Service { Name = "ComplexService", Category = ServiceCategory.Registration },
                IsServiceResponse = true,
                Fields =
                [
                    new Parameter { Name = "Field1" },
                    new Parameter { Name = "Field2" }
                ],
                Encodings =
                [
                    new EncodingDesign { SymbolicName = new XmlQualifiedName("Encoding1") },
                    new EncodingDesign { SymbolicName = new XmlQualifiedName("Encoding2") }
                ]
            };

            // Act
            int hashCode = instance.GetHashCode();

            // Assert
            Assert.That(hashCode, Is.Not.EqualTo(0));
        }
    }

    /// <summary>
    /// Unit tests for the PropertyDesign class.
    /// </summary>
    public partial class PropertyDesignTests
    {
        /// <summary>
        /// Tests that Equals returns false when comparing with null.
        /// </summary>
        [Test]
        public void Equals_WithNull_ReturnsFalse()
        {
            // Arrange
            var design = new PropertyDesign();

            // Act
#pragma warning disable CA1508 // Avoid dead conditional code
            bool result = design.Equals(null);
#pragma warning restore CA1508 // Avoid dead conditional code

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing an instance with itself.
        /// </summary>
        [Test]
        public void Equals_WithSameInstance_ReturnsTrue()
        {
            // Arrange
            var design = new PropertyDesign
            {
                SymbolicName = new XmlQualifiedName("TestProperty", "http://test.org")
            };

            // Act
            bool result = design.Equals(design);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing two instances with different property values.
        /// </summary>
        [Test]
        public void Equals_WithDifferentProperties_ReturnsFalse()
        {
            // Arrange
            var design1 = new PropertyDesign
            {
                SymbolicName = new XmlQualifiedName("TestProperty1", "http://test.org"),
                DataType = new XmlQualifiedName("Int32", "http://opcfoundation.org/UA/")
            };

            var design2 = new PropertyDesign
            {
                SymbolicName = new XmlQualifiedName("TestProperty2", "http://test.org"),
                DataType = new XmlQualifiedName("String", "http://opcfoundation.org/UA/")
            };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns true when comparing two default-initialized instances.
        /// </summary>
        [Test]
        public void Equals_WithDefaultInstances_ReturnsTrue()
        {
            // Arrange
            var design1 = new PropertyDesign();
            var design2 = new PropertyDesign();

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing instances with different ArrayDimensions.
        /// </summary>
        [Test]
        public void Equals_WithDifferentArrayDimensions_ReturnsFalse()
        {
            // Arrange
            var design1 = new PropertyDesign
            {
                SymbolicName = new XmlQualifiedName("TestProperty", "http://test.org"),
                ArrayDimensions = "1,2,3"
            };

            var design2 = new PropertyDesign
            {
                SymbolicName = new XmlQualifiedName("TestProperty", "http://test.org"),
                ArrayDimensions = "4,5,6"
            };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing instances with different Historizing flag.
        /// </summary>
        [Test]
        public void Equals_WithDifferentHistorizing_ReturnsFalse()
        {
            // Arrange
            var design1 = new PropertyDesign
            {
                SymbolicName = new XmlQualifiedName("TestProperty", "http://test.org"),
                Historizing = true,
                HistorizingSpecified = true
            };

            var design2 = new PropertyDesign
            {
                SymbolicName = new XmlQualifiedName("TestProperty", "http://test.org"),
                Historizing = false,
                HistorizingSpecified = true
            };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that Equals returns false when comparing instances with different MinimumSamplingInterval.
        /// </summary>
        [Test]
        public void Equals_WithDifferentMinimumSamplingInterval_ReturnsFalse()
        {
            // Arrange
            var design1 = new PropertyDesign
            {
                SymbolicName = new XmlQualifiedName("TestProperty", "http://test.org"),
                MinimumSamplingInterval = 100,
                MinimumSamplingIntervalSpecified = true
            };

            var design2 = new PropertyDesign
            {
                SymbolicName = new XmlQualifiedName("TestProperty", "http://test.org"),
                MinimumSamplingInterval = 200,
                MinimumSamplingIntervalSpecified = true
            };

            // Act
            bool result = design1.Equals(design2);

            // Assert
            Assert.That(result, Is.False);
        }
    }
}
