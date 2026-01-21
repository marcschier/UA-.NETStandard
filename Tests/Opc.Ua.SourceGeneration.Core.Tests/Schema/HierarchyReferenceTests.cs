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
using System.Globalization;
using System.Xml;
using NUnit.Framework;

namespace Opc.Ua.Schema.Model.Tests
{
    /// <summary>
    /// Unit tests for the HierarchyReference class.
    /// </summary>
    [TestFixture]
    [Category("ModelDesign")]
    [SetCulture("en-us")]
    [SetUICulture("en-us")]
    [Parallelizable]
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
}
