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

using Moq;
using NUnit.Framework;
using Opc.Ua.Schema.Model;
using System;
using System.IO;
using System.Reflection;
using System.Text;

namespace Opc.Ua.SourceGeneration.Generator.Tests
{
    /// <summary>
    /// Unit tests for the <see cref = "TextResource"/> class.
    /// </summary>
    [TestFixture]
    public class TextResourceTests
    {
        /// <summary>
        /// Tests that GetLength returns the correct UTF-8 byte count for various text inputs.
        /// </summary>
        /// <param name = "text">The text to test.</param>
        /// <param name = "expectedByteCount">The expected UTF-8 byte count.</param>
        [TestCase("", 0, TestName = "GetLength_EmptyString_ReturnsZero")]
        [TestCase("Hello", 5, TestName = "GetLength_SimpleAsciiText_ReturnsCorrectByteCount")]
        [TestCase("Hello World!", 12, TestName = "GetLength_AsciiTextWithSpace_ReturnsCorrectByteCount")]
        [TestCase("café", 5, TestName = "GetLength_LatinExtendedCharacters_ReturnsCorrectByteCount")]
        [TestCase("你好", 6, TestName = "GetLength_ChineseCharacters_ReturnsCorrectByteCount")]
        [TestCase("こんにちは", 15, TestName = "GetLength_JapaneseCharacters_ReturnsCorrectByteCount")]
        [TestCase("🚀", 4, TestName = "GetLength_EmojiCharacter_ReturnsCorrectByteCount")]
        [TestCase("Hello 世界 🌍", 17, TestName = "GetLength_MixedAsciiUnicodeEmoji_ReturnsCorrectByteCount")]
        [TestCase("\n\r\t", 3, TestName = "GetLength_SpecialCharacters_ReturnsCorrectByteCount")]
        [TestCase("Line1\nLine2\r\nLine3", 18, TestName = "GetLength_TextWithNewlines_ReturnsCorrectByteCount")]
        public void GetLength_VariousTextInputs_ReturnsCorrectUtf8ByteCount(string text, long expectedByteCount)
        {
            // Arrange
            var resource = new TextResource("Test.Resource", text);
            var mockFileSystem = new Mock<IFileSystem>();
            // Act
            long actualByteCount = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(actualByteCount, Is.EqualTo(expectedByteCount));
        }

        /// <summary>
        /// Tests that GetLength returns the correct UTF-8 byte count for a very long string.
        /// </summary>
        [Test]
        public void GetLength_VeryLongString_ReturnsCorrectByteCount()
        {
            // Arrange
            string longText = new('A', 100000);
            var resource = new TextResource("Test.Resource", longText);
            long expectedByteCount = Encoding.UTF8.GetByteCount(longText);
            var mockFileSystem = new Mock<IFileSystem>();
            // Act
            long actualByteCount = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(actualByteCount, Is.EqualTo(expectedByteCount));
            Assert.That(actualByteCount, Is.EqualTo(100000));
        }

        /// <summary>
        /// Tests that GetLength throws ArgumentNullException when Text property is null.
        /// </summary>
        [Test]
        public void GetLength_NullText_ThrowsArgumentNullException()
        {
            // Arrange
            var resource = new TextResource("Test.Resource", null);
            var mockFileSystem = new Mock<IFileSystem>();
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => resource.GetLength(mockFileSystem.Object));
        }

        /// <summary>
        /// Tests that GetLength works correctly when fileSystem parameter is null,
        /// demonstrating that the parameter is not used by the method.
        /// </summary>
        [Test]
        public void GetLength_NullFileSystemParameter_ReturnsCorrectByteCount()
        {
            // Arrange
            const string text = "Test text";
            var resource = new TextResource("Test.Resource", text);
            long expectedByteCount = Encoding.UTF8.GetByteCount(text);
            // Act
            long actualByteCount = resource.GetLength(null);
            // Assert
            Assert.That(actualByteCount, Is.EqualTo(expectedByteCount));
            Assert.That(actualByteCount, Is.EqualTo(9));
        }

        /// <summary>
        /// Tests that GetLength returns correct byte count for text with various control characters.
        /// </summary>
        [Test]
        public void GetLength_TextWithControlCharacters_ReturnsCorrectByteCount()
        {
            // Arrange
            const string text = "Hello\0World\u0001\u0002";
            var resource = new TextResource("Test.Resource", text);
            long expectedByteCount = Encoding.UTF8.GetByteCount(text);
            var mockFileSystem = new Mock<IFileSystem>();
            // Act
            long actualByteCount = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(actualByteCount, Is.EqualTo(expectedByteCount));
        }

        /// <summary>
        /// Tests that GetLength returns correct byte count for text with all valid UTF-8 ranges.
        /// </summary>
        [Test]
        public void GetLength_TextWithVariousUtf8Ranges_ReturnsCorrectByteCount()
        {
            // Arrange
            // 1-byte: ASCII
            // 2-byte: Latin Extended
            // 3-byte: CJK
            // 4-byte: Emoji
            const string text = "Aé中🎉";
            var resource = new TextResource("Test.Resource", text);
            const long expectedByteCount = 1 + 2 + 3 + 4; // Total: 10 bytes
            var mockFileSystem = new Mock<IFileSystem>();
            // Act
            long actualByteCount = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(actualByteCount, Is.EqualTo(expectedByteCount));
            Assert.That(actualByteCount, Is.EqualTo(10));
        }

        /// <summary>
        /// Tests that GetLength returns correct byte count for whitespace-only text.
        /// </summary>
        [Test]
        public void GetLength_WhitespaceOnlyText_ReturnsCorrectByteCount()
        {
            // Arrange
            const string text = "   \t\t\n\r  ";
            var resource = new TextResource("Test.Resource", text);
            long expectedByteCount = Encoding.UTF8.GetByteCount(text);
            var mockFileSystem = new Mock<IFileSystem>();
            // Act
            long actualByteCount = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(actualByteCount, Is.EqualTo(expectedByteCount));
        }
    }

    /// <summary>
    /// Unit tests for the <see cref = "TextReaderResource"/> class.
    /// </summary>
    [TestFixture]
    public class TextReaderResourceTests
    {
        /// <summary>
        /// Tests that GetLength returns 0 when called with a valid IFileSystem mock.
        /// This verifies that the method correctly indicates unknown length for a TextReader resource.
        /// </summary>
        [Test]
        public void GetLength_WithValidFileSystem_ReturnsZero()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            using var reader = new StringReader("Sample text content");
            var resource = new TextReaderResource("TestResource", reader);
            // Act
            long length = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(length, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetLength returns 0 when called with a null IFileSystem parameter.
        /// This verifies that the method does not throw and correctly handles null input
        /// since the parameter is not actually used in the implementation.
        /// </summary>
        [Test]
        public void GetLength_WithNullFileSystem_ReturnsZero()
        {
            // Arrange
            using var reader = new StringReader("Sample text content");
            var resource = new TextReaderResource("TestResource", reader);
            // Act
            long length = resource.GetLength(null);
            // Assert
            Assert.That(length, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetLength returns 0 consistently across multiple calls.
        /// This verifies that the method behavior is deterministic and stateless.
        /// </summary>
        [Test]
        public void GetLength_MultipleCallsWithSameInstance_ReturnsZeroConsistently()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            using var reader = new StringReader("Sample text content");
            var resource = new TextReaderResource("TestResource", reader);
            // Act
            long length1 = resource.GetLength(mockFileSystem.Object);
            long length2 = resource.GetLength(mockFileSystem.Object);
            long length3 = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(length1, Is.EqualTo(0));
            Assert.That(length2, Is.EqualTo(0));
            Assert.That(length3, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetLength returns 0 with AsUtf16 parameter set to true.
        /// This verifies that the AsUtf16 encoding flag does not affect the returned length.
        /// </summary>
        [Test]
        public void GetLength_WithAsUtf16True_ReturnsZero()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            using var reader = new StringReader("Sample text content");
            var resource = new TextReaderResource("TestResource", reader, AsUtf16: true);
            // Act
            long length = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(length, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that GetLength returns 0 with an empty TextReader.
        /// This verifies that the method returns 0 regardless of the TextReader content.
        /// </summary>
        [Test]
        public void GetLength_WithEmptyTextReader_ReturnsZero()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            using var reader = new StringReader(string.Empty);
            var resource = new TextReaderResource("TestResource", reader);
            // Act
            long length = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(length, Is.EqualTo(0));
        }
    }

    /// <summary>
    /// Unit tests for <see cref = "BinaryResource"/>.
    /// </summary>
    [TestFixture]
    public partial class BinaryResourceTests
    {
        /// <summary>
        /// Tests GetLength returns zero for an empty byte array.
        /// Input: Empty byte array.
        /// Expected: Returns 0.
        /// </summary>
        [Test]
        public void GetLength_EmptyByteArray_ReturnsZero()
        {
            // Arrange
            byte[] data = [];
            var resource = new BinaryResource("TestResource", data);
            // Act
            long length = resource.GetLength(null);
            // Assert
            Assert.That(length, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests GetLength returns correct length for various byte array sizes.
        /// Input: Byte arrays of different sizes.
        /// Expected: Returns the correct array length.
        /// </summary>
        [TestCase(1)]
        [TestCase(10)]
        [TestCase(100)]
        [TestCase(1024)]
        [TestCase(10000)]
        [TestCase(1048576)]
        public void GetLength_VariousSizes_ReturnsCorrectLength(int size)
        {
            // Arrange
            byte[] data = new byte[size];
            var resource = new BinaryResource("TestResource", data);
            // Act
            long length = resource.GetLength(null);
            // Assert
            Assert.That(length, Is.EqualTo(size));
        }

        /// <summary>
        /// Tests GetLength does not use the fileSystem parameter and returns correct length.
        /// Input: Valid byte array and mocked IFileSystem.
        /// Expected: Returns correct length without accessing fileSystem.
        /// </summary>
        [Test]
        public void GetLength_WithMockedFileSystem_ReturnsCorrectLengthWithoutUsingParameter()
        {
            // Arrange
            byte[] data = new byte[42];
            var resource = new BinaryResource("TestResource", data);
            var mockFileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
            // Act
            long length = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(length, Is.EqualTo(42));
            mockFileSystem.VerifyNoOtherCalls();
        }

        /// <summary>
        /// Tests GetLength with null IFileSystem parameter.
        /// Input: Valid byte array and null fileSystem.
        /// Expected: Returns correct length (parameter not used).
        /// </summary>
        [Test]
        public void GetLength_NullFileSystem_ReturnsCorrectLength()
        {
            // Arrange
            byte[] data = new byte[123];
            var resource = new BinaryResource("TestResource", data);
            // Act
            long length = resource.GetLength(null);
            // Assert
            Assert.That(length, Is.EqualTo(123));
        }

        /// <summary>
        /// Tests GetLength returns long type for large arrays demonstrating implicit int to long conversion.
        /// Input: Large byte array near int.MaxValue boundary.
        /// Expected: Returns correct length as long.
        /// </summary>
        [Test]
        public void GetLength_LargeArray_ReturnsLongType()
        {
            // Arrange
            byte[] data = new byte[int.MaxValue / 1000];
            var resource = new BinaryResource("TestResource", data);
            // Act
            long length = resource.GetLength(null);
            // Assert
            Assert.That(length, Is.EqualTo(int.MaxValue / 1000));
            Assert.That(length, Is.TypeOf<long>());
        }

        /// <summary>
        /// Tests GetLength throws NullReferenceException when Data is null.
        /// Input: BinaryResource with null Data array.
        /// Expected: Throws NullReferenceException.
        /// </summary>
        [Test]
        public void GetLength_NullData_ThrowsNullReferenceException()
        {
            // Arrange
            var resource = new BinaryResource("TestResource", null);
            // Act & Assert
            Assert.Throws<NullReferenceException>(() => resource.GetLength(null));
        }
    }

    /// <summary>
    /// Unit tests for the TextFileResource class.
    /// </summary>
    [TestFixture]
    public class TextFileResourceTests
    {
        /// <summary>
        /// Tests that GetLength returns the expected file length from the file system.
        /// </summary>
        /// <param name = "fileName">The file name to test with.</param>
        /// <param name = "expectedLength">The expected length value that the file system should return.</param>
        [TestCase("test.txt", 100L)]
        [TestCase("file.xml", 0L)]
        [TestCase("large.bin", long.MaxValue)]
        [TestCase("C:\\path\\to\\file.txt", 12345L)]
        [TestCase("../relative/path.txt", 999L)]
        [TestCase("file-with-special-chars_@#$.txt", 42L)]
        public void GetLength_ValidFileSystemAndFileName_ReturnsExpectedLength(string fileName, long expectedLength)
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(fs => fs.GetLength(fileName)).Returns(expectedLength);
            var resource = new TextFileResource("TestResource", fileName);
            // Act
            long actualLength = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(actualLength, Is.EqualTo(expectedLength));
            mockFileSystem.Verify(fs => fs.GetLength(fileName), Times.Once);
        }

        /// <summary>
        /// Tests that GetLength throws NullReferenceException when fileSystem parameter is null.
        /// </summary>
        [Test]
        public void GetLength_NullFileSystem_ThrowsNullReferenceException()
        {
            // Arrange
            var resource = new TextFileResource("TestResource", "test.txt");
            // Act & Assert
            Assert.Throws<NullReferenceException>(() => resource.GetLength(null));
        }

        /// <summary>
        /// Tests that GetLength handles empty file name string.
        /// </summary>
        [Test]
        public void GetLength_EmptyFileName_CallsFileSystemWithEmptyString()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(fs => fs.GetLength(string.Empty)).Returns(0L);
            var resource = new TextFileResource("TestResource", string.Empty);
            // Act
            long actualLength = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(actualLength, Is.EqualTo(0L));
            mockFileSystem.Verify(fs => fs.GetLength(string.Empty), Times.Once);
        }

        /// <summary>
        /// Tests that GetLength returns zero for zero-length files.
        /// </summary>
        [Test]
        public void GetLength_ZeroLengthFile_ReturnsZero()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(fs => fs.GetLength("empty.txt")).Returns(0L);
            var resource = new TextFileResource("TestResource", "empty.txt");
            // Act
            long actualLength = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(actualLength, Is.EqualTo(0L));
        }

        /// <summary>
        /// Tests that GetLength correctly handles maximum long value for very large files.
        /// </summary>
        [Test]
        public void GetLength_MaximumFileSize_ReturnsMaxValue()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(fs => fs.GetLength("huge.bin")).Returns(long.MaxValue);
            var resource = new TextFileResource("TestResource", "huge.bin");
            // Act
            long actualLength = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(actualLength, Is.EqualTo(long.MaxValue));
        }

        /// <summary>
        /// Tests that GetLength handles negative return values from the file system (edge case).
        /// </summary>
        [Test]
        public void GetLength_NegativeLength_ReturnsNegativeValue()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(fs => fs.GetLength("invalid.txt")).Returns(-1L);
            var resource = new TextFileResource("TestResource", "invalid.txt");
            // Act
            long actualLength = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(actualLength, Is.EqualTo(-1L));
        }

        /// <summary>
        /// Tests that GetLength correctly passes the FileName property to the file system.
        /// </summary>
        [Test]
        public void GetLength_DifferentFileNames_PassesCorrectFileNameToFileSystem()
        {
            // Arrange
            const string expectedFileName = "specific-file.txt";
            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(fs => fs.GetLength(expectedFileName)).Returns(500L);
            var resource = new TextFileResource("TestResource", expectedFileName);
            // Act
            resource.GetLength(mockFileSystem.Object);
            // Assert
            mockFileSystem.Verify(fs => fs.GetLength(expectedFileName), Times.Once);
        }

        /// <summary>
        /// Tests that GetLength returns the correct file length from the file system
        /// when provided with a valid file name and file system.
        /// </summary>
        [TestCase(0L)]
        [TestCase(1L)]
        [TestCase(100L)]
        [TestCase(1024L)]
        [TestCase(1048576L)]
        [TestCase(long.MaxValue)]
        public void GetLength_ValidFileSystem_ReturnsExpectedLength(long expectedLength)
        {
            // Arrange
            const string resourceName = "Test.Resource";
            const string fileName = "test.txt";
            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(fs => fs.GetLength(fileName)).Returns(expectedLength);
            var resource = new TextFileResource(resourceName, fileName);
            // Act
            long actualLength = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(actualLength, Is.EqualTo(expectedLength));
            mockFileSystem.Verify(fs => fs.GetLength(fileName), Times.Once);
        }

        /// <summary>
        /// Tests that GetLength passes the correct FileName to the file system's GetLength method.
        /// </summary>
        [TestCase("simple.txt")]
        [TestCase("path/to/file.txt")]
        [TestCase("C:\\absolute\\path\\file.txt")]
        [TestCase("")]
        [TestCase("file with spaces.txt")]
        [TestCase("file_with_special_chars!@#.txt")]
        public void GetLength_VariousFileNames_PassesCorrectFileNameToFileSystem(string fileName)
        {
            // Arrange
            const string resourceName = "Test.Resource";
            const long expectedLength = 42L;
            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(fs => fs.GetLength(fileName)).Returns(expectedLength);
            var resource = new TextFileResource(resourceName, fileName);
            // Act
            long actualLength = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(actualLength, Is.EqualTo(expectedLength));
            mockFileSystem.Verify(fs => fs.GetLength(fileName), Times.Once);
        }

        /// <summary>
        /// Tests that GetLength propagates exceptions thrown by the file system's GetLength method.
        /// </summary>
        [Test]
        public void GetLength_FileSystemThrowsIOException_PropagatesException()
        {
            // Arrange
            const string resourceName = "Test.Resource";
            const string fileName = "nonexistent.txt";
            var mockFileSystem = new Mock<IFileSystem>();
            var expectedException = new IOException("File not found");
            mockFileSystem.Setup(fs => fs.GetLength(fileName)).Throws(expectedException);
            var resource = new TextFileResource(resourceName, fileName);
            // Act & Assert
            IOException thrownException = Assert.Throws<IOException>(() => resource.GetLength(mockFileSystem.Object));
            Assert.That(thrownException.Message, Is.EqualTo("File not found"));
        }

        /// <summary>
        /// Tests that GetLength propagates ArgumentException when the file system throws it.
        /// </summary>
        [Test]
        public void GetLength_FileSystemThrowsArgumentException_PropagatesException()
        {
            // Arrange
            const string resourceName = "Test.Resource";
            const string fileName = "invalid:filename.txt";
            var mockFileSystem = new Mock<IFileSystem>();
            var expectedException = new ArgumentException("Invalid file name");
            mockFileSystem.Setup(fs => fs.GetLength(fileName)).Throws(expectedException);
            var resource = new TextFileResource(resourceName, fileName);
            // Act & Assert
            ArgumentException thrownException = Assert.Throws<ArgumentException>(() => resource.GetLength(mockFileSystem.Object));
            Assert.That(thrownException.Message, Is.EqualTo("Invalid file name"));
        }

        /// <summary>
        /// Tests that GetLength returns zero when the file system reports a zero-length file.
        /// </summary>
        [Test]
        public void GetLength_EmptyFile_ReturnsZero()
        {
            // Arrange
            const string resourceName = "Test.Resource";
            const string fileName = "empty.txt";
            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(fs => fs.GetLength(fileName)).Returns(0L);
            var resource = new TextFileResource(resourceName, fileName);
            // Act
            long actualLength = resource.GetLength(mockFileSystem.Object);
            // Assert
            Assert.That(actualLength, Is.EqualTo(0L));
        }
    }

    /// <summary>
    /// Unit tests for the ResourceGenerator class.
    /// </summary>
    [TestFixture]
    public class ResourceGeneratorTests
    {
        /// <summary>
        /// Tests that Embed throws ArgumentException when no resources are provided.
        /// </summary>
        [Test]
        public void Embed_EmptyResourceArray_ThrowsArgumentException()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            Mock<GeneratorContext> mockGeneratorContext = CreateMockGeneratorContext(mockFileSystem.Object);
            var generator = new ResourceGenerator(mockGeneratorContext.Object);
            // Act & Assert
            ArgumentException ex = Assert.Throws<ArgumentException>(() => generator.Embed("TestNamespace", "TestName", false));
            Assert.That(ex.Message, Is.EqualTo("At least one resource must be provided"));
        }

        private static Mock<GeneratorContext> CreateMockGeneratorContext(IFileSystem fileSystem, string outputFolder = "C:\\Output")
        {
            var mockContext = new Mock<GeneratorContext>();
            mockContext.Setup(c => c.FileSystem).Returns(fileSystem);
            mockContext.Setup(c => c.OutputFolder).Returns(outputFolder);
            mockContext.Setup(c => c.Options).Returns(new GeneratorOptions());
            return mockContext;
        }

        /// <summary>
        /// Tests that constructor assigns context and uses default values when base64Threshold is null and OptimizeForCompileSpeed is false.
        /// Input: Valid context with OptimizeForCompileSpeed=false, base64Threshold=null, useByteArrayForBase64=false.
        /// Expected: m_base64Threshold should be int.MaxValue.
        /// </summary>
        [Test]
        public void Constructor_DefaultParameters_OptimizeForCompileSpeedFalse_SetsBase64ThresholdToMaxValue()
        {
            // Arrange
            GeneratorContext context = CreateGeneratorContext(optimizeForCompileSpeed: false);
            // Act
            var generator = new ResourceGenerator(context);
            // Assert
            Assert.That(generator, Is.Not.Null);
            int base64ThresholdField = GetPrivateField<int>(generator, "m_base64Threshold");
            Assert.That(base64ThresholdField, Is.EqualTo(int.MaxValue));
            GeneratorContext contextField = GetPrivateField<GeneratorContext>(generator, "m_context");
            Assert.That(contextField, Is.SameAs(context));
            bool useByteArrayField = GetPrivateField<bool>(generator, "m_useByteArrayForBase64");
            Assert.That(useByteArrayField, Is.False);
        }

        /// <summary>
        /// Tests that constructor assigns context and uses default values when base64Threshold is null and OptimizeForCompileSpeed is true.
        /// Input: Valid context with OptimizeForCompileSpeed=true, base64Threshold=null, useByteArrayForBase64=false.
        /// Expected: m_base64Threshold should be 1024.
        /// </summary>
        [Test]
        public void Constructor_DefaultParameters_OptimizeForCompileSpeedTrue_SetsBase64ThresholdTo1024()
        {
            // Arrange
            GeneratorContext context = CreateGeneratorContext(optimizeForCompileSpeed: true);
            // Act
            var generator = new ResourceGenerator(context);
            // Assert
            Assert.That(generator, Is.Not.Null);
            int base64ThresholdField = GetPrivateField<int>(generator, "m_base64Threshold");
            Assert.That(base64ThresholdField, Is.EqualTo(1024));
            GeneratorContext contextField = GetPrivateField<GeneratorContext>(generator, "m_context");
            Assert.That(contextField, Is.SameAs(context));
            bool useByteArrayField = GetPrivateField<bool>(generator, "m_useByteArrayForBase64");
            Assert.That(useByteArrayField, Is.False);
        }

        /// <summary>
        /// Tests that constructor uses provided base64Threshold value when not null.
        /// Input: Valid context, base64Threshold values, useByteArrayForBase64=false.
        /// Expected: m_base64Threshold should be the provided value regardless of OptimizeForCompileSpeed.
        /// </summary>
        [TestCase(0)]
        [TestCase(1)]
        [TestCase(1024)]
        [TestCase(2147483647)]
        [TestCase(-1)]
        [TestCase(-2147483648)]
        public void Constructor_CustomBase64Threshold_UsesProvidedValue(int threshold)
        {
            // Arrange
            GeneratorContext context = CreateGeneratorContext(optimizeForCompileSpeed: true);
            // Act
            var generator = new ResourceGenerator(context, base64Threshold: threshold);
            // Assert
            Assert.That(generator, Is.Not.Null);
            int base64ThresholdField = GetPrivateField<int>(generator, "m_base64Threshold");
            Assert.That(base64ThresholdField, Is.EqualTo(threshold));
        }

        /// <summary>
        /// Tests that constructor correctly assigns useByteArrayForBase64 parameter.
        /// Input: Valid context, useByteArrayForBase64=true.
        /// Expected: m_useByteArrayForBase64 should be true.
        /// </summary>
        [Test]
        public void Constructor_UseByteArrayForBase64True_AssignsCorrectly()
        {
            // Arrange
            GeneratorContext context = CreateGeneratorContext(optimizeForCompileSpeed: false);
            // Act
            var generator = new ResourceGenerator(context, useByteArrayForBase64: true);
            // Assert
            Assert.That(generator, Is.Not.Null);
            bool useByteArrayField = GetPrivateField<bool>(generator, "m_useByteArrayForBase64");
            Assert.That(useByteArrayField, Is.True);
        }

        /// <summary>
        /// Tests that constructor correctly assigns all parameters when custom values are provided.
        /// Input: Valid context, custom base64Threshold, useByteArrayForBase64=true.
        /// Expected: All fields should be assigned correctly.
        /// </summary>
        [Test]
        public void Constructor_AllParametersProvided_AssignsCorrectly()
        {
            // Arrange
            GeneratorContext context = CreateGeneratorContext(optimizeForCompileSpeed: true);
            const int customThreshold = 512;
            // Act
            var generator = new ResourceGenerator(context, base64Threshold: customThreshold, useByteArrayForBase64: true);
            // Assert
            Assert.That(generator, Is.Not.Null);
            int base64ThresholdField = GetPrivateField<int>(generator, "m_base64Threshold");
            Assert.That(base64ThresholdField, Is.EqualTo(customThreshold));
            GeneratorContext contextField = GetPrivateField<GeneratorContext>(generator, "m_context");
            Assert.That(contextField, Is.SameAs(context));
            bool useByteArrayField = GetPrivateField<bool>(generator, "m_useByteArrayForBase64");
            Assert.That(useByteArrayField, Is.True);
        }

        /// <summary>
        /// Tests that constructor throws NullReferenceException when context is null.
        /// Input: null context.
        /// Expected: NullReferenceException is thrown.
        /// </summary>
        [Test]
        public void Constructor_NullContext_ThrowsNullReferenceException()
        {
            // Arrange
            GeneratorContext context = null;
            // Act & Assert
            Assert.Throws<NullReferenceException>(() => new ResourceGenerator(context));
        }

        /// <summary>
        /// Tests that constructor handles boundary values for base64Threshold.
        /// Input: Valid context with int.MinValue and int.MaxValue for base64Threshold.
        /// Expected: Values are assigned correctly.
        /// </summary>
        [TestCase(int.MinValue)]
        [TestCase(int.MaxValue)]
        public void Constructor_BoundaryBase64Threshold_AssignsCorrectly(int threshold)
        {
            // Arrange
            GeneratorContext context = CreateGeneratorContext(optimizeForCompileSpeed: false);
            // Act
            var generator = new ResourceGenerator(context, base64Threshold: threshold);
            // Assert
            Assert.That(generator, Is.Not.Null);
            int base64ThresholdField = GetPrivateField<int>(generator, "m_base64Threshold");
            Assert.That(base64ThresholdField, Is.EqualTo(threshold));
        }

        /// <summary>
        /// Tests that constructor with OptimizeForCompileSpeed true overrides default only when base64Threshold is null.
        /// Input: Context with OptimizeForCompileSpeed=true, base64Threshold=null.
        /// Expected: m_base64Threshold should be 1024 (not int.MaxValue).
        /// </summary>
        [Test]
        public void Constructor_OptimizeForCompileSpeedTrue_NullThreshold_Uses1024()
        {
            // Arrange
            GeneratorContext context = CreateGeneratorContext(optimizeForCompileSpeed: true);
            // Act
            var generator = new ResourceGenerator(context, base64Threshold: null);
            // Assert
            Assert.That(generator, Is.Not.Null);
            int base64ThresholdField = GetPrivateField<int>(generator, "m_base64Threshold");
            Assert.That(base64ThresholdField, Is.EqualTo(1024));
        }

        /// <summary>
        /// Tests that constructor with OptimizeForCompileSpeed false uses int.MaxValue when base64Threshold is null.
        /// Input: Context with OptimizeForCompileSpeed=false, base64Threshold=null.
        /// Expected: m_base64Threshold should be int.MaxValue.
        /// </summary>
        [Test]
        public void Constructor_OptimizeForCompileSpeedFalse_NullThreshold_UsesMaxValue()
        {
            // Arrange
            GeneratorContext context = CreateGeneratorContext(optimizeForCompileSpeed: false);
            // Act
            var generator = new ResourceGenerator(context, base64Threshold: null);
            // Assert
            Assert.That(generator, Is.Not.Null);
            int base64ThresholdField = GetPrivateField<int>(generator, "m_base64Threshold");
            Assert.That(base64ThresholdField, Is.EqualTo(int.MaxValue));
        }

        /// <summary>
        /// Tests that constructor ignores OptimizeForCompileSpeed when explicit base64Threshold is provided.
        /// Input: Context with OptimizeForCompileSpeed=true, explicit base64Threshold=int.MaxValue.
        /// Expected: m_base64Threshold should be int.MaxValue (not 1024).
        /// </summary>
        [Test]
        public void Constructor_ExplicitThreshold_IgnoresOptimizeForCompileSpeed()
        {
            // Arrange
            GeneratorContext context = CreateGeneratorContext(optimizeForCompileSpeed: true);
            // Act
            var generator = new ResourceGenerator(context, base64Threshold: int.MaxValue);
            // Assert
            Assert.That(generator, Is.Not.Null);
            int base64ThresholdField = GetPrivateField<int>(generator, "m_base64Threshold");
            Assert.That(base64ThresholdField, Is.EqualTo(int.MaxValue));
        }

        private static GeneratorContext CreateGeneratorContext(bool optimizeForCompileSpeed)
        {
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockValidator = new Mock<ModelDesignValidator>();
            return new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "output",
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = new GeneratorOptions
                {
                    OptimizeForCompileSpeed = optimizeForCompileSpeed
                }
            };
        }

        private static T GetPrivateField<T>(object obj, string fieldName)
        {
            FieldInfo field = obj.GetType().GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance);
            return (T)field.GetValue(obj);
        }
    }
}
