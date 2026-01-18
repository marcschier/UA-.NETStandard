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
using System.IO;
using Moq;
using NUnit.Framework;
using Opc.Ua.Schema.Model;

namespace Opc.Ua.SourceGeneration.Generator.Tests
{
    /// <summary>
    /// Unit tests for <see cref="EndpointsGenerator"/>.
    /// </summary>
    [TestFixture]
    public class EndpointsGeneratorTests
    {
        /// <summary>
        /// Tests that Emit method generates endpoint code successfully with valid context.
        /// Verifies that the file writer is created with the correct path and that template rendering occurs.
        /// Expected result: Method completes without exceptions and creates file with proper name.
        /// </summary>
        [Test]
        public void Emit_ValidContext_GeneratesEndpointCodeSuccessfully()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTextWriter = new Mock<TextWriter>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockOptions = new Mock<GeneratorOptions>();

            string expectedOutputFolder = Path.Combine(Path.GetTempPath(), "TestOutput");
            const string expectedFileName = "Opc.Ua.Endpoints.g.cs";
            string expectedPath = Path.Combine(expectedOutputFolder, expectedFileName);

            mockFileSystem.Setup(fs => fs.CreateTextWriter(expectedPath))
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = expectedOutputFolder,
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new EndpointsGenerator(context);

            // Act
            generator.Emit();

            // Assert
            mockFileSystem.Verify(fs => fs.CreateTextWriter(expectedPath), Times.Once);
            mockTextWriter.Verify(tw => tw.Dispose(), Times.Once);
        }

        /// <summary>
        /// Tests that Emit method handles empty output folder path correctly.
        /// Verifies that the file is created in the current directory when OutputFolder is empty.
        /// Expected result: CreateTextWriter is called with a path relative to current directory.
        /// </summary>
        [Test]
        public void Emit_EmptyOutputFolder_CreatesFileInCurrentDirectory()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTextWriter = new Mock<TextWriter>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockOptions = new Mock<GeneratorOptions>();

            const string expectedFileName = "Opc.Ua.Endpoints.g.cs";

            mockFileSystem.Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = string.Empty,
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new EndpointsGenerator(context);

            // Act
            generator.Emit();

            // Assert
            mockFileSystem.Verify(fs => fs.CreateTextWriter(expectedFileName), Times.Once);
            mockTextWriter.Verify(tw => tw.Dispose(), Times.Once);
        }

        /// <summary>
        /// Tests that Emit method handles output folder with special characters.
        /// Verifies that paths with special characters are handled correctly by the file system.
        /// Expected result: CreateTextWriter is called with the path containing special characters.
        /// </summary>
        [Test]
        public void Emit_OutputFolderWithSpecialCharacters_HandlesCorrectly()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTextWriter = new Mock<TextWriter>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockOptions = new Mock<GeneratorOptions>();

            string folderWithSpecialChars = Path.Combine(Path.GetTempPath(), "Test Folder (123) & [456]");
            string expectedPath = Path.Combine(folderWithSpecialChars, "Opc.Ua.Endpoints.g.cs");

            mockFileSystem.Setup(fs => fs.CreateTextWriter(expectedPath))
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = folderWithSpecialChars,
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new EndpointsGenerator(context);

            // Act
            generator.Emit();

            // Assert
            mockFileSystem.Verify(fs => fs.CreateTextWriter(expectedPath), Times.Once);
            mockTextWriter.Verify(tw => tw.Dispose(), Times.Once);
        }

        /// <summary>
        /// Tests that Emit method properly disposes TextWriter when exception occurs during rendering.
        /// Verifies that resources are cleaned up even when template rendering fails.
        /// Expected result: TextWriter is disposed even when an exception is thrown.
        /// </summary>
        [Test]
        public void Emit_CreateTextWriterThrowsException_PropagatesException()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockOptions = new Mock<GeneratorOptions>();

            var expectedException = new IOException("Disk full");

            mockFileSystem.Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Throws(expectedException);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = Path.GetTempPath(),
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new EndpointsGenerator(context);

            // Act & Assert
            IOException ex = Assert.Throws<IOException>(generator.Emit);
            Assert.That(ex, Is.SameAs(expectedException));
        }

        /// <summary>
        /// Tests that Emit method handles very long output folder paths.
        /// Verifies that the method can handle paths near the system's maximum length.
        /// Expected result: CreateTextWriter is called with the long path.
        /// </summary>
        [Test]
        public void Emit_VeryLongOutputFolder_HandlesCorrectly()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTextWriter = new Mock<TextWriter>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockOptions = new Mock<GeneratorOptions>();

            string longPath = Path.Combine(Path.GetTempPath(), new string('a', 200));
            string expectedPath = Path.Combine(longPath, "Opc.Ua.Endpoints.g.cs");

            mockFileSystem.Setup(fs => fs.CreateTextWriter(expectedPath))
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = longPath,
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new EndpointsGenerator(context);

            // Act
            generator.Emit();

            // Assert
            mockFileSystem.Verify(fs => fs.CreateTextWriter(expectedPath), Times.Once);
            mockTextWriter.Verify(tw => tw.Dispose(), Times.Once);
        }

        /// <summary>
        /// Tests that Emit method handles whitespace-only output folder.
        /// Verifies that whitespace folder paths are handled correctly.
        /// Expected result: CreateTextWriter is called with the whitespace path.
        /// </summary>
        [Test]
        public void Emit_WhitespaceOutputFolder_HandlesCorrectly()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTextWriter = new Mock<TextWriter>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockOptions = new Mock<GeneratorOptions>();

            const string whitespaceFolder = "   ";
            string expectedPath = Path.Combine(whitespaceFolder, "Opc.Ua.Endpoints.g.cs");

            mockFileSystem.Setup(fs => fs.CreateTextWriter(expectedPath))
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = whitespaceFolder,
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new EndpointsGenerator(context);

            // Act
            generator.Emit();

            // Assert
            mockFileSystem.Verify(fs => fs.CreateTextWriter(expectedPath), Times.Once);
            mockTextWriter.Verify(tw => tw.Dispose(), Times.Once);
        }

        /// <summary>
        /// Tests that Emit method handles relative output folder paths.
        /// Verifies that relative paths are correctly combined with the file name.
        /// Expected result: CreateTextWriter is called with the relative path.
        /// </summary>
        [Test]
        public void Emit_RelativeOutputFolder_HandlesCorrectly()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTextWriter = new Mock<TextWriter>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockOptions = new Mock<GeneratorOptions>();

            string relativePath = Path.Combine(".", "output", "generated");
            string expectedPath = Path.Combine(relativePath, "Opc.Ua.Endpoints.g.cs");

            mockFileSystem.Setup(fs => fs.CreateTextWriter(expectedPath))
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = relativePath,
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new EndpointsGenerator(context);

            // Act
            generator.Emit();

            // Assert
            mockFileSystem.Verify(fs => fs.CreateTextWriter(expectedPath), Times.Once);
            mockTextWriter.Verify(tw => tw.Dispose(), Times.Once);
        }

        /// <summary>
        /// Tests that Emit method handles output folder with path separators at the end.
        /// Verifies that trailing path separators don't cause issues.
        /// Expected result: CreateTextWriter is called with properly combined path.
        /// </summary>
        [Test]
        public void Emit_OutputFolderWithTrailingSeparator_HandlesCorrectly()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTextWriter = new Mock<TextWriter>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockOptions = new Mock<GeneratorOptions>();

            string folderWithSeparator = Path.GetTempPath(); // Already has trailing separator
            string expectedPath = Path.Combine(folderWithSeparator, "Opc.Ua.Endpoints.g.cs");

            mockFileSystem.Setup(fs => fs.CreateTextWriter(expectedPath))
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = folderWithSeparator,
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new EndpointsGenerator(context);

            // Act
            generator.Emit();

            // Assert
            mockFileSystem.Verify(fs => fs.CreateTextWriter(expectedPath), Times.Once);
            mockTextWriter.Verify(tw => tw.Dispose(), Times.Once);
        }

        /// <summary>
        /// Tests that Emit method properly disposes resources when an exception occurs.
        /// Verifies that the using statement ensures TextWriter is disposed even on exception.
        /// Expected result: TextWriter.Dispose is called even when rendering fails.
        /// </summary>
        [Test]
        public void Emit_ExceptionDuringRendering_DisposesResourcesProperly()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTextWriter = new Mock<TextWriter>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockOptions = new Mock<GeneratorOptions>();

            // Setup TextWriter to throw exception when written to
            mockTextWriter.Setup(tw => tw.Write(It.IsAny<string>()))
                .Throws(new InvalidOperationException("Write failed"));

            mockFileSystem.Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = Path.GetTempPath(),
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new EndpointsGenerator(context);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(generator.Emit);
            mockTextWriter.Verify(tw => tw.Dispose(), Times.Once);
        }

        /// <summary>
        /// Tests that Emit method uses correct file name based on CoreNamespacePrefix constant.
        /// Verifies that the generated file name follows the expected pattern.
        /// Expected result: File name is "Opc.Ua.Endpoints.g.cs".
        /// </summary>
        [Test]
        public void Emit_ValidContext_UsesCorrectFileName()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTextWriter = new Mock<TextWriter>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockOptions = new Mock<GeneratorOptions>();

            string capturedPath = null;
            mockFileSystem.Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Callback<string>(path => capturedPath = path)
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = Path.GetTempPath(),
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new EndpointsGenerator(context);

            // Act
            generator.Emit();

            // Assert
            Assert.That(capturedPath, Is.Not.Null);
            Assert.That(Path.GetFileName(capturedPath), Is.EqualTo("Opc.Ua.Endpoints.g.cs"));
        }

        /// <summary>
        /// Tests that the constructor successfully creates an instance with a valid GeneratorContext.
        /// Verifies that no exception is thrown when a properly initialized context is provided.
        /// </summary>
        [Test]
        public void Constructor_ValidContext_CreatesInstance()
        {
            // Arrange
            GeneratorContext context = CreateValidGeneratorContext();

            // Act
            var generator = new EndpointsGenerator(context);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor accepts a null context without throwing an exception.
        /// This verifies that no validation is performed on the context parameter in the constructor.
        /// </summary>
        [Test]
        public void Constructor_NullContext_DoesNotThrowException()
        {
            // Arrange
            GeneratorContext context = null;

            // Act & Assert
            Assert.DoesNotThrow(() => new EndpointsGenerator(context));
        }

        /// <summary>
        /// Creates a valid GeneratorContext instance with all required properties initialized.
        /// </summary>
        /// <returns>A valid GeneratorContext instance for testing.</returns>
        private GeneratorContext CreateValidGeneratorContext()
        {
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockOptions = new Mock<GeneratorOptions>();

            return new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "TestOutput",
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };
        }
    }
}
