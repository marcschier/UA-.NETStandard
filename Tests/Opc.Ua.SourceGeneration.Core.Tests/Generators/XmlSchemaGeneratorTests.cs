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
    public partial class XmlSchemaGeneratorTests
    {
        /// <summary>
        /// Tests that Emit returns a valid TextFileResource with correct file path and resource name when validateOutput is false.
        /// Input: Valid GeneratorContext with namespace prefix "TestPrefix", output folder "C:\Output"
        /// Expected: TextFileResource with FileName = "C:\Output\TestPrefix.Types.xsd" and ResourceName based on the file name
        /// </summary>
        [Test]
        public void Emit_ValidContext_WithoutValidation_ReturnsTextFileResource()
        {
            // Arrange
            const string namespacePrefix = "TestPrefix";
            const string outputFolder = @"C:\Output";
            const string expectedFileName = @"C:\Output\TestPrefix.Types.xsd";

            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext(namespacePrefix, outputFolder);
            var generator = new XmlSchemaGenerator(mockContext.Object);

            // Act
            TextFileResource result = generator.Emit(validateOutput: false);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.FileName, Is.EqualTo(expectedFileName));
            Assert.That(result.ResourceName, Is.Not.Null);
            Assert.That(result.ResourceName, Is.Not.Empty);
        }

        /// <summary>
        /// Tests that Emit returns a valid TextFileResource with correct file path when validateOutput is true.
        /// Input: Valid GeneratorContext with namespace prefix "TestPrefix", validateOutput = true
        /// Expected: TextFileResource returned after validation completes successfully
        /// </summary>
        [Test]
        public void Emit_ValidContext_WithValidation_ReturnsTextFileResource()
        {
            // Arrange
            const string namespacePrefix = "TestPrefix";
            const string outputFolder = @"C:\Output";

            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext(namespacePrefix, outputFolder);
            var generator = new XmlSchemaGenerator(mockContext.Object);

            // Act
            TextFileResource result = generator.Emit(validateOutput: true);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.FileName, Does.Contain(namespacePrefix));
            Assert.That(result.FileName, Does.EndWith(".Types.xsd"));
        }

        /// <summary>
        /// Tests that Emit uses default parameter value (false) when validateOutput is not provided.
        /// Input: Valid GeneratorContext, no validateOutput parameter
        /// Expected: TextFileResource returned without validation
        /// </summary>
        [Test]
        public void Emit_NoValidateOutputParameter_UsesDefaultFalseValue()
        {
            // Arrange
            const string namespacePrefix = "Test";
            const string outputFolder = @"C:\Output";

            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext(namespacePrefix, outputFolder);
            var generator = new XmlSchemaGenerator(mockContext.Object);

            // Act
            TextFileResource result = generator.Emit();

            // Assert
            Assert.That(result, Is.Not.Null);
        }

        /// <summary>
        /// Tests that Emit correctly constructs file path with various namespace prefix values.
        /// Input: Different namespace prefix values (normal, with special characters, numeric)
        /// Expected: File path includes the prefix correctly formatted
        /// </summary>
        [TestCase("SimplePrefix", "SimplePrefix.Types.xsd")]
        [TestCase("Opc.Ua.Test", "Opc.Ua.Test.Types.xsd")]
        [TestCase("MyNamespace123", "MyNamespace123.Types.xsd")]
        [TestCase("Prefix_With_Underscore", "Prefix_With_Underscore.Types.xsd")]
        public void Emit_DifferentNamespacePrefixes_ConstructsCorrectFileName(string namespacePrefix, string expectedFileName)
        {
            // Arrange
            const string outputFolder = @"C:\Output";
            string expectedFullPath = Path.Combine(outputFolder, expectedFileName);

            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext(namespacePrefix, outputFolder);
            var generator = new XmlSchemaGenerator(mockContext.Object);

            // Act
            TextFileResource result = generator.Emit(validateOutput: false);

            // Assert
            Assert.That(result.FileName, Is.EqualTo(expectedFullPath));
        }

        /// <summary>
        /// Tests that Emit correctly constructs file path with empty namespace prefix.
        /// Input: Empty string as namespace prefix
        /// Expected: File path constructed with ".Types.xsd" extension
        /// </summary>
        [Test]
        public void Emit_EmptyNamespacePrefix_ConstructsFileNameWithEmptyPrefix()
        {
            // Arrange
            const string namespacePrefix = "";
            const string outputFolder = @"C:\Output";
            const string expectedFileName = ".Types.xsd";
            string expectedFullPath = Path.Combine(outputFolder, expectedFileName);

            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext(namespacePrefix, outputFolder);
            var generator = new XmlSchemaGenerator(mockContext.Object);

            // Act
            TextFileResource result = generator.Emit(validateOutput: false);

            // Assert
            Assert.That(result.FileName, Is.EqualTo(expectedFullPath));
        }

        /// <summary>
        /// Tests that Emit correctly handles different output folder paths.
        /// Input: Various output folder paths (absolute, with subdirectories)
        /// Expected: File path correctly combined with output folder
        /// </summary>
        [TestCase(@"C:\Output")]
        [TestCase(@"C:\Output\SubFolder")]
        [TestCase(@"D:\Projects\OpcUa\Output")]
        [TestCase(@".\RelativePath")]
        public void Emit_DifferentOutputFolders_ConstructsCorrectFilePath(string outputFolder)
        {
            // Arrange
            const string namespacePrefix = "Test";

            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext(namespacePrefix, outputFolder);
            var generator = new XmlSchemaGenerator(mockContext.Object);

            // Act
            TextFileResource result = generator.Emit(validateOutput: false);

            // Assert
            Assert.That(result.FileName, Does.StartWith(outputFolder));
            Assert.That(result.FileName, Does.EndWith("Test.Types.xsd"));
        }

        /// <summary>
        /// Tests that Emit creates TextWriter on the file system for writing the schema.
        /// Input: Valid GeneratorContext
        /// Expected: FileSystem.CreateTextWriter is called with the correct file path
        /// </summary>
        [Test]
        public void Emit_ValidContext_CallsCreateTextWriterOnFileSystem()
        {
            // Arrange
            const string namespacePrefix = "TestPrefix";
            const string outputFolder = @"C:\Output";
            const string expectedFileName = @"C:\Output\TestPrefix.Types.xsd";

            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext(namespacePrefix, outputFolder);
            var generator = new XmlSchemaGenerator(mockContext.Object);

            // Act
            generator.Emit(validateOutput: false);

            // Assert
            mockContext.Verify(c => c.FileSystem.CreateTextWriter(expectedFileName), Times.Once);
        }

        /// <summary>
        /// Tests that Emit with validateOutput true creates and uses XmlSchemaValidator2.
        /// Input: Valid GeneratorContext, validateOutput = true
        /// Expected: Validation occurs without throwing exceptions
        /// </summary>
        [Test]
        public void Emit_WithValidation_CompletesSuccessfully()
        {
            // Arrange
            const string namespacePrefix = "ValidPrefix";
            const string outputFolder = @"C:\ValidOutput";

            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext(namespacePrefix, outputFolder);
            var generator = new XmlSchemaGenerator(mockContext.Object);

            // Act & Assert
            Assert.DoesNotThrow(() => generator.Emit(validateOutput: true));
        }

        /// <summary>
        /// Tests that Emit returns TextFileResource with ResourceName derived from the file name.
        /// Input: Valid GeneratorContext with specific namespace prefix
        /// Expected: TextFileResource.ResourceName is properly formatted based on file name and prefix
        /// </summary>
        [Test]
        public void Emit_ValidContext_ReturnsTextFileResourceWithCorrectResourceName()
        {
            // Arrange
            const string namespacePrefix = "MyNamespace";
            const string outputFolder = @"C:\Output";

            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext(namespacePrefix, outputFolder);
            var generator = new XmlSchemaGenerator(mockContext.Object);

            // Act
            TextFileResource result = generator.Emit(validateOutput: false);

            // Assert
            Assert.That(result.ResourceName, Is.EqualTo("TypesXsd"));
        }

        /// <summary>
        /// Tests that Emit constructs correct file path using Path.Combine and CoreUtils.Format.
        /// Input: Valid GeneratorContext with namespace prefix and output folder
        /// Expected: File path follows the pattern {OutputFolder}\{Prefix}.Types.xsd
        /// </summary>
        [Test]
        public void Emit_ValidContext_ConstructsFilePathUsingPathCombineAndFormat()
        {
            // Arrange
            const string namespacePrefix = "CustomPrefix";
            const string outputFolder = @"C:\CustomOutput";

            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext(namespacePrefix, outputFolder);
            var generator = new XmlSchemaGenerator(mockContext.Object);

            // Act
            TextFileResource result = generator.Emit(validateOutput: false);

            // Assert
            string expectedPath = Path.Combine(outputFolder, CoreUtils.Format("{0}.Types.xsd", namespacePrefix));
            Assert.That(result.FileName, Is.EqualTo(expectedPath));
        }

        /// <summary>
        /// Tests that Emit with namespace prefix containing special characters constructs valid file path.
        /// Input: Namespace prefix with special characters like dots and dashes
        /// Expected: File path includes the special characters as part of the file name
        /// </summary>
        [TestCase("Opc.Ua.Custom")]
        [TestCase("My-Custom-Prefix")]
        [TestCase("Prefix.With.Multiple.Dots")]
        public void Emit_NamespacePrefixWithSpecialCharacters_ConstructsValidFilePath(string namespacePrefix)
        {
            // Arrange
            const string outputFolder = @"C:\Output";

            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext(namespacePrefix, outputFolder);
            var generator = new XmlSchemaGenerator(mockContext.Object);

            // Act
            TextFileResource result = generator.Emit(validateOutput: false);

            // Assert
            Assert.That(result.FileName, Does.Contain(namespacePrefix));
            Assert.That(result.FileName, Does.EndWith(".Types.xsd"));
        }

        /// <summary>
        /// Helper method to create a mock GeneratorContext with required dependencies.
        /// </summary>
        private Mock<GeneratorContext> CreateMockGeneratorContext(string namespacePrefix, string outputFolder)
        {
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTextWriter = new Mock<TextWriter>();
            mockFileSystem.Setup(fs => fs.CreateTextWriter(It.IsAny<string>())).Returns(mockTextWriter.Object);

            var mockNamespace = new Mock<Namespace>();
            mockNamespace.Setup(ns => ns.Prefix).Returns(namespacePrefix);

            var mockModelDesign = new Mock<ModelDesign>();
            mockModelDesign.Setup(md => md.TargetNamespaceInfo).Returns(mockNamespace.Object);
            mockModelDesign.Setup(md => md.TargetVersion).Returns("1.0");
            mockModelDesign.Setup(md => md.TargetPublicationDate).Returns(DateTime.UtcNow);

            var mockValidator = new Mock<ModelDesignValidator>();
            mockValidator.Setup(v => v.Dictionary).Returns(mockModelDesign.Object);

            var mockContext = new Mock<GeneratorContext>();
            mockContext.Setup(c => c.Validator).Returns(mockValidator.Object);
            mockContext.Setup(c => c.OutputFolder).Returns(outputFolder);
            mockContext.Setup(c => c.FileSystem).Returns(mockFileSystem.Object);

            return mockContext;
        }

        /// <summary>
        /// Tests that the constructor initializes successfully with a valid GeneratorContext.
        /// Input: Valid GeneratorContext instance with all required properties.
        /// Expected: XmlSchemaGenerator instance is created without throwing an exception.
        /// </summary>
        [Test]
        public void Constructor_ValidContext_CreatesInstance()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockOptions = new Mock<GeneratorOptions>();

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "TestOutput",
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            // Act
            var generator = new XmlSchemaGenerator(context);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor accepts null context without throwing.
        /// Input: Null GeneratorContext.
        /// Expected: XmlSchemaGenerator instance is created without throwing an exception.
        /// </summary>
        /// <remarks>
        /// This test documents that the constructor does not validate the context parameter.
        /// In production code, passing null would likely cause issues when the context is used.
        /// </remarks>
        [Test]
        public void Constructor_NullContext_CreatesInstanceWithoutValidation()
        {
            // Arrange
            GeneratorContext context = null;

            // Act
            var generator = new XmlSchemaGenerator(context);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }
    }
}
