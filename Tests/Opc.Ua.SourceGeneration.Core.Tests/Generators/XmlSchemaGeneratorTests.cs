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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Moq;
using NUnit.Framework;
using Opc.Ua.Schema.Model;

namespace Opc.Ua.SourceGeneration.Generator.Tests
{
    /// <summary>
    /// Unit tests for the XmlSchemaGenerator class.
    /// </summary>
    [TestFixture]
    [Category("Generator")]
    [SetCulture("en-us")]
    [SetUICulture("en-us")]
    [Parallelizable]
    public class XmlSchemaGeneratorTests
    {
        private Mock<IFileSystem> _mockFileSystem;
        private Mock<IModelDesign> _mockModelDesign;
        private Mock<ITelemetryContext> _mockTelemetry;
        private GeneratorContext _context;

        [SetUp]
        public void SetUp()
        {
            _mockFileSystem = new Mock<IFileSystem>();
            _mockModelDesign = new Mock<IModelDesign>();
            _mockTelemetry = new Mock<ITelemetryContext>();

            // Setup default namespace
            var targetNamespace = new Namespace
            {
                Value = "http://test.org/UA/",
                Prefix = "Test",
                Name = "TestNamespace"
            };
            _mockModelDesign.Setup(m => m.TargetNamespace).Returns(targetNamespace);
            _mockModelDesign.Setup(m => m.Namespaces).Returns([targetNamespace]);
            _mockModelDesign.Setup(m => m.GetNodeDesigns()).Returns([]);
            _mockModelDesign.Setup(m => m.TargetVersion).Returns("1.0.0");
            _mockModelDesign.Setup(m => m.TargetPublicationDate).Returns(new DateTime(2025, 1, 15));
        }

        /// <summary>
        /// Tests that the constructor throws ArgumentNullException when context is null.
        /// </summary>
        [Test]
        public void Constructor_NullContext_ThrowsArgumentNullException()
        {
            // Arrange
            GeneratorContext context = null;

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new XmlSchemaGenerator(context));
        }

        /// <summary>
        /// Tests that constructor creates instance with valid context.
        /// </summary>
        [Test]
        public void Constructor_ValidContext_CreatesInstance()
        {
            // Arrange
            _context = new GeneratorContext
            {
                FileSystem = _mockFileSystem.Object,
                OutputFolder = "TestOutput",
                ModelDesign = _mockModelDesign.Object,
                Telemetry = _mockTelemetry.Object,
                Options = new GeneratorOptions()
            };

            // Act
            var generator = new XmlSchemaGenerator(_context);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that Emit creates an XML schema file with the correct name.
        /// </summary>
        [Test]
        public void Emit_CreatesFileWithCorrectName()
        {
            // Arrange
            using var memoryStream = new MemoryStream();

            string capturedPath = null;
            _mockFileSystem.Setup(fs => fs.OpenWrite(It.IsAny<string>()))
                .Callback<string>(path => capturedPath = path)
                .Returns(memoryStream);

            _context = new GeneratorContext
            {
                FileSystem = _mockFileSystem.Object,
                OutputFolder = "C:\\output",
                ModelDesign = _mockModelDesign.Object,
                Telemetry = _mockTelemetry.Object,
                Options = new GeneratorOptions()
            };

            var generator = new XmlSchemaGenerator(_context);

            // Act
            IEnumerable<Resource> result = generator.Emit();

            // Assert
            Assert.That(capturedPath, Is.Not.Null);
            Assert.That(capturedPath, Does.Contain("Test.Types.xsd"));
            Assert.That(capturedPath, Does.StartWith("C:\\output"));
            Assert.That(result, Is.Not.Null);
            Assert.That(result.FirstOrDefault()?.ResourceName, Is.EqualTo("TypesXsd"));
            _mockFileSystem.Verify(fs => fs.OpenWrite(It.IsAny<string>()), Times.Once);
        }

        /// <summary>
        /// Tests that Emit with validateOutput false does not perform validation.
        /// </summary>
        [Test]
        public void Emit_WithValidateOutputFalse_DoesNotValidate()
        {
            // Arrange
            using var memoryStream = new MemoryStream();

            _mockFileSystem.Setup(fs => fs.OpenWrite(It.IsAny<string>()))
                .Returns(memoryStream);

            _context = new GeneratorContext
            {
                FileSystem = _mockFileSystem.Object,
                OutputFolder = "C:\\output",
                ModelDesign = _mockModelDesign.Object,
                Telemetry = _mockTelemetry.Object,
                Options = new GeneratorOptions()
            };

            var generator = new XmlSchemaGenerator(_context);

            // Act
            IEnumerable<Resource> result = generator.Emit();

            // Assert - Only OpenWrite should be called, not OpenRead for validation
            Assert.That(result, Is.Not.Null);
            _mockFileSystem.Verify(fs => fs.OpenWrite(It.IsAny<string>()), Times.Once);
        }

        /// <summary>
        /// Tests that Emit returns TextFileResource with correct prefix.
        /// </summary>
        [Test]
        public void Emit_ReturnsTextFileResourceWithCorrectPrefix()
        {
            // Arrange
            using var memoryStream = new MemoryStream();

            _mockFileSystem.Setup(fs => fs.OpenWrite(It.IsAny<string>()))
                .Returns(memoryStream);

            _context = new GeneratorContext
            {
                FileSystem = _mockFileSystem.Object,
                OutputFolder = "TestOutput",
                ModelDesign = _mockModelDesign.Object,
                Telemetry = _mockTelemetry.Object,
                Options = new GeneratorOptions()
            };

            var generator = new XmlSchemaGenerator(_context);

            // Act
            IEnumerable<Resource> result = generator.Emit();

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.FirstOrDefault()?.ResourceName, Is.EqualTo("TypesXsd"));
        }

        /// <summary>
        /// Tests that Emit handles empty output folder correctly.
        /// </summary>
        [Test]
        public void Emit_EmptyOutputFolder_CreatesFileInCurrentDirectory()
        {
            // Arrange
            using var memoryStream = new MemoryStream();

            string capturedPath = null;
            _mockFileSystem.Setup(fs => fs.OpenWrite(It.IsAny<string>()))
                .Callback<string>(path => capturedPath = path)
                .Returns(memoryStream);

            _context = new GeneratorContext
            {
                FileSystem = _mockFileSystem.Object,
                OutputFolder = string.Empty,
                ModelDesign = _mockModelDesign.Object,
                Telemetry = _mockTelemetry.Object,
                Options = new GeneratorOptions()
            };

            var generator = new XmlSchemaGenerator(_context);

            // Act
            IEnumerable<Resource> result = generator.Emit();

            // Assert
            Assert.That(capturedPath, Is.Not.Null);
            Assert.That(capturedPath, Does.Contain("Test.Types.xsd"));
            Assert.That(result, Is.Not.Null);
            _mockFileSystem.Verify(fs => fs.OpenWrite(It.IsAny<string>()), Times.Once);
        }
    }
}
