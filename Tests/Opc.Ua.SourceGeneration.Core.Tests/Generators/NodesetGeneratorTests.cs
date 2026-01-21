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
    /// Unit tests for the NodesetGenerator class.
    /// </summary>
    [TestFixture]
    [Category("Generator")]
    [SetCulture("en-us")]
    [SetUICulture("en-us")]
    [Parallelizable]
    public class NodesetGeneratorTests
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
            _mockModelDesign.Setup(m => m.Nodes).Returns([]);
            _mockModelDesign.Setup(m => m.NamespaceUris).Returns(new NamespaceTable());
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
            Assert.Throws<ArgumentNullException>(() => new NodesetGenerator(context));
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
            var generator = new NodesetGenerator(_context);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that constructor creates instance with useXmlInitializers flag set to true.
        /// </summary>
        [Test]
        public void Constructor_WithUseXmlInitializersTrue_CreatesInstance()
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
            var generator = new NodesetGenerator(_context, useXmlInitializers: true);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that constructor creates instance with embedNodeset flag set to true.
        /// </summary>
        [Test]
        public void Constructor_WithEmbedNodesetTrue_CreatesInstance()
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
            var generator = new NodesetGenerator(_context, embedNodeset: true);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that constructor creates instance with both flags set to true.
        /// </summary>
        [Test]
        public void Constructor_WithBothFlagsTrue_CreatesInstance()
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
            var generator = new NodesetGenerator(_context, useXmlInitializers: true, embedNodeset: true);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that Emit creates files with no nodes.
        /// </summary>
        [Test]
        public void Emit_NoNodes_CreatesFiles()
        {
            // Arrange
            _mockFileSystem.Setup(fs => fs.OpenWrite(It.IsAny<string>()))
                .Returns(() => new MemoryStream());

            _context = new GeneratorContext
            {
                FileSystem = _mockFileSystem.Object,
                OutputFolder = "C:\\output",
                ModelDesign = _mockModelDesign.Object,
                Telemetry = _mockTelemetry.Object,
                Options = new GeneratorOptions()
            };

            var generator = new NodesetGenerator(_context);

            // Act
            generator.Emit();

            // Assert - OpenWrite should be called at least once for the nodeset file
            _mockFileSystem.Verify(fs => fs.OpenWrite(It.IsAny<string>()), Times.AtLeastOnce);
        }
    }
}
