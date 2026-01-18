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

using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using Opc.Ua.Schema.Model;
using System;

namespace Opc.Ua.SourceGeneration.Generator.Tests
{
    /// <summary>
    /// Unit tests for the <see cref = "NodesetGenerator"/> class.
    /// </summary>
    [TestFixture]
    public sealed class NodesetGeneratorTests
    {
        /// <summary>
        /// Tests that the constructor successfully creates an instance with valid context and default parameters.
        /// Input: Valid GeneratorContext with useXmlInitializers and embedNodeset both defaulting to false.
        /// Expected: Instance is created successfully without throwing any exceptions, and CreateLogger is invoked.
        /// </summary>
        [Test]
        public void Constructor_ValidContextWithDefaults_CreatesInstance()
        {
            // Arrange
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockLoggerFactory = new Mock<ILoggerFactory>();
            var mockLogger = new Mock<ILogger<NodesetGenerator>>();
            mockTelemetry.Setup(t => t.GetLoggerFactory()).Returns(mockLoggerFactory.Object);
            mockLoggerFactory.Setup(f => f.CreateLogger(It.IsAny<string>())).Returns(mockLogger.Object);
            var context = new GeneratorContext
            {
                FileSystem = Mock.Of<IFileSystem>(),
                OutputFolder = "output",
                Validator = Mock.Of<ModelDesignValidator>(),
                Telemetry = mockTelemetry.Object,
                Options = Mock.Of<GeneratorOptions>()
            };
            // Act
            var generator = new NodesetGenerator(context);
            // Assert
            Assert.That(generator, Is.Not.Null);
            mockTelemetry.Verify(t => t.GetLoggerFactory(), Times.Once);
        }

        /// <summary>
        /// Tests that the constructor successfully creates an instance with useXmlInitializers set to true.
        /// Input: Valid GeneratorContext with useXmlInitializers = true, embedNodeset = false (default).
        /// Expected: Instance is created successfully without throwing any exceptions.
        /// </summary>
        [Test]
        public void Constructor_UseXmlInitializersTrue_CreatesInstance()
        {
            // Arrange
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockLoggerFactory = new Mock<ILoggerFactory>();
            var mockLogger = new Mock<ILogger<NodesetGenerator>>();
            mockTelemetry.Setup(t => t.GetLoggerFactory()).Returns(mockLoggerFactory.Object);
            mockLoggerFactory.Setup(f => f.CreateLogger(It.IsAny<string>())).Returns(mockLogger.Object);
            var context = new GeneratorContext
            {
                FileSystem = Mock.Of<IFileSystem>(),
                OutputFolder = "output",
                Validator = Mock.Of<ModelDesignValidator>(),
                Telemetry = mockTelemetry.Object,
                Options = Mock.Of<GeneratorOptions>()
            };
            // Act
            var generator = new NodesetGenerator(context, useXmlInitializers: true);
            // Assert
            Assert.That(generator, Is.Not.Null);
            mockTelemetry.Verify(t => t.GetLoggerFactory(), Times.Once);
        }

        /// <summary>
        /// Tests that the constructor successfully creates an instance with embedNodeset set to true.
        /// Input: Valid GeneratorContext with useXmlInitializers = false (default), embedNodeset = true.
        /// Expected: Instance is created successfully without throwing any exceptions.
        /// </summary>
        [Test]
        public void Constructor_EmbedNodesetTrue_CreatesInstance()
        {
            // Arrange
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockLoggerFactory = new Mock<ILoggerFactory>();
            var mockLogger = new Mock<ILogger<NodesetGenerator>>();
            mockTelemetry.Setup(t => t.GetLoggerFactory()).Returns(mockLoggerFactory.Object);
            mockLoggerFactory.Setup(f => f.CreateLogger(It.IsAny<string>())).Returns(mockLogger.Object);
            var context = new GeneratorContext
            {
                FileSystem = Mock.Of<IFileSystem>(),
                OutputFolder = "output",
                Validator = Mock.Of<ModelDesignValidator>(),
                Telemetry = mockTelemetry.Object,
                Options = Mock.Of<GeneratorOptions>()
            };
            // Act
            var generator = new NodesetGenerator(context, embedNodeset: true);
            // Assert
            Assert.That(generator, Is.Not.Null);
            mockTelemetry.Verify(t => t.GetLoggerFactory(), Times.Once);
        }

        /// <summary>
        /// Tests that the constructor successfully creates an instance with both flags set to true.
        /// Input: Valid GeneratorContext with useXmlInitializers = true and embedNodeset = true.
        /// Expected: Instance is created successfully without throwing any exceptions.
        /// </summary>
        [Test]
        public void Constructor_BothFlagsTrue_CreatesInstance()
        {
            // Arrange
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockLoggerFactory = new Mock<ILoggerFactory>();
            var mockLogger = new Mock<ILogger<NodesetGenerator>>();
            mockTelemetry.Setup(t => t.GetLoggerFactory()).Returns(mockLoggerFactory.Object);
            mockLoggerFactory.Setup(f => f.CreateLogger(It.IsAny<string>())).Returns(mockLogger.Object);
            var context = new GeneratorContext
            {
                FileSystem = Mock.Of<IFileSystem>(),
                OutputFolder = "output",
                Validator = Mock.Of<ModelDesignValidator>(),
                Telemetry = mockTelemetry.Object,
                Options = Mock.Of<GeneratorOptions>()
            };
            // Act
            var generator = new NodesetGenerator(context, useXmlInitializers: true, embedNodeset: true);
            // Assert
            Assert.That(generator, Is.Not.Null);
            mockTelemetry.Verify(t => t.GetLoggerFactory(), Times.Once);
        }

        /// <summary>
        /// Tests that the constructor successfully creates an instance with both flags set to false explicitly.
        /// Input: Valid GeneratorContext with useXmlInitializers = false and embedNodeset = false.
        /// Expected: Instance is created successfully without throwing any exceptions.
        /// </summary>
        [Test]
        public void Constructor_BothFlagsFalse_CreatesInstance()
        {
            // Arrange
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockLoggerFactory = new Mock<ILoggerFactory>();
            var mockLogger = new Mock<ILogger<NodesetGenerator>>();
            mockTelemetry.Setup(t => t.GetLoggerFactory()).Returns(mockLoggerFactory.Object);
            mockLoggerFactory.Setup(f => f.CreateLogger(It.IsAny<string>())).Returns(mockLogger.Object);
            var context = new GeneratorContext
            {
                FileSystem = Mock.Of<IFileSystem>(),
                OutputFolder = "output",
                Validator = Mock.Of<ModelDesignValidator>(),
                Telemetry = mockTelemetry.Object,
                Options = Mock.Of<GeneratorOptions>()
            };
            // Act
            var generator = new NodesetGenerator(context, useXmlInitializers: false, embedNodeset: false);
            // Assert
            Assert.That(generator, Is.Not.Null);
            mockTelemetry.Verify(t => t.GetLoggerFactory(), Times.Once);
        }

        /// <summary>
        /// Tests that the constructor throws NullReferenceException when context is null.
        /// Input: Null GeneratorContext.
        /// Expected: NullReferenceException is thrown when attempting to access the Telemetry property.
        /// </summary>
        [Test]
        public void Constructor_NullContext_ThrowsNullReferenceException()
        {
            // Arrange
            GeneratorContext context = null;
            // Act & Assert
            Assert.Throws<NullReferenceException>(() => new NodesetGenerator(context));
        }

        /// <summary>
        /// Tests that the constructor throws NullReferenceException when context is null with explicit parameters.
        /// Input: Null GeneratorContext with useXmlInitializers = true and embedNodeset = true.
        /// Expected: NullReferenceException is thrown when attempting to access the Telemetry property.
        /// </summary>
        [Test]
        public void Constructor_NullContextWithParameters_ThrowsNullReferenceException()
        {
            // Arrange
            GeneratorContext context = null;
            // Act & Assert
            Assert.Throws<NullReferenceException>(() => new NodesetGenerator(context, useXmlInitializers: true, embedNodeset: true));
        }

        /// <summary>
        /// Tests that the constructor throws when Telemetry property is null.
        /// Input: GeneratorContext with null Telemetry property.
        /// Expected: NullReferenceException is thrown when attempting to access Telemetry.GetLoggerFactory().
        /// </summary>
        [Test]
        public void Constructor_NullTelemetry_ThrowsNullReferenceException()
        {
            // Arrange
            var context = new GeneratorContext
            {
                FileSystem = Mock.Of<IFileSystem>(),
                OutputFolder = "output",
                Validator = Mock.Of<ModelDesignValidator>(),
                Telemetry = null,
                Options = Mock.Of<GeneratorOptions>()
            };
            // Act & Assert
            Assert.Throws<NullReferenceException>(() => new NodesetGenerator(context));
        }
    }
}
