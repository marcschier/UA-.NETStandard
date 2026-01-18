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

using System.Collections.Generic;
using System.IO;
using System.Xml;
using Moq;
using NUnit.Framework;
using Opc.Ua.Schema.Model;

namespace Opc.Ua.SourceGeneration.Generator.Tests
{
    /// <summary>
    /// Unit tests for the <see cref="ConstantsGenerator"/> class.
    /// </summary>
    [TestFixture]
    public class ConstantsGeneratorTests
    {
        /// <summary>
        /// Tests that the constructor successfully creates an instance when provided with a valid GeneratorContext.
        /// Verifies that the constructor accepts a non-null context and completes without throwing an exception.
        /// Expected result: ConstantsGenerator instance is created successfully.
        /// </summary>
        [Test]
        public void Constructor_ValidGeneratorContext_CreatesInstance()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockOptions = new Mock<GeneratorOptions>();

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "output",
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            // Act
            var generator = new ConstantsGenerator(context);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor accepts a null GeneratorContext without throwing an exception.
        /// This documents that the constructor does not validate the context parameter for null.
        /// Expected result: ConstantsGenerator instance is created without throwing.
        /// </summary>
        [Test]
        public void Constructor_NullGeneratorContext_CreatesInstance()
        {
            // Arrange
            GeneratorContext context = null;

            // Act
            var generator = new ConstantsGenerator(context);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that Emit returns early when GetNodeDesigns returns an empty collection.
        /// No file should be created or template rendered.
        /// </summary>
        [Test]
        public void Emit_EmptyNodeDesigns_ReturnsEarlyWithoutCreatingFile()
        {
            // Arrange
            GeneratorContext mockContext = CreateMockGeneratorContext();
            var mockValidator = Mock.Get(mockContext.Validator);
            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(new List<NodeDesign>());

            var generator = new ConstantsGenerator(mockContext);

            // Act
            generator.Emit();

            // Assert
            Mock.Get(mockContext.FileSystem).Verify(
                fs => fs.CreateTextWriter(It.IsAny<string>()),
                Times.Never,
                "CreateTextWriter should not be called when there are no node designs");
        }

        /// <summary>
        /// Tests that Emit returns early when CollectBrowseNames produces no browse names.
        /// No file should be created or template rendered.
        /// </summary>
        [Test]
        public void Emit_NodeDesignsWithNoBrowseNames_ReturnsEarlyWithoutCreatingFile()
        {
            // Arrange
            GeneratorContext mockContext = CreateMockGeneratorContext();
            var mockValidator = Mock.Get(mockContext.Validator);
            NodeDesign mockNodeDesign = CreateMockNodeDesign("ExcludedNode", "http://different.namespace.com");
            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(new List<NodeDesign> { mockNodeDesign });
            mockValidator.Setup(v => v.IsExcluded(mockNodeDesign)).Returns(false);

            var generator = new ConstantsGenerator(mockContext);

            // Act
            generator.Emit();

            // Assert
            Mock.Get(mockContext.FileSystem).Verify(
                fs => fs.CreateTextWriter(It.IsAny<string>()),
                Times.Never,
                "CreateTextWriter should not be called when browse names count is zero");
        }

        /// <summary>
        /// Tests that Emit successfully creates file and renders template when valid browse names exist.
        /// Verifies the complete execution path including file creation and template rendering.
        /// </summary>
        [Test]
        public void Emit_ValidBrowseNames_CreatesFileAndRendersTemplate()
        {
            // Arrange
            GeneratorContext mockContext = CreateMockGeneratorContext();
            var mockValidator = Mock.Get(mockContext.Validator);
            NodeDesign mockNodeDesign = CreateMockNodeDesign("TestNode", "http://test.namespace.com");
            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(new List<NodeDesign> { mockNodeDesign });
            mockValidator.Setup(v => v.IsExcluded(mockNodeDesign)).Returns(false);

            var mockTextWriter = new Mock<TextWriter>();
            Mock.Get(mockContext.FileSystem)
                .Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var generator = new ConstantsGenerator(mockContext);

            // Act
            generator.Emit();

            // Assert
            Mock.Get(mockContext.FileSystem).Verify(
                fs => fs.CreateTextWriter(It.Is<string>(path => path.Contains("TestPrefix.Constants.g.cs"))),
                Times.Once,
                "CreateTextWriter should be called once with correct file name");

            mockTextWriter.Verify(w => w.Dispose(), Times.Once, "TextWriter should be disposed");
        }

        /// <summary>
        /// Tests that Emit correctly formats the output file name using the target namespace prefix.
        /// Verifies that Path.Combine and Format are used correctly to construct the file path.
        /// </summary>
        [Test]
        public void Emit_ValidBrowseNames_CreatesFileWithCorrectPath()
        {
            // Arrange
            GeneratorContext mockContext = CreateMockGeneratorContext();
            var mockValidator = Mock.Get(mockContext.Validator);
            NodeDesign mockNodeDesign = CreateMockNodeDesign("TestNode", "http://test.namespace.com");
            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(new List<NodeDesign> { mockNodeDesign });
            mockValidator.Setup(v => v.IsExcluded(mockNodeDesign)).Returns(false);

            string expectedPath = Path.Combine("/output", "TestPrefix.Constants.g.cs");
            var mockTextWriter = new Mock<TextWriter>();
            Mock.Get(mockContext.FileSystem)
                .Setup(fs => fs.CreateTextWriter(expectedPath))
                .Returns(mockTextWriter.Object);

            var generator = new ConstantsGenerator(mockContext);

            // Act
            generator.Emit();

            // Assert
            Mock.Get(mockContext.FileSystem).Verify(
                fs => fs.CreateTextWriter(expectedPath),
                Times.Once,
                "CreateTextWriter should be called with the correctly formatted path");
        }

        /// <summary>
        /// Tests that Emit handles multiple node designs correctly.
        /// Verifies that CollectBrowseNames is called for each node design.
        /// </summary>
        [Test]
        public void Emit_MultipleNodeDesigns_ProcessesAllNodes()
        {
            // Arrange
            GeneratorContext mockContext = CreateMockGeneratorContext();
            var mockValidator = Mock.Get(mockContext.Validator);
            NodeDesign mockNodeDesign1 = CreateMockNodeDesign("TestNode1", "http://test.namespace.com");
            NodeDesign mockNodeDesign2 = CreateMockNodeDesign("TestNode2", "http://test.namespace.com");
            var nodeDesigns = new List<NodeDesign> { mockNodeDesign1, mockNodeDesign2 };
            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(nodeDesigns);
            mockValidator.Setup(v => v.IsExcluded(It.IsAny<NodeDesign>())).Returns(false);

            var mockTextWriter = new Mock<TextWriter>();
            Mock.Get(mockContext.FileSystem)
                .Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var generator = new ConstantsGenerator(mockContext);

            // Act
            generator.Emit();

            // Assert
            Mock.Get(mockContext.FileSystem).Verify(
                fs => fs.CreateTextWriter(It.IsAny<string>()),
                Times.Once,
                "File should be created when multiple valid node designs exist");
        }

        /// <summary>
        /// Tests that Emit correctly disposes resources when an exception occurs during template rendering.
        /// Verifies that TextWriter is disposed even when an exception is thrown.
        /// </summary>
        [Test]
        public void Emit_ExceptionDuringRendering_DisposesResourcesProperly()
        {
            // Arrange
            GeneratorContext mockContext = CreateMockGeneratorContext();
            var mockValidator = Mock.Get(mockContext.Validator);
            NodeDesign mockNodeDesign = CreateMockNodeDesign("TestNode", "http://test.namespace.com");
            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(new List<NodeDesign> { mockNodeDesign });
            mockValidator.Setup(v => v.IsExcluded(mockNodeDesign)).Returns(false);

            var mockTextWriter = new Mock<TextWriter>();
            Mock.Get(mockContext.FileSystem)
                .Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var generator = new ConstantsGenerator(mockContext);

            // Act & Assert
            Assert.DoesNotThrow(generator.Emit, "Emit should handle exceptions gracefully");

            mockTextWriter.Verify(w => w.Dispose(), Times.Once, "TextWriter should be disposed even if exceptions occur");
        }

        /// <summary>
        /// Tests that Emit handles null OutputFolder gracefully.
        /// Verifies that null output folder doesn't cause null reference exceptions.
        /// </summary>
        [Test]
        public void Emit_NullOutputFolder_HandlesGracefully()
        {
            // Arrange
            GeneratorContext mockContext = CreateMockGeneratorContext(outputFolder: null);
            var mockValidator = Mock.Get(mockContext.Validator);
            NodeDesign mockNodeDesign = CreateMockNodeDesign("TestNode", "http://test.namespace.com");
            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(new List<NodeDesign> { mockNodeDesign });
            mockValidator.Setup(v => v.IsExcluded(mockNodeDesign)).Returns(false);

            var mockTextWriter = new Mock<TextWriter>();
            Mock.Get(mockContext.FileSystem)
                .Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var generator = new ConstantsGenerator(mockContext);

            // Act & Assert
            Assert.DoesNotThrow(generator.Emit, "Emit should not throw with null output folder");
        }

        /// <summary>
        /// Tests that Emit handles empty string OutputFolder.
        /// Verifies proper handling of empty output folder path.
        /// </summary>
        [Test]
        public void Emit_EmptyOutputFolder_HandlesGracefully()
        {
            // Arrange
            GeneratorContext mockContext = CreateMockGeneratorContext(outputFolder: string.Empty);
            var mockValidator = Mock.Get(mockContext.Validator);
            NodeDesign mockNodeDesign = CreateMockNodeDesign("TestNode", "http://test.namespace.com");
            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(new List<NodeDesign> { mockNodeDesign });
            mockValidator.Setup(v => v.IsExcluded(mockNodeDesign)).Returns(false);

            var mockTextWriter = new Mock<TextWriter>();
            Mock.Get(mockContext.FileSystem)
                .Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var generator = new ConstantsGenerator(mockContext);

            // Act & Assert
            Assert.DoesNotThrow(generator.Emit, "Emit should handle empty output folder");
        }

        /// <summary>
        /// Tests that Emit handles whitespace-only OutputFolder.
        /// Verifies proper handling of whitespace-only output folder path.
        /// </summary>
        [Test]
        public void Emit_WhitespaceOutputFolder_HandlesGracefully()
        {
            // Arrange
            GeneratorContext mockContext = CreateMockGeneratorContext(outputFolder: "   ");
            var mockValidator = Mock.Get(mockContext.Validator);
            NodeDesign mockNodeDesign = CreateMockNodeDesign("TestNode", "http://test.namespace.com");
            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(new List<NodeDesign> { mockNodeDesign });
            mockValidator.Setup(v => v.IsExcluded(mockNodeDesign)).Returns(false);

            var mockTextWriter = new Mock<TextWriter>();
            Mock.Get(mockContext.FileSystem)
                .Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var generator = new ConstantsGenerator(mockContext);

            // Act & Assert
            Assert.DoesNotThrow(generator.Emit, "Emit should handle whitespace output folder");
        }

        /// <summary>
        /// Tests that Emit handles very long OutputFolder paths.
        /// Verifies proper handling of extremely long path strings.
        /// </summary>
        [Test]
        public void Emit_VeryLongOutputFolder_HandlesGracefully()
        {
            // Arrange
            string longPath = new('a', 1000);
            GeneratorContext mockContext = CreateMockGeneratorContext(outputFolder: longPath);
            var mockValidator = Mock.Get(mockContext.Validator);
            NodeDesign mockNodeDesign = CreateMockNodeDesign("TestNode", "http://test.namespace.com");
            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(new List<NodeDesign> { mockNodeDesign });
            mockValidator.Setup(v => v.IsExcluded(mockNodeDesign)).Returns(false);

            var mockTextWriter = new Mock<TextWriter>();
            Mock.Get(mockContext.FileSystem)
                .Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var generator = new ConstantsGenerator(mockContext);

            // Act & Assert
            Assert.DoesNotThrow(generator.Emit, "Emit should handle very long output folder paths");
        }

        /// <summary>
        /// Tests that Emit handles OutputFolder with special characters.
        /// Verifies proper handling of paths with special characters.
        /// </summary>
        [Test]
        public void Emit_OutputFolderWithSpecialCharacters_HandlesGracefully()
        {
            // Arrange
            GeneratorContext mockContext = CreateMockGeneratorContext(outputFolder: "/path/with/special:chars*?");
            var mockValidator = Mock.Get(mockContext.Validator);
            NodeDesign mockNodeDesign = CreateMockNodeDesign("TestNode", "http://test.namespace.com");
            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(new List<NodeDesign> { mockNodeDesign });
            mockValidator.Setup(v => v.IsExcluded(mockNodeDesign)).Returns(false);

            var mockTextWriter = new Mock<TextWriter>();
            Mock.Get(mockContext.FileSystem)
                .Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var generator = new ConstantsGenerator(mockContext);

            // Act & Assert
            Assert.DoesNotThrow(generator.Emit, "Emit should handle output folder with special characters");
        }

        /// <summary>
        /// Tests that Emit handles null TargetNamespaceInfo.Prefix gracefully.
        /// Verifies proper handling when prefix is null.
        /// </summary>
        [Test]
        public void Emit_NullPrefix_HandlesGracefully()
        {
            // Arrange
            GeneratorContext mockContext = CreateMockGeneratorContext(prefix: null);
            var mockValidator = Mock.Get(mockContext.Validator);
            NodeDesign mockNodeDesign = CreateMockNodeDesign("TestNode", "http://test.namespace.com");
            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(new List<NodeDesign> { mockNodeDesign });
            mockValidator.Setup(v => v.IsExcluded(mockNodeDesign)).Returns(false);

            var mockTextWriter = new Mock<TextWriter>();
            Mock.Get(mockContext.FileSystem)
                .Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var generator = new ConstantsGenerator(mockContext);

            // Act & Assert
            Assert.DoesNotThrow(generator.Emit, "Emit should handle null prefix");
        }

        /// <summary>
        /// Tests that Emit handles empty string TargetNamespaceInfo.Prefix.
        /// Verifies proper handling when prefix is an empty string.
        /// </summary>
        [Test]
        public void Emit_EmptyPrefix_HandlesGracefully()
        {
            // Arrange
            GeneratorContext mockContext = CreateMockGeneratorContext(prefix: string.Empty);
            var mockValidator = Mock.Get(mockContext.Validator);
            NodeDesign mockNodeDesign = CreateMockNodeDesign("TestNode", "http://test.namespace.com");
            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(new List<NodeDesign> { mockNodeDesign });
            mockValidator.Setup(v => v.IsExcluded(mockNodeDesign)).Returns(false);

            var mockTextWriter = new Mock<TextWriter>();
            Mock.Get(mockContext.FileSystem)
                .Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var generator = new ConstantsGenerator(mockContext);

            // Act & Assert
            Assert.DoesNotThrow(generator.Emit, "Emit should handle empty prefix");
        }

        /// <summary>
        /// Tests that Emit handles empty Namespaces array.
        /// Verifies proper handling when namespaces array is empty.
        /// </summary>
        [Test]
        public void Emit_EmptyNamespacesArray_HandlesGracefully()
        {
            // Arrange
            GeneratorContext mockContext = CreateMockGeneratorContext(namespacesArray: []);
            var mockValidator = Mock.Get(mockContext.Validator);
            NodeDesign mockNodeDesign = CreateMockNodeDesign("TestNode", "http://test.namespace.com");
            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(new List<NodeDesign> { mockNodeDesign });
            mockValidator.Setup(v => v.IsExcluded(mockNodeDesign)).Returns(false);

            var mockTextWriter = new Mock<TextWriter>();
            Mock.Get(mockContext.FileSystem)
                .Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var generator = new ConstantsGenerator(mockContext);

            // Act & Assert
            Assert.DoesNotThrow(generator.Emit, "Emit should handle empty namespaces array");
        }

        private GeneratorContext CreateMockGeneratorContext(
            string outputFolder = "/output",
            string prefix = "TestPrefix",
            Namespace[] namespacesArray = null)
        {
            var mockFileSystem = new Mock<IFileSystem>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockDictionary = new Mock<ModelDesign>();
            var mockTargetNamespaceInfo = new Mock<Namespace>();

            mockTargetNamespaceInfo.SetupGet(t => t.Prefix).Returns(prefix);
            mockTargetNamespaceInfo.SetupGet(t => t.Name).Returns("TestNamespace");
            mockTargetNamespaceInfo.SetupGet(t => t.Value).Returns("http://test.namespace.com");

            if (namespacesArray == null)
            {
                var mockNamespace = new Mock<Namespace>();
                mockNamespace.SetupGet(n => n.Value).Returns("http://test.namespace.com");
                mockNamespace.SetupGet(n => n.Prefix).Returns(prefix);
                mockNamespace.SetupGet(n => n.Name).Returns("TestNamespace");
                namespacesArray = [mockNamespace.Object];
            }

            mockDictionary.SetupGet(d => d.TargetNamespaceInfo).Returns(mockTargetNamespaceInfo.Object);
            mockDictionary.SetupGet(d => d.Namespaces).Returns(namespacesArray);
            mockDictionary.SetupGet(d => d.TargetNamespace).Returns("http://test.namespace.com");

            mockValidator.SetupGet(v => v.Dictionary).Returns(mockDictionary.Object);

            var mockContext = new Mock<GeneratorContext>();
            mockContext.SetupGet(c => c.FileSystem).Returns(mockFileSystem.Object);
            mockContext.SetupGet(c => c.Validator).Returns(mockValidator.Object);
            mockContext.SetupGet(c => c.OutputFolder).Returns(outputFolder);

            return mockContext.Object;
        }

        private NodeDesign CreateMockNodeDesign(string name, string namespaceUri)
        {
            var mockNodeDesign = new Mock<NodeDesign>();
            var symbolicName = new XmlQualifiedName(name, namespaceUri);
            mockNodeDesign.SetupGet(n => n.SymbolicName).Returns(symbolicName);
            mockNodeDesign.SetupGet(n => n.BrowseName).Returns(name);
            mockNodeDesign.SetupGet(n => n.HasChildren).Returns(false);
            return mockNodeDesign.Object;
        }
    }
}
