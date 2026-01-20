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
using Moq;
using NUnit.Framework;
using Opc.Ua.Schema.Model;

namespace Opc.Ua.SourceGeneration.Generator.Tests
{
    /// <summary>
    /// Unit tests for the DataTypeGenerator class.
    /// </summary>
    [TestFixture]
    [Category("Generator")]
    [SetCulture("en-us")]
    [SetUICulture("en-us")]
    [Parallelizable]
    public class DataTypeGeneratorTests
    {
        /// <summary>
        /// Tests that Emit returns early when no data types are available.
        /// Verifies that no file writer is created and no template rendering occurs when GetDataTypes returns an empty list.
        /// Expected: Method returns without creating any files or templates.
        /// </summary>
        [Test]
        public void Emit_NoDataTypes_ReturnsEarlyWithoutCreatingFiles()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
            var mockValidator = new Mock<ModelDesignValidator>(MockBehavior.Strict);
            var mockTelemetry = new Mock<ITelemetryContext>(MockBehavior.Strict);
            var mockOptions = new Mock<GeneratorOptions>(MockBehavior.Strict);

            mockValidator.Setup(v => v.GetNodeDesigns()).Returns([]);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "C:\\output",
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new DataTypeGenerator(context, false);

            // Act
            generator.Emit();

            // Assert
            mockFileSystem.Verify(fs => fs.CreateTextWriter(It.IsAny<string>()), Times.Never);
            mockValidator.Verify(v => v.GetNodeDesigns(), Times.Once);
        }

        /// <summary>
        /// Tests that Emit creates output file with correct filename when data types are available.
        /// Verifies that the filename is constructed using the target namespace prefix and proper format.
        /// Expected: File writer is created with correctly formatted filename.
        /// </summary>
        [Test]
        public void Emit_WithDataTypes_CreatesFileWithCorrectName()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
            var mockValidator = new Mock<ModelDesignValidator>(MockBehavior.Strict);
            var mockDictionary = new Mock<ModelDesign>(MockBehavior.Strict);
            var mockNamespaceInfo = new Mock<Namespace>(MockBehavior.Strict);
            var mockTelemetry = new Mock<ITelemetryContext>(MockBehavior.Strict);
            var mockOptions = new Mock<GeneratorOptions>(MockBehavior.Strict);
            var mockTextWriter = new Mock<TextWriter>(MockBehavior.Strict);

            var dataType = new Mock<DataTypeDesign>(MockBehavior.Strict);
            dataType.Setup(dt => dt.IsPartOfOpcUaTypesLibrary()).Returns(false);

            var nodeDesigns = new List<NodeDesign> { dataType.Object };
            Namespace[] namespaces = [];

            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(nodeDesigns);
            mockValidator.SetupGet(v => v.Dictionary).Returns(mockDictionary.Object);
            mockDictionary.SetupGet(d => d.TargetNamespaceInfo).Returns(mockNamespaceInfo.Object);
            mockNamespaceInfo.SetupGet(n => n.Prefix).Returns("TestPrefix");
            mockDictionary.SetupGet(d => d.Namespaces).Returns(namespaces);
            mockDictionary.SetupGet(d => d.TargetNamespace).Returns("http://test.namespace");

            mockTextWriter.Setup(tw => tw.Dispose());

            string capturedPath = null;
            mockFileSystem.Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Callback<string>(path => capturedPath = path)
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "C:\\output",
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new DataTypeGenerator(context, false);

            // Act
            generator.Emit();

            // Assert
            Assert.That(capturedPath, Is.Not.Null);
            Assert.That(capturedPath, Does.Contain("TestPrefix.DataTypes.g.cs"));
            Assert.That(capturedPath, Does.StartWith("C:\\output"));
            mockFileSystem.Verify(fs => fs.CreateTextWriter(It.IsAny<string>()), Times.Once);
        }

        /// <summary>
        /// Tests that Emit handles empty string prefix correctly.
        /// Verifies that an empty prefix results in a valid filename.
        /// Expected: File is created with ".DataTypes.g.cs" filename.
        /// </summary>
        [Test]
        public void Emit_WithEmptyPrefix_CreatesFileWithEmptyPrefixName()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
            var mockValidator = new Mock<ModelDesignValidator>(MockBehavior.Strict);
            var mockDictionary = new Mock<ModelDesign>(MockBehavior.Strict);
            var mockNamespaceInfo = new Mock<Namespace>(MockBehavior.Strict);
            var mockTelemetry = new Mock<ITelemetryContext>(MockBehavior.Strict);
            var mockOptions = new Mock<GeneratorOptions>(MockBehavior.Strict);
            var mockTextWriter = new Mock<TextWriter>(MockBehavior.Strict);

            var dataType = new Mock<DataTypeDesign>(MockBehavior.Strict);
            dataType.Setup(dt => dt.IsPartOfOpcUaTypesLibrary()).Returns(false);

            var nodeDesigns = new List<NodeDesign> { dataType.Object };
            Namespace[] namespaces = [];

            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(nodeDesigns);
            mockValidator.SetupGet(v => v.Dictionary).Returns(mockDictionary.Object);
            mockDictionary.SetupGet(d => d.TargetNamespaceInfo).Returns(mockNamespaceInfo.Object);
            mockNamespaceInfo.SetupGet(n => n.Prefix).Returns(string.Empty);
            mockDictionary.SetupGet(d => d.Namespaces).Returns(namespaces);
            mockDictionary.SetupGet(d => d.TargetNamespace).Returns("http://test.namespace");

            mockTextWriter.Setup(tw => tw.Dispose());

            string capturedPath = null;
            mockFileSystem.Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Callback<string>(path => capturedPath = path)
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "C:\\output",
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new DataTypeGenerator(context, false);

            // Act
            generator.Emit();

            // Assert
            Assert.That(capturedPath, Is.Not.Null);
            Assert.That(capturedPath, Does.Contain(".DataTypes.g.cs"));
        }

        /// <summary>
        /// Tests that Emit handles special characters in prefix correctly.
        /// Verifies that prefixes with special characters are handled properly in filename generation.
        /// Expected: File is created with the special character prefix in the filename.
        /// </summary>
        [TestCase("Test-Prefix")]
        [TestCase("Test.Prefix")]
        [TestCase("Test_Prefix")]
        [TestCase("Test123")]
        public void Emit_WithSpecialCharactersInPrefix_CreatesFileWithSpecialCharacters(string prefix)
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
            var mockValidator = new Mock<ModelDesignValidator>(MockBehavior.Strict);
            var mockDictionary = new Mock<ModelDesign>(MockBehavior.Strict);
            var mockNamespaceInfo = new Mock<Namespace>(MockBehavior.Strict);
            var mockTelemetry = new Mock<ITelemetryContext>(MockBehavior.Strict);
            var mockOptions = new Mock<GeneratorOptions>(MockBehavior.Strict);
            var mockTextWriter = new Mock<TextWriter>(MockBehavior.Strict);

            var dataType = new Mock<DataTypeDesign>(MockBehavior.Strict);
            dataType.Setup(dt => dt.IsPartOfOpcUaTypesLibrary()).Returns(false);

            var nodeDesigns = new List<NodeDesign> { dataType.Object };
            Namespace[] namespaces = [];

            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(nodeDesigns);
            mockValidator.SetupGet(v => v.Dictionary).Returns(mockDictionary.Object);
            mockDictionary.SetupGet(d => d.TargetNamespaceInfo).Returns(mockNamespaceInfo.Object);
            mockNamespaceInfo.SetupGet(n => n.Prefix).Returns(prefix);
            mockDictionary.SetupGet(d => d.Namespaces).Returns(namespaces);
            mockDictionary.SetupGet(d => d.TargetNamespace).Returns("http://test.namespace");

            mockTextWriter.Setup(tw => tw.Dispose());

            string capturedPath = null;
            mockFileSystem.Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Callback<string>(path => capturedPath = path)
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "C:\\output",
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new DataTypeGenerator(context, false);

            // Act
            generator.Emit();

            // Assert
            Assert.That(capturedPath, Is.Not.Null);
            Assert.That(capturedPath, Does.Contain($"{prefix}.DataTypes.g.cs"));
        }

        /// <summary>
        /// Tests that Emit filters out data types that are part of OPC UA types library.
        /// Verifies that only non-OPC UA library data types are processed.
        /// Expected: Only returns early when all data types are OPC UA library types.
        /// </summary>
        [Test]
        public void Emit_WithOnlyOpcUaLibraryDataTypes_ReturnsEarly()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
            var mockValidator = new Mock<ModelDesignValidator>(MockBehavior.Strict);
            var mockTelemetry = new Mock<ITelemetryContext>(MockBehavior.Strict);
            var mockOptions = new Mock<GeneratorOptions>(MockBehavior.Strict);

            var dataType = new Mock<DataTypeDesign>(MockBehavior.Strict);
            dataType.Setup(dt => dt.IsPartOfOpcUaTypesLibrary()).Returns(true);

            var nodeDesigns = new List<NodeDesign> { dataType.Object };

            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(nodeDesigns);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "C:\\output",
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new DataTypeGenerator(context, false);

            // Act
            generator.Emit();

            // Assert
            mockFileSystem.Verify(fs => fs.CreateTextWriter(It.IsAny<string>()), Times.Never);
        }

        /// <summary>
        /// Tests that Emit processes multiple data types correctly.
        /// Verifies that when multiple non-OPC UA library data types exist, the file is created.
        /// Expected: File is created once regardless of the number of data types.
        /// </summary>
        [Test]
        public void Emit_WithMultipleDataTypes_CreatesFileSingleTime()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
            var mockValidator = new Mock<ModelDesignValidator>(MockBehavior.Strict);
            var mockDictionary = new Mock<ModelDesign>(MockBehavior.Strict);
            var mockNamespaceInfo = new Mock<Namespace>(MockBehavior.Strict);
            var mockTelemetry = new Mock<ITelemetryContext>(MockBehavior.Strict);
            var mockOptions = new Mock<GeneratorOptions>(MockBehavior.Strict);
            var mockTextWriter = new Mock<TextWriter>(MockBehavior.Strict);

            var dataType1 = new Mock<DataTypeDesign>(MockBehavior.Strict);
            dataType1.Setup(dt => dt.IsPartOfOpcUaTypesLibrary()).Returns(false);

            var dataType2 = new Mock<DataTypeDesign>(MockBehavior.Strict);
            dataType2.Setup(dt => dt.IsPartOfOpcUaTypesLibrary()).Returns(false);

            var nodeDesigns = new List<NodeDesign> { dataType1.Object, dataType2.Object };
            Namespace[] namespaces = [];

            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(nodeDesigns);
            mockValidator.SetupGet(v => v.Dictionary).Returns(mockDictionary.Object);
            mockDictionary.SetupGet(d => d.TargetNamespaceInfo).Returns(mockNamespaceInfo.Object);
            mockNamespaceInfo.SetupGet(n => n.Prefix).Returns("Multi");
            mockDictionary.SetupGet(d => d.Namespaces).Returns(namespaces);
            mockDictionary.SetupGet(d => d.TargetNamespace).Returns("http://test.namespace");

            mockTextWriter.Setup(tw => tw.Dispose());

            mockFileSystem.Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "C:\\output",
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new DataTypeGenerator(context, false);

            // Act
            generator.Emit();

            // Assert
            mockFileSystem.Verify(fs => fs.CreateTextWriter(It.IsAny<string>()), Times.Once);
        }

        /// <summary>
        /// Tests that Emit handles mixed node types correctly.
        /// Verifies that only DataTypeDesign nodes are processed, and other node types are ignored.
        /// Expected: Only DataTypeDesign nodes that are not OPC UA library types are processed.
        /// </summary>
        [Test]
        public void Emit_WithMixedNodeTypes_ProcessesOnlyDataTypeDesigns()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
            var mockValidator = new Mock<ModelDesignValidator>(MockBehavior.Strict);
            var mockDictionary = new Mock<ModelDesign>(MockBehavior.Strict);
            var mockNamespaceInfo = new Mock<Namespace>(MockBehavior.Strict);
            var mockTelemetry = new Mock<ITelemetryContext>(MockBehavior.Strict);
            var mockOptions = new Mock<GeneratorOptions>(MockBehavior.Strict);
            var mockTextWriter = new Mock<TextWriter>(MockBehavior.Strict);

            var dataType = new Mock<DataTypeDesign>(MockBehavior.Strict);
            dataType.Setup(dt => dt.IsPartOfOpcUaTypesLibrary()).Returns(false);

            var otherNode = new Mock<NodeDesign>(MockBehavior.Strict);

            var nodeDesigns = new List<NodeDesign> { otherNode.Object, dataType.Object };
            Namespace[] namespaces = [];

            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(nodeDesigns);
            mockValidator.SetupGet(v => v.Dictionary).Returns(mockDictionary.Object);
            mockDictionary.SetupGet(d => d.TargetNamespaceInfo).Returns(mockNamespaceInfo.Object);
            mockNamespaceInfo.SetupGet(n => n.Prefix).Returns("Mixed");
            mockDictionary.SetupGet(d => d.Namespaces).Returns(namespaces);
            mockDictionary.SetupGet(d => d.TargetNamespace).Returns("http://test.namespace");

            mockTextWriter.Setup(tw => tw.Dispose());

            mockFileSystem.Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "C:\\output",
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new DataTypeGenerator(context, false);

            // Act
            generator.Emit();

            // Assert
            mockFileSystem.Verify(fs => fs.CreateTextWriter(It.IsAny<string>()), Times.Once);
        }

        /// <summary>
        /// Tests that Emit uses the correct output folder path.
        /// Verifies that the output folder from context is used in the file path.
        /// Expected: File path contains the specified output folder.
        /// </summary>
        [TestCase("C:\\output")]
        [TestCase("C:\\test\\output")]
        [TestCase("D:\\generated")]
        public void Emit_WithDifferentOutputFolders_UsesCorrectOutputFolder(string outputFolder)
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
            var mockValidator = new Mock<ModelDesignValidator>(MockBehavior.Strict);
            var mockDictionary = new Mock<ModelDesign>(MockBehavior.Strict);
            var mockNamespaceInfo = new Mock<Namespace>(MockBehavior.Strict);
            var mockTelemetry = new Mock<ITelemetryContext>(MockBehavior.Strict);
            var mockOptions = new Mock<GeneratorOptions>(MockBehavior.Strict);
            var mockTextWriter = new Mock<TextWriter>(MockBehavior.Strict);

            var dataType = new Mock<DataTypeDesign>(MockBehavior.Strict);
            dataType.Setup(dt => dt.IsPartOfOpcUaTypesLibrary()).Returns(false);

            var nodeDesigns = new List<NodeDesign> { dataType.Object };
            Namespace[] namespaces = [];

            mockValidator.Setup(v => v.GetNodeDesigns()).Returns(nodeDesigns);
            mockValidator.SetupGet(v => v.Dictionary).Returns(mockDictionary.Object);
            mockDictionary.SetupGet(d => d.TargetNamespaceInfo).Returns(mockNamespaceInfo.Object);
            mockNamespaceInfo.SetupGet(n => n.Prefix).Returns("Test");
            mockDictionary.SetupGet(d => d.Namespaces).Returns(namespaces);
            mockDictionary.SetupGet(d => d.TargetNamespace).Returns("http://test.namespace");

            mockTextWriter.Setup(tw => tw.Dispose());

            string capturedPath = null;
            mockFileSystem.Setup(fs => fs.CreateTextWriter(It.IsAny<string>()))
                .Callback<string>(path => capturedPath = path)
                .Returns(mockTextWriter.Object);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = outputFolder,
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new DataTypeGenerator(context, false);

            // Act
            generator.Emit();

            // Assert
            Assert.That(capturedPath, Is.Not.Null);
            Assert.That(capturedPath, Does.StartWith(outputFolder));
        }

        /// <summary>
        /// Tests that Emit correctly handles useXmlInitializers parameter in constructor.
        /// Verifies that the generator can be instantiated with both true and false values.
        /// Expected: Generator is created successfully with either parameter value.
        /// </summary>
        [TestCase(true)]
        [TestCase(false)]
        public void Emit_WithUseXmlInitializersParameter_WorksCorrectly(bool useXmlInitializers)
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
            var mockValidator = new Mock<ModelDesignValidator>(MockBehavior.Strict);
            var mockTelemetry = new Mock<ITelemetryContext>(MockBehavior.Strict);
            var mockOptions = new Mock<GeneratorOptions>(MockBehavior.Strict);

            mockValidator.Setup(v => v.GetNodeDesigns()).Returns([]);

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "C:\\output",
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            var generator = new DataTypeGenerator(context, useXmlInitializers);

            // Act
            generator.Emit();

            // Assert
            mockValidator.Verify(v => v.GetNodeDesigns(), Times.Once);
        }

        /// <summary>
        /// Tests that the constructor throws NullReferenceException when the context parameter is null.
        /// This test verifies that the constructor does not handle null context gracefully.
        /// Expected result: NullReferenceException is thrown.
        /// </summary>
        [Test]
        public void Constructor_NullContext_ThrowsArgumentNullException()
        {
            // Arrange
            GeneratorContext context = null;

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new DataTypeGenerator(context));
        }

        /// <summary>
        /// Tests that the constructor initializes successfully with a valid context and default useXmlInitializers.
        /// This test verifies that the constructor accepts a valid GeneratorContext and uses the default value for useXmlInitializers (false).
        /// Expected result: DataTypeGenerator instance is created without throwing exceptions.
        /// </summary>
        [Test]
        public void Constructor_ValidContextAndDefaultUseXmlInitializers_InitializesSuccessfully()
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
            var generator = new DataTypeGenerator(context);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor initializes successfully with a valid context and useXmlInitializers set to true.
        /// This test verifies that the constructor properly handles the useXmlInitializers parameter when explicitly set to true.
        /// Expected result: DataTypeGenerator instance is created without throwing exceptions.
        /// </summary>
        [Test]
        public void Constructor_ValidContextAndUseXmlInitializersTrue_InitializesSuccessfully()
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
            var generator = new DataTypeGenerator(context, useXmlInitializers: true);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor initializes successfully with a valid context and useXmlInitializers explicitly set to false.
        /// This test verifies that the constructor properly handles the useXmlInitializers parameter when explicitly set to false.
        /// Expected result: DataTypeGenerator instance is created without throwing exceptions.
        /// </summary>
        [Test]
        public void Constructor_ValidContextAndUseXmlInitializersFalse_InitializesSuccessfully()
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
            var generator = new DataTypeGenerator(context, useXmlInitializers: false);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor throws NullReferenceException when context.Telemetry is null.
        /// This test verifies that the constructor does not handle null Telemetry property gracefully.
        /// Expected result: NullReferenceException is thrown when creating ServiceMessageContext.
        /// </summary>
        [Test]
        public void Constructor_ContextWithNullTelemetry_ThrowsArgumentNullException()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockOptions = new Mock<GeneratorOptions>();

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "TestOutput",
                Validator = mockValidator.Object,
                Telemetry = null,
                Options = mockOptions.Object
            };

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new DataTypeGenerator(context));
        }
    }
}
