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
using Moq;
using NUnit.Framework;
using Opc.Ua.Schema.Model;

namespace Opc.Ua.SourceGeneration.Generator.Tests
{
    /// <summary>
    /// Unit tests for the Generators.GenerateCode method
    /// </summary>
    [TestFixture]
    public class GeneratorsTests
    {
        /// <summary>
        /// Tests that GenerateCode returns early when DesignFiles collection is empty.
        /// Input: Empty DesignFiles collection
        /// Expected: Method returns without processing, no file system or telemetry calls
        /// </summary>
        [Test]
        public void GenerateCode_EmptyDesignFilesCollection_ReturnsEarlyWithoutProcessing()
        {
            // Arrange
            var designFiles = new DesignFileCollection
            {
                DesignFiles = new List<string>()
            };
            var mockFileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
            var mockTelemetry = new Mock<ITelemetryContext>(MockBehavior.Strict);
            const string outputDir = "output";

            // Act
            designFiles.GenerateCode(mockFileSystem.Object, outputDir, mockTelemetry.Object);

            // Assert - No calls should be made to mocks (MockBehavior.Strict would throw if they were)
            mockFileSystem.VerifyNoOtherCalls();
            mockTelemetry.VerifyNoOtherCalls();
        }

        /// <summary>
        /// Tests that GenerateCode creates default GeneratorOptions when null is provided.
        /// Input: Null options parameter
        /// Expected: Method proceeds with newly created GeneratorOptions
        /// </summary>
        [Test]
        public void GenerateCode_NullOptions_CreatesDefaultGeneratorOptions()
        {
            // Arrange
            var designFiles = new DesignFileCollection
            {
                DesignFiles = new List<string> { "design1.xml" }
            };
            var mockFileSystem = new Mock<IFileSystem>();
            var mockCombinedFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockModelDesignValidator = new Mock<ModelDesignValidator>();
            const string outputDir = "output";

            mockFileSystem.Setup(fs => fs.WithFallback(It.IsAny<IFileSystem[]>()))
                .Returns(mockCombinedFileSystem.Object);
            mockCombinedFileSystem.Setup(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<ITelemetryContext>(),
                It.IsAny<bool>()))
                .Returns(mockModelDesignValidator.Object);

            // Act
            designFiles.GenerateCode(mockFileSystem.Object, outputDir, mockTelemetry.Object, options: null);

            // Assert
            mockCombinedFileSystem.Verify(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.Is<IReadOnlyList<string>>(e => e != null && e.Count == 0),
                mockTelemetry.Object,
                false), Times.Once);
        }

        /// <summary>
        /// Tests that GenerateCode uses provided GeneratorOptions when not null.
        /// Input: Non-null GeneratorOptions with specific Exclusions
        /// Expected: Method uses the provided options with the specified exclusions
        /// </summary>
        [Test]
        public void GenerateCode_NonNullOptions_UsesProvidedOptions()
        {
            // Arrange
            var designFiles = new DesignFileCollection
            {
                DesignFiles = new List<string> { "design1.xml" }
            };
            var mockFileSystem = new Mock<IFileSystem>();
            var mockCombinedFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockModelDesignValidator = new Mock<ModelDesignValidator>();
            var options = new GeneratorOptions
            {
                Exclusions = new List<string> { "exclusion1", "exclusion2" }
            };
            const string outputDir = "output";

            mockFileSystem.Setup(fs => fs.WithFallback(It.IsAny<IFileSystem[]>()))
                .Returns(mockCombinedFileSystem.Object);
            mockCombinedFileSystem.Setup(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<ITelemetryContext>(),
                It.IsAny<bool>()))
                .Returns(mockModelDesignValidator.Object);

            // Act
            designFiles.GenerateCode(mockFileSystem.Object, outputDir, mockTelemetry.Object, options);

            // Assert
            mockCombinedFileSystem.Verify(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.Is<IReadOnlyList<string>>(e => e.Count == 2),
                mockTelemetry.Object,
                false), Times.Once);
        }

        /// <summary>
        /// Tests that GenerateCode processes each grouped design file collection.
        /// Input: Single design file that results in one group
        /// Expected: OpenModelDesign and Generate are called once
        /// </summary>
        [Test]
        public void GenerateCode_SingleDesignFile_ProcessesOneGroup()
        {
            // Arrange
            var designFiles = new DesignFileCollection
            {
                DesignFiles = new List<string> { "C:\\designs\\design1.xml" }
            };
            var mockFileSystem = new Mock<IFileSystem>();
            var mockCombinedFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockModelDesignValidator = new Mock<ModelDesignValidator>();
            const string outputDir = "output";

            mockFileSystem.Setup(fs => fs.WithFallback(It.IsAny<IFileSystem[]>()))
                .Returns(mockCombinedFileSystem.Object);
            mockCombinedFileSystem.Setup(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<ITelemetryContext>(),
                It.IsAny<bool>()))
                .Returns(mockModelDesignValidator.Object);

            // Act
            designFiles.GenerateCode(mockFileSystem.Object, outputDir, mockTelemetry.Object);

            // Assert
            mockCombinedFileSystem.Verify(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                mockTelemetry.Object,
                false), Times.Once);
        }

        /// <summary>
        /// Tests that GenerateCode processes multiple groups when design files are in different directories.
        /// Input: Multiple design files in different directories
        /// Expected: OpenModelDesign and Generate are called multiple times
        /// </summary>
        [Test]
        public void GenerateCode_MultipleDesignFilesInDifferentDirectories_ProcessesMultipleGroups()
        {
            // Arrange
            var designFiles = new DesignFileCollection
            {
                DesignFiles = new List<string>
                {
                    "C:\\designs\\dir1\\design1.xml",
                    "C:\\designs\\dir2\\design2.xml"
                }
            };
            var mockFileSystem = new Mock<IFileSystem>();
            var mockCombinedFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockModelDesignValidator = new Mock<ModelDesignValidator>();
            const string outputDir = "output";

            mockFileSystem.Setup(fs => fs.WithFallback(It.IsAny<IFileSystem[]>()))
                .Returns(mockCombinedFileSystem.Object);
            mockCombinedFileSystem.Setup(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<ITelemetryContext>(),
                It.IsAny<bool>()))
                .Returns(mockModelDesignValidator.Object);

            // Act
            designFiles.GenerateCode(mockFileSystem.Object, outputDir, mockTelemetry.Object);

            // Assert
            mockCombinedFileSystem.Verify(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                mockTelemetry.Object,
                false), Times.Exactly(2));
        }

        /// <summary>
        /// Tests that GenerateCode passes useAllowSubtypes parameter correctly.
        /// Input: useAllowSubtypes = true
        /// Expected: OpenModelDesign is called with true for useAllowSubtypes parameter
        /// </summary>
        [TestCase(true)]
        [TestCase(false)]
        public void GenerateCode_UseAllowSubtypesParameter_PassedToOpenModelDesign(bool useAllowSubtypes)
        {
            // Arrange
            var designFiles = new DesignFileCollection
            {
                DesignFiles = new List<string> { "design1.xml" }
            };
            var mockFileSystem = new Mock<IFileSystem>();
            var mockCombinedFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockModelDesignValidator = new Mock<ModelDesignValidator>();
            const string outputDir = "output";

            mockFileSystem.Setup(fs => fs.WithFallback(It.IsAny<IFileSystem[]>()))
                .Returns(mockCombinedFileSystem.Object);
            mockCombinedFileSystem.Setup(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<ITelemetryContext>(),
                It.IsAny<bool>()))
                .Returns(mockModelDesignValidator.Object);

            // Act
            designFiles.GenerateCode(
                mockFileSystem.Object,
                outputDir,
                mockTelemetry.Object,
                useAllowSubtypes: useAllowSubtypes);

            // Assert
            mockCombinedFileSystem.Verify(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                mockTelemetry.Object,
                useAllowSubtypes), Times.Once);
        }

        /// <summary>
        /// Tests that GenerateCode handles null identifierFiles parameter correctly.
        /// Input: null identifierFiles
        /// Expected: Method processes normally, passing null to Group method
        /// </summary>
        [Test]
        public void GenerateCode_NullIdentifierFiles_ProcessesSuccessfully()
        {
            // Arrange
            var designFiles = new DesignFileCollection
            {
                DesignFiles = new List<string> { "design1.xml" }
            };
            var mockFileSystem = new Mock<IFileSystem>();
            var mockCombinedFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockModelDesignValidator = new Mock<ModelDesignValidator>();
            const string outputDir = "output";

            mockFileSystem.Setup(fs => fs.WithFallback(It.IsAny<IFileSystem[]>()))
                .Returns(mockCombinedFileSystem.Object);
            mockCombinedFileSystem.Setup(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<ITelemetryContext>(),
                It.IsAny<bool>()))
                .Returns(mockModelDesignValidator.Object);

            // Act
            designFiles.GenerateCode(
                mockFileSystem.Object,
                outputDir,
                mockTelemetry.Object,
                identifierFiles: null);

            // Assert
            mockCombinedFileSystem.Verify(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                mockTelemetry.Object,
                false), Times.Once);
        }

        /// <summary>
        /// Tests that GenerateCode handles non-null identifierFiles parameter correctly.
        /// Input: List of identifier files
        /// Expected: Method processes normally, passing the list to Group method
        /// </summary>
        [Test]
        public void GenerateCode_NonNullIdentifierFiles_ProcessesSuccessfully()
        {
            // Arrange
            var designFiles = new DesignFileCollection
            {
                DesignFiles = new List<string> { "C:\\designs\\design1.xml" }
            };
            var mockFileSystem = new Mock<IFileSystem>();
            var mockCombinedFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockModelDesignValidator = new Mock<ModelDesignValidator>();
            var identifierFiles = new List<string> { "C:\\designs\\identifiers.csv" };
            const string outputDir = "output";

            mockFileSystem.Setup(fs => fs.WithFallback(It.IsAny<IFileSystem[]>()))
                .Returns(mockCombinedFileSystem.Object);
            mockCombinedFileSystem.Setup(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<ITelemetryContext>(),
                It.IsAny<bool>()))
                .Returns(mockModelDesignValidator.Object);

            // Act
            designFiles.GenerateCode(
                mockFileSystem.Object,
                outputDir,
                mockTelemetry.Object,
                identifierFiles: identifierFiles);

            // Assert
            mockCombinedFileSystem.Verify(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                mockTelemetry.Object,
                false), Times.Once);
        }

        /// <summary>
        /// Tests that GenerateCode handles null outputDir parameter correctly.
        /// Input: null outputDir
        /// Expected: Method processes successfully with null output directory
        /// </summary>
        [Test]
        public void GenerateCode_NullOutputDir_ProcessesSuccessfully()
        {
            // Arrange
            var designFiles = new DesignFileCollection
            {
                DesignFiles = new List<string> { "design1.xml" }
            };
            var mockFileSystem = new Mock<IFileSystem>();
            var mockCombinedFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockModelDesignValidator = new Mock<ModelDesignValidator>();

            mockFileSystem.Setup(fs => fs.WithFallback(It.IsAny<IFileSystem[]>()))
                .Returns(mockCombinedFileSystem.Object);
            mockCombinedFileSystem.Setup(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<ITelemetryContext>(),
                It.IsAny<bool>()))
                .Returns(mockModelDesignValidator.Object);

            // Act
            designFiles.GenerateCode(mockFileSystem.Object, null, mockTelemetry.Object);

            // Assert
            mockCombinedFileSystem.Verify(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                mockTelemetry.Object,
                false), Times.Once);
        }

        /// <summary>
        /// Tests that GenerateCode handles various outputDir values correctly.
        /// Input: Empty and whitespace outputDir values
        /// Expected: Method processes successfully with any outputDir value
        /// </summary>
        [TestCase("")]
        [TestCase("   ")]
        [TestCase("C:\\output")]
        public void GenerateCode_VariousOutputDirValues_ProcessesSuccessfully(string outputDir)
        {
            // Arrange
            var designFiles = new DesignFileCollection
            {
                DesignFiles = new List<string> { "design1.xml" }
            };
            var mockFileSystem = new Mock<IFileSystem>();
            var mockCombinedFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockModelDesignValidator = new Mock<ModelDesignValidator>();

            mockFileSystem.Setup(fs => fs.WithFallback(It.IsAny<IFileSystem[]>()))
                .Returns(mockCombinedFileSystem.Object);
            mockCombinedFileSystem.Setup(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<ITelemetryContext>(),
                It.IsAny<bool>()))
                .Returns(mockModelDesignValidator.Object);

            // Act
            designFiles.GenerateCode(mockFileSystem.Object, outputDir, mockTelemetry.Object);

            // Assert
            mockCombinedFileSystem.Verify(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                mockTelemetry.Object,
                false), Times.Once);
        }

        /// <summary>
        /// Tests that GenerateCode combines fileSystem with assembly resources correctly.
        /// Input: Standard parameters with design files
        /// Expected: WithFallback is called on the assembly file system with the original fileSystem
        /// </summary>
        [Test]
        public void GenerateCode_ValidParameters_CombinesFileSystemWithAssemblyResources()
        {
            // Arrange
            var designFiles = new DesignFileCollection
            {
                DesignFiles = new List<string> { "design1.xml" }
            };
            var mockFileSystem = new Mock<IFileSystem>();
            var mockCombinedFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockModelDesignValidator = new Mock<ModelDesignValidator>();
            const string outputDir = "output";

            mockFileSystem.Setup(fs => fs.WithFallback(It.IsAny<IFileSystem[]>()))
                .Returns(mockCombinedFileSystem.Object);
            mockCombinedFileSystem.Setup(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<ITelemetryContext>(),
                It.IsAny<bool>()))
                .Returns(mockModelDesignValidator.Object);

            // Act
            designFiles.GenerateCode(mockFileSystem.Object, outputDir, mockTelemetry.Object);

            // Assert
            mockFileSystem.Verify(fs => fs.WithFallback(It.IsAny<IFileSystem[]>()), Times.Once);
        }

        /// <summary>
        /// Tests that GenerateCode handles embedNodeSet2Xml parameter correctly.
        /// Input: embedNodeSet2Xml = true and false
        /// Expected: Parameter is passed through to Generate method
        /// </summary>
        [TestCase(true)]
        [TestCase(false)]
        public void GenerateCode_EmbedNodeSet2XmlParameter_PassedToGenerate(bool embedNodeSet2Xml)
        {
            // Arrange
            var designFiles = new DesignFileCollection
            {
                DesignFiles = new List<string> { "design1.xml" }
            };
            var mockFileSystem = new Mock<IFileSystem>();
            var mockCombinedFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockModelDesignValidator = new Mock<ModelDesignValidator>();
            const string outputDir = "output";

            mockFileSystem.Setup(fs => fs.WithFallback(It.IsAny<IFileSystem[]>()))
                .Returns(mockCombinedFileSystem.Object);
            mockCombinedFileSystem.Setup(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<ITelemetryContext>(),
                It.IsAny<bool>()))
                .Returns(mockModelDesignValidator.Object);

            // Act
            designFiles.GenerateCode(
                mockFileSystem.Object,
                outputDir,
                mockTelemetry.Object,
                embedNodeSet2Xml: embedNodeSet2Xml);

            // Assert - Verify Generate was called (indirectly through OpenModelDesign being called)
            mockCombinedFileSystem.Verify(fs => fs.OpenModelDesign(
                It.IsAny<DesignFileCollection>(),
                It.IsAny<IReadOnlyList<string>>(),
                mockTelemetry.Object,
                false), Times.Once);
        }

        /// <summary>
        /// Tests that GenerateCode returns early when the nodesets Files collection is empty.
        /// Condition: nodesets.Files.Count == 0
        /// Expected: Method returns immediately without processing
        /// </summary>
        [Test]
        public void GenerateCode_EmptyFilesCollection_ReturnsEarly()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var nodesets = new NodesetFileCollection(
                [],
                mockFileSystem.Object,
                mockTelemetry.Object);

            // Act
            nodesets.GenerateCode(
                mockFileSystem.Object,
                "output",
                mockTelemetry.Object);

            // Assert
            Assert.That(nodesets.Files.Count, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that GenerateCode handles null outputDir parameter.
        /// Condition: outputDir is null
        /// Expected: Method executes without throwing exception
        /// </summary>
        [Test]
        public void GenerateCode_NullOutputDir_DoesNotThrow()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var nodesets = new NodesetFileCollection(
                [],
                mockFileSystem.Object,
                mockTelemetry.Object);

            // Act & Assert
            Assert.DoesNotThrow(() => nodesets.GenerateCode(
                mockFileSystem.Object,
                null,
                mockTelemetry.Object));
        }

        /// <summary>
        /// Tests that GenerateCode handles empty string outputDir parameter.
        /// Condition: outputDir is empty string
        /// Expected: Method executes without throwing exception
        /// </summary>
        [Test]
        public void GenerateCode_EmptyOutputDir_DoesNotThrow()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var nodesets = new NodesetFileCollection(
                [],
                mockFileSystem.Object,
                mockTelemetry.Object);

            // Act & Assert
            Assert.DoesNotThrow(() => nodesets.GenerateCode(
                mockFileSystem.Object,
                string.Empty,
                mockTelemetry.Object));
        }

        /// <summary>
        /// Tests that GenerateCode handles whitespace outputDir parameter.
        /// Condition: outputDir contains only whitespace
        /// Expected: Method executes without throwing exception
        /// </summary>
        [Test]
        public void GenerateCode_WhitespaceOutputDir_DoesNotThrow()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var nodesets = new NodesetFileCollection(
                [],
                mockFileSystem.Object,
                mockTelemetry.Object);

            // Act & Assert
            Assert.DoesNotThrow(() => nodesets.GenerateCode(
                mockFileSystem.Object,
                "   ",
                mockTelemetry.Object));
        }

        /// <summary>
        /// Tests that GenerateCode handles outputDir with special characters.
        /// Condition: outputDir contains special characters
        /// Expected: Method executes without throwing exception
        /// </summary>
        [Test]
        public void GenerateCode_OutputDirWithSpecialCharacters_DoesNotThrow()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var nodesets = new NodesetFileCollection(
                [],
                mockFileSystem.Object,
                mockTelemetry.Object);

            // Act & Assert
            Assert.DoesNotThrow(() => nodesets.GenerateCode(
                mockFileSystem.Object,
                "C:\\Special@#$%Folder\\Output",
                mockTelemetry.Object));
        }

        /// <summary>
        /// Tests that GenerateCode handles null options parameter by creating default options.
        /// Condition: options parameter is null
        /// Expected: Method creates new GeneratorOptions instance internally
        /// </summary>
        [Test]
        public void GenerateCode_NullOptions_DoesNotThrow()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var nodesets = new NodesetFileCollection(
                [],
                mockFileSystem.Object,
                mockTelemetry.Object);

            // Act & Assert
            Assert.DoesNotThrow(() => nodesets.GenerateCode(
                mockFileSystem.Object,
                "output",
                mockTelemetry.Object,
                options: null));
        }

        /// <summary>
        /// Tests that GenerateCode uses provided options when not null.
        /// Condition: options parameter is provided
        /// Expected: Method uses the provided options
        /// </summary>
        [Test]
        public void GenerateCode_WithOptions_DoesNotThrow()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var nodesets = new NodesetFileCollection(
                [],
                mockFileSystem.Object,
                mockTelemetry.Object);
            var options = new GeneratorOptions();

            // Act & Assert
            Assert.DoesNotThrow(() => nodesets.GenerateCode(
                mockFileSystem.Object,
                "output",
                mockTelemetry.Object,
                options: options));
        }

        /// <summary>
        /// Tests that GenerateCode handles useAllowSubtypes set to false.
        /// Condition: useAllowSubtypes is false
        /// Expected: Method executes with useAllowSubtypes false
        /// </summary>
        [Test]
        public void GenerateCode_UseAllowSubtypesFalse_DoesNotThrow()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var nodesets = new NodesetFileCollection(
                [],
                mockFileSystem.Object,
                mockTelemetry.Object);

            // Act & Assert
            Assert.DoesNotThrow(() => nodesets.GenerateCode(
                mockFileSystem.Object,
                "output",
                mockTelemetry.Object,
                useAllowSubtypes: false));
        }

        /// <summary>
        /// Tests that GenerateCode handles useAllowSubtypes set to true.
        /// Condition: useAllowSubtypes is true
        /// Expected: Method executes with useAllowSubtypes true
        /// </summary>
        [Test]
        public void GenerateCode_UseAllowSubtypesTrue_DoesNotThrow()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var nodesets = new NodesetFileCollection(
                [],
                mockFileSystem.Object,
                mockTelemetry.Object);

            // Act & Assert
            Assert.DoesNotThrow(() => nodesets.GenerateCode(
                mockFileSystem.Object,
                "output",
                mockTelemetry.Object,
                useAllowSubtypes: true));
        }

        /// <summary>
        /// Tests that GenerateCode handles embedNodeSet2Xml set to false.
        /// Condition: embedNodeSet2Xml is false
        /// Expected: Method executes with embedNodeSet2Xml false
        /// </summary>
        [Test]
        public void GenerateCode_EmbedNodeSet2XmlFalse_DoesNotThrow()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var nodesets = new NodesetFileCollection(
                [],
                mockFileSystem.Object,
                mockTelemetry.Object);

            // Act & Assert
            Assert.DoesNotThrow(() => nodesets.GenerateCode(
                mockFileSystem.Object,
                "output",
                mockTelemetry.Object,
                embedNodeSet2Xml: false));
        }

        /// <summary>
        /// Tests that GenerateCode handles embedNodeSet2Xml set to true.
        /// Condition: embedNodeSet2Xml is true
        /// Expected: Method executes with embedNodeSet2Xml true
        /// </summary>
        [Test]
        public void GenerateCode_EmbedNodeSet2XmlTrue_DoesNotThrow()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var nodesets = new NodesetFileCollection(
                [],
                mockFileSystem.Object,
                mockTelemetry.Object);

            // Act & Assert
            Assert.DoesNotThrow(() => nodesets.GenerateCode(
                mockFileSystem.Object,
                "output",
                mockTelemetry.Object,
                embedNodeSet2Xml: true));
        }

        /// <summary>
        /// Tests that GenerateCode handles all boolean parameter combinations.
        /// Condition: Various combinations of useAllowSubtypes and embedNodeSet2Xml
        /// Expected: Method executes for all combinations
        /// </summary>
        [TestCase(false, false)]
        [TestCase(false, true)]
        [TestCase(true, false)]
        [TestCase(true, true)]
        public void GenerateCode_BooleanParameterCombinations_DoesNotThrow(
            bool useAllowSubtypes,
            bool embedNodeSet2Xml)
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var nodesets = new NodesetFileCollection(
                [],
                mockFileSystem.Object,
                mockTelemetry.Object);

            // Act & Assert
            Assert.DoesNotThrow(() => nodesets.GenerateCode(
                mockFileSystem.Object,
                "output",
                mockTelemetry.Object,
                useAllowSubtypes: useAllowSubtypes,
                embedNodeSet2Xml: embedNodeSet2Xml));
        }

        /// <summary>
        /// Tests GenerateStack with all valid StackGenerationType enum values.
        /// Verifies that the method executes without throwing exceptions for each generation type.
        /// </summary>
        [TestCase(StackGenerationType.None)]
        [TestCase(StackGenerationType.Stack)]
        [TestCase(StackGenerationType.Models)]
        [TestCase(StackGenerationType.All)]
        public void GenerateStack_ValidGenerationType_ExecutesSuccessfully(StackGenerationType generationType)
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            const string outputDir = "output";

            // Act & Assert
            Assert.DoesNotThrow(() => Generators.GenerateStack(
                generationType,
                mockFileSystem.Object,
                outputDir,
                mockTelemetry.Object));
        }

        /// <summary>
        /// Tests GenerateStack with null options parameter.
        /// Verifies that the method creates a default GeneratorOptions instance and executes successfully.
        /// </summary>
        [Test]
        public void GenerateStack_NullOptions_CreatesDefaultOptions()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            const string outputDir = "output";

            // Act & Assert
            Assert.DoesNotThrow(() => Generators.GenerateStack(
                StackGenerationType.None,
                mockFileSystem.Object,
                outputDir,
                mockTelemetry.Object,
                options: null));
        }

        /// <summary>
        /// Tests GenerateStack with valid GeneratorOptions instance.
        /// Verifies that the method accepts and uses the provided options without throwing exceptions.
        /// </summary>
        [Test]
        public void GenerateStack_ValidOptions_ExecutesSuccessfully()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            const string outputDir = "output";
            var options = new GeneratorOptions();

            // Act & Assert
            Assert.DoesNotThrow(() => Generators.GenerateStack(
                StackGenerationType.None,
                mockFileSystem.Object,
                outputDir,
                mockTelemetry.Object,
                options));
        }

        /// <summary>
        /// Tests GenerateStack with null fileSystem parameter.
        /// Verifies that the method throws an appropriate exception when fileSystem is null.
        /// </summary>
        [Test]
        public void GenerateStack_NullFileSystem_ThrowsException()
        {
            // Arrange
            var mockTelemetry = new Mock<ITelemetryContext>();
            const string outputDir = "output";

            // Act & Assert
            Assert.Throws<NullReferenceException>(() => Generators.GenerateStack(
                StackGenerationType.None,
                null,
                outputDir,
                mockTelemetry.Object));
        }

        /// <summary>
        /// Tests GenerateStack with null telemetry parameter.
        /// Verifies that the method throws an appropriate exception when telemetry is null.
        /// </summary>
        [Test]
        public void GenerateStack_NullTelemetry_ThrowsException()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            const string outputDir = "output";

            // Act & Assert
            Assert.Throws<NullReferenceException>(() => Generators.GenerateStack(
                StackGenerationType.None,
                mockFileSystem.Object,
                outputDir,
                null));
        }

        /// <summary>
        /// Tests GenerateStack with various outputDir parameter values.
        /// Verifies that the method handles null, empty, and whitespace output directories without throwing exceptions.
        /// </summary>
        [TestCase(null)]
        [TestCase("")]
        [TestCase(" ")]
        [TestCase("output")]
        [TestCase("C:\\output")]
        [TestCase("/output")]
        public void GenerateStack_VariousOutputDirectories_ExecutesSuccessfully(string outputDir)
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();

            // Act & Assert
            Assert.DoesNotThrow(() => Generators.GenerateStack(
                StackGenerationType.None,
                mockFileSystem.Object,
                outputDir,
                mockTelemetry.Object));
        }

        /// <summary>
        /// Tests GenerateStack with flag combination of Stack and Models.
        /// Verifies that StackGenerationType.All (which is Stack | Models) executes successfully.
        /// </summary>
        [Test]
        public void GenerateStack_CombinedStackAndModels_ExecutesSuccessfully()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            const string outputDir = "output";

            // Act & Assert
            Assert.DoesNotThrow(() => Generators.GenerateStack(
                StackGenerationType.Stack | StackGenerationType.Models,
                mockFileSystem.Object,
                outputDir,
                mockTelemetry.Object));
        }

        /// <summary>
        /// Tests GenerateStack with an invalid enum value cast from an integer.
        /// Verifies that the method handles invalid enum values gracefully.
        /// </summary>
        [Test]
        public void GenerateStack_InvalidEnumValue_ExecutesSuccessfully()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            const string outputDir = "output";
            const StackGenerationType invalidGenerationType = (StackGenerationType)999;

            // Act & Assert
            Assert.DoesNotThrow(() => Generators.GenerateStack(
                invalidGenerationType,
                mockFileSystem.Object,
                outputDir,
                mockTelemetry.Object));
        }

        /// <summary>
        /// Tests GenerateStack with very long output directory path.
        /// Verifies that the method handles long path strings without throwing exceptions.
        /// </summary>
        [Test]
        public void GenerateStack_VeryLongOutputDirectory_ExecutesSuccessfully()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            string outputDir = new('a', 1000);

            // Act & Assert
            Assert.DoesNotThrow(() => Generators.GenerateStack(
                StackGenerationType.None,
                mockFileSystem.Object,
                outputDir,
                mockTelemetry.Object));
        }

        /// <summary>
        /// Tests GenerateStack with output directory containing special characters.
        /// Verifies that the method handles special characters in paths without throwing exceptions.
        /// </summary>
        [TestCase("output@#$%")]
        [TestCase("output\twith\ttabs")]
        [TestCase("output\nwith\nnewlines")]
        public void GenerateStack_OutputDirectoryWithSpecialCharacters_ExecutesSuccessfully(string outputDir)
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();

            // Act & Assert
            Assert.DoesNotThrow(() => Generators.GenerateStack(
                StackGenerationType.None,
                mockFileSystem.Object,
                outputDir,
                mockTelemetry.Object));
        }

        /// <summary>
        /// Tests GenerateStack with options having OptimizeForCompileSpeed set to true.
        /// Verifies that the method respects the OptimizeForCompileSpeed option when generating models.
        /// </summary>
        [Test]
        public void GenerateStack_OptionsWithOptimizeForCompileSpeed_ExecutesSuccessfully()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            const string outputDir = "output";
            var options = new GeneratorOptions
            {
                OptimizeForCompileSpeed = true
            };

            // Act & Assert
            Assert.DoesNotThrow(() => Generators.GenerateStack(
                StackGenerationType.Models,
                mockFileSystem.Object,
                outputDir,
                mockTelemetry.Object,
                options));
        }
    }
}
