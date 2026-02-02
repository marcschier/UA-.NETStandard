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
using System.Linq;
using System.Text;
using System.Xml;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using Opc.Ua.Schema.Model;
using Opc.Ua.Tests;

namespace Opc.Ua.SourceGeneration.Generator.Tests
{
    /// <summary>
    /// Unit tests for the NodeStateGenerator class.
    /// </summary>
    [TestFixture]
    [Category("Generator")]
    [SetCulture("en-us")]
    [SetUICulture("en-us")]
    [Parallelizable]
    public class NodeStateGeneratorTests
    {
        [SetUp]
        public void SetUp()
        {
            m_mockFileSystem = new Mock<IFileSystem>();
            m_mockModelDesign = new Mock<IModelDesign>();
            m_mockTelemetry = new Mock<ITelemetryContext>();

            // Setup default namespace
            var targetNamespace = new Namespace
            {
                Value = "http://test.org/UA/",
                Prefix = "Test",
                Name = "TestNamespace"
            };
            m_mockModelDesign.Setup(m => m.TargetNamespace).Returns(targetNamespace);
            m_mockModelDesign.Setup(m => m.Namespaces).Returns([targetNamespace]);
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
            Assert.Throws<ArgumentNullException>(() => new NodeStateGenerator(context));
        }

        /// <summary>
        /// Tests that constructor creates instance with valid context.
        /// </summary>
        [Test]
        public void Constructor_ValidContext_CreatesInstance()
        {
            // Arrange
            m_context = new GeneratorContext
            {
                FileSystem = m_mockFileSystem.Object,
                OutputFolder = "TestOutput",
                ModelDesign = m_mockModelDesign.Object,
                Telemetry = m_mockTelemetry.Object,
                Options = new GeneratorOptions()
            };

            // Act
            var generator = new NodeStateGenerator(m_context);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that Emit returns early without creating files when no node state classes exist.
        /// </summary>
        [Test]
        public void Emit_NoNodeStateClasses_ReturnsEarlyWithoutCreatingFiles()
        {
            // Arrange
            m_mockModelDesign.Setup(m => m.GetNodeDesigns()).Returns([]);

            m_context = new GeneratorContext
            {
                FileSystem = m_mockFileSystem.Object,
                OutputFolder = "TestOutput",
                ModelDesign = m_mockModelDesign.Object,
                Telemetry = m_mockTelemetry.Object,
                Options = new GeneratorOptions()
            };

            var generator = new NodeStateGenerator(m_context);

            // Act
            generator.Emit();

            // Assert - OpenWrite should not be called when there are no node state classes
            m_mockFileSystem.Verify(
                fs => fs.OpenWrite(It.IsAny<string>()),
                Times.Never,
                "OpenWrite should not be called when there are no node state classes");
        }

        [Test]
        public void GenerateNodeStateGeneratorCodeTest()
        {
            // Arrange
            ITelemetryContext telemetry = NUnitTelemetryContext.Create(logLevel: LogLevel.Error);
            using var fileSystem = new VirtualFileSystem();

            // Act - Generate full stack
            Generators.GenerateStack(StackGenerationType.All, fileSystem, string.Empty, telemetry);

            // Assert - NodeState file should be created
            var generatedFiles = fileSystem.CreatedFiles
                .Where(c => c.EndsWith(".NodeStates.ex.g.cs", StringComparison.Ordinal))
                .ToList();

            Assert.That(generatedFiles, Is.Not.Empty,
                "NodeStates.ex.g.cs file should be generated");

            foreach (string file in generatedFiles)
            {
                string content = Encoding.UTF8.GetString(fileSystem.Get(file));
                TestContext.Out.WriteLine("Generated file: {0} ({1} bytes)", file, content.Length);

                // Verify basic structure
                Assert.That(content, Does.Contain("// <auto-generated />"),
                    "Generated code should have auto-generated header");
                Assert.That(content, Does.Contain("public static partial class OpcUaExtensions"),
                    "Generated code should contain OpcUaExtensions class");
                Assert.That(content, Does.Contain("public static global::Opc.Ua.NodeStateCollection AddOpcUa"),
                    "Generated code should contain AddOpcUa method");
            }
        }

        [Test]
        public void GeneratedNodeStateGeneratorCodeCompilesTest()
        {
            // Arrange
            ITelemetryContext telemetry = NUnitTelemetryContext.Create(logLevel: LogLevel.Error);
            using var fileSystem = new VirtualFileSystem();

            // Act - Generate stack
            Generators.GenerateStack(StackGenerationType.All, fileSystem, string.Empty, telemetry);

            // Get all generated C# files
            var generatedText = fileSystem.CreatedFiles
                .Where(c => Path.GetExtension(c) == ".cs")
                .ToDictionary(c => c, c => Encoding.UTF8.GetString(fileSystem.Get(c)));

            // Verify generated code compiles
            using var peStream = new MemoryStream();
            bool success = OptimizationLevel.Debug
                .CreateCompilation()
                .AddCode(generatedText.WithOpcUaCoreStubs(), LanguageVersion.Latest)
                .Emit(peStream)
                .Check(TestContext.Out, out int errorCount, out int warnCount);

            // Assert
            Assert.That(success, Is.True,
                $"Generated NodeStates should compile without errors. Errors: {errorCount}, Warnings: {warnCount}");
        }

        [Test]
        public void NodeStateGeneratorCodeGeneratesCorrectMethodSignatures()
        {
            // Arrange
            ITelemetryContext telemetry = NUnitTelemetryContext.Create(logLevel: LogLevel.Error);
            using var fileSystem = new VirtualFileSystem();

            // Act
            Generators.GenerateStack(StackGenerationType.All, fileSystem, string.Empty, telemetry);

            // Find NodeStateGenerator files
            var predefinedNodesFiles = fileSystem.CreatedFiles
                .Where(c => c.EndsWith(".NodeStates.ex.g.cs", StringComparison.Ordinal))
                .ToList();

            Assert.That(predefinedNodesFiles, Is.Not.Empty);

            foreach (string file in predefinedNodesFiles)
            {
                string content = Encoding.UTF8.GetString(fileSystem.Get(file));

                // Check for proper method signatures
                Assert.That(content, Does.Contain("global::Opc.Ua.ISystemContext context"),
                    "Methods should use ISystemContext parameter");
                Assert.That(content, Does.Contain("state.NodeId ="),
                    "Code should set NodeId property");
                Assert.That(content, Does.Contain("state.BrowseName ="),
                    "Code should set BrowseName property");
            }
        }

        /// <summary>
        /// Tests that IsBuiltInProperty returns true when the instance parameter is null.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_NullInstance_ReturnsTrue()
        {
            // Arrange
            InstanceDesign mockInstance = null;

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty returns true when the parent is a MethodDesign
        /// and the symbolic name is "InputArguments" in the OpcUa namespace.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_MethodDesignParentWithInputArguments_ReturnsTrue()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = new MethodDesign(),
                SymbolicName = new XmlQualifiedName("InputArguments", Namespaces.OpcUa)
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty returns true when the parent is a MethodDesign
        /// and the symbolic name is "OutputArguments" in the OpcUa namespace.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_MethodDesignParentWithOutputArguments_ReturnsTrue()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = new MethodDesign(),
                SymbolicName = new XmlQualifiedName("OutputArguments", Namespaces.OpcUa)
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty returns false when the parent is a MethodDesign
        /// but the symbolic name is "InputArguments" in a different namespace.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_MethodDesignParentWithInputArgumentsDifferentNamespace_ReturnsFalse()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = new MethodDesign(),
                SymbolicName = new XmlQualifiedName("InputArguments", "http://custom.namespace/")
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty returns false when the parent is a MethodDesign
        /// but the symbolic name is "OutputArguments" in a different namespace.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_MethodDesignParentWithOutputArgumentsDifferentNamespace_ReturnsFalse()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = new MethodDesign(),
                SymbolicName = new XmlQualifiedName("OutputArguments", "http://custom.namespace/")
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty returns false when the parent is a MethodDesign
        /// but the symbolic name is not InputArguments or OutputArguments.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_MethodDesignParentWithDifferentName_ReturnsFalse()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = new MethodDesign(),
                SymbolicName = new XmlQualifiedName("CustomProperty", Namespaces.OpcUa)
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty returns true when the parent is a VariableDesign
        /// and the symbolic name is "EnumStrings" in the OpcUa namespace.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_VariableDesignParentWithEnumStrings_ReturnsTrue()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = new VariableDesign(),
                SymbolicName = new XmlQualifiedName("EnumStrings", Namespaces.OpcUa)
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.True);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty returns false when the parent is a VariableDesign
        /// but the symbolic name is "EnumStrings" in a different namespace.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_VariableDesignParentWithEnumStringsDifferentNamespace_ReturnsFalse()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = new VariableDesign(),
                SymbolicName = new XmlQualifiedName("EnumStrings", "http://custom.namespace/")
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty returns false when the parent is a VariableDesign
        /// but the symbolic name is not EnumStrings.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_VariableDesignParentWithDifferentName_ReturnsFalse()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = new VariableDesign(),
                SymbolicName = new XmlQualifiedName("CustomProperty", Namespaces.OpcUa)
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty returns false when the parent is neither
        /// a MethodDesign nor a VariableDesign.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_OtherParentType_ReturnsFalse()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = new NodeDesign(),
                SymbolicName = new XmlQualifiedName("SomeProperty", Namespaces.OpcUa)
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty returns false when the parent is null.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_NullParent_ReturnsFalse()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = null,
                SymbolicName = new XmlQualifiedName("InputArguments", Namespaces.OpcUa)
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty returns false when the symbolic name is null
        /// and the parent is a MethodDesign.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_NullSymbolicName_ReturnsFalse()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = new MethodDesign(),
                SymbolicName = null
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty returns false when the symbolic name has empty name
        /// and the parent is a MethodDesign.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_EmptySymbolicName_ReturnsFalse()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = new MethodDesign(),
                SymbolicName = new XmlQualifiedName(string.Empty, Namespaces.OpcUa)
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty is case-sensitive for InputArguments.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_MethodDesignParentWithInputArgumentsDifferentCase_ReturnsFalse()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = new MethodDesign(),
                SymbolicName = new XmlQualifiedName("inputarguments", Namespaces.OpcUa)
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty is case-sensitive for OutputArguments.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_MethodDesignParentWithOutputArgumentsDifferentCase_ReturnsFalse()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = new MethodDesign(),
                SymbolicName = new XmlQualifiedName("OUTPUTARGUMENTS", Namespaces.OpcUa)
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.False);
        }

        /// <summary>
        /// Tests that IsBuiltInProperty is case-sensitive for EnumStrings.
        /// </summary>
        [Test]
        public void IsBuiltInProperty_VariableDesignParentWithEnumStringsDifferentCase_ReturnsFalse()
        {
            // Arrange
            var mockInstance = new InstanceDesign
            {
                Parent = new VariableDesign(),
                SymbolicName = new XmlQualifiedName("enumstrings", Namespaces.OpcUa)
            };

            // Act
            bool result = NodeStateGenerator.IsBuiltInProperty(mockInstance);

            // Assert
            Assert.That(result, Is.False);
        }

        private Mock<IFileSystem> m_mockFileSystem;
        private Mock<IModelDesign> m_mockModelDesign;
        private Mock<ITelemetryContext> m_mockTelemetry;
        private GeneratorContext m_context;
    }
}
