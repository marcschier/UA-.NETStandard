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
using System.Reflection;
using System.Xml;
using Moq;
using NUnit.Framework;
using Opc.Ua.Schema.Model;

namespace Opc.Ua.SourceGeneration.Generator.Tests
{
    /// <summary>
    /// Unit tests for <see cref="NodeStateGenerator"/> class.
    /// </summary>
    [TestFixture]
    [Category("Generator")]
    [SetCulture("en-us")]
    [SetUICulture("en-us")]
    [Parallelizable]
    public class NodeStateGeneratorTests
    {
        /// <summary>
        /// Tests that the constructor initializes successfully with a valid context and default useXmlInitializers value (false).
        /// </summary>
        [Test]
        public void Constructor_WithValidContextAndDefaultUseXmlInitializers_InitializesSuccessfully()
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

            // Act & Assert
            Assert.DoesNotThrow(() => new NodeStateGenerator(context));
        }

        /// <summary>
        /// Tests that the constructor initializes successfully with a valid context and useXmlInitializers set to true.
        /// </summary>
        [Test]
        public void Constructor_WithValidContextAndTrueUseXmlInitializers_InitializesSuccessfully()
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

            // Act & Assert
            Assert.DoesNotThrow(() => new NodeStateGenerator(context, useXmlInitializers: true));
        }

        /// <summary>
        /// Tests that the constructor initializes successfully with a valid context and useXmlInitializers explicitly set to false.
        /// </summary>
        [Test]
        public void Constructor_WithValidContextAndFalseUseXmlInitializers_InitializesSuccessfully()
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

            // Act & Assert
            Assert.DoesNotThrow(() => new NodeStateGenerator(context, useXmlInitializers: false));
        }

        /// <summary>
        /// Tests that the constructor throws NullReferenceException when context parameter is null.
        /// Verifies that null context causes exception when accessing context.Telemetry property.
        /// </summary>
        [Test]
        public void Constructor_WithNullContext_ThrowsArgumentNullException()
        {
            // Arrange
            GeneratorContext context = null;

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new NodeStateGenerator(context));
        }

        /// <summary>
        /// Tests that the constructor throws NullReferenceException when context.Telemetry is null.
        /// Verifies that ServiceMessageContext constructor fails with null telemetry.
        /// </summary>
        [Test]
        public void Constructor_WithNullTelemetry_ThrowsArgumentNullException()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockOptions = new Mock<GeneratorOptions>();

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "output",
                Validator = mockValidator.Object,
                Telemetry = null,
                Options = mockOptions.Object
            };

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new NodeStateGenerator(context));
        }

        /// <summary>
        /// Tests that AddInitializer creates a binary resource when child is null and forInstance is false.
        /// Expects the method to serialize the node state and add it to the initializers dictionary.
        /// </summary>
        [Test]
        public void AddInitializer_WithNodeStateAndBinaryEncoding_AddsResourceSuccessfully()
        {
            // Arrange
            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext();
            Mock<NodeDesign> mockNode = CreateMockNodeDesign();
            var generator = new NodeStateGenerator(mockContext.Object, useXmlInitializers: false);
            const string forClass = "TestClass";
            const bool forInstance = false;

            // Act
            generator.AddInitializer(forClass, mockNode.Object, forInstance, null);

            // Assert
            Dictionary<string, Resource> initializers = GetInitializers(generator);
            Assert.That(initializers.Count, Is.EqualTo(1));
            Assert.That(initializers.ContainsKey("TestClassInitializers.Binary"), Is.True);
        }

        /// <summary>
        /// Tests that AddInitializer creates an XML resource when useXmlInitializers is true.
        /// Expects the method to serialize the node state as XML and add it to the initializers dictionary.
        /// </summary>
        [Test]
        public void AddInitializer_WithXmlEncoding_AddsXmlResourceSuccessfully()
        {
            // Arrange
            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext();
            Mock<NodeDesign> mockNode = CreateMockNodeDesign();
            var generator = new NodeStateGenerator(mockContext.Object, useXmlInitializers: true);
            const string forClass = "TestClass";
            const bool forInstance = false;

            // Act
            generator.AddInitializer(forClass, mockNode.Object, forInstance, null);

            // Assert
            Dictionary<string, Resource> initializers = GetInitializers(generator);
            Assert.That(initializers.Count, Is.EqualTo(1));
            Assert.That(initializers.ContainsKey("TestClassInitializers.Xml"), Is.True);
        }

        /// <summary>
        /// Tests that AddInitializer uses InstanceState when forInstance is true.
        /// Expects the method to use node.InstanceState instead of node.State.
        /// </summary>
        [Test]
        public void AddInitializer_WithForInstanceTrue_UsesInstanceState()
        {
            // Arrange
            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext();
            Mock<NodeDesign> mockNode = CreateMockNodeDesignWithInstanceState();
            var generator = new NodeStateGenerator(mockContext.Object, useXmlInitializers: false);
            const string forClass = "TestClass";
            const bool forInstance = true;

            // Act
            generator.AddInitializer(forClass, mockNode.Object, forInstance, null);

            // Assert
            Dictionary<string, Resource> initializers = GetInitializers(generator);
            Assert.That(initializers.Count, Is.EqualTo(1));
        }

        /// <summary>
        /// Tests that AddInitializer uses child.State when child parameter is provided.
        /// Expects the method to use child.State instead of node.State.
        /// </summary>
        [Test]
        public void AddInitializer_WithChildProvided_UsesChildState()
        {
            // Arrange
            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext();
            Mock<NodeDesign> mockNode = CreateMockNodeDesign();
            Mock<NodeDesign> mockChild = CreateMockNodeDesignWithSymbolicName("ChildNode");
            var generator = new NodeStateGenerator(mockContext.Object, useXmlInitializers: false);
            const string forClass = "TestClass";
            const bool forInstance = false;

            // Act
            generator.AddInitializer(forClass, mockNode.Object, forInstance, mockChild.Object);

            // Assert
            Dictionary<string, Resource> initializers = GetInitializers(generator);
            Assert.That(initializers.Count, Is.EqualTo(1));
            Assert.That(initializers.ContainsKey("TestClassInitializers.ChildNodeBinary"), Is.True);
        }

        /// <summary>
        /// Tests that AddInitializer returns early when state is null.
        /// Expects no resource to be added to the initializers dictionary.
        /// </summary>
        [Test]
        public void AddInitializer_WithNullState_ReturnsEarlyWithoutAddingResource()
        {
            // Arrange
            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext();
            var mockNode = new Mock<NodeDesign>();
            mockNode.Setup(n => n.State).Returns((NodeState)null);
            mockNode.Setup(n => n.InstanceState).Returns((NodeState)null);
            var generator = new NodeStateGenerator(mockContext.Object, useXmlInitializers: false);
            const string forClass = "TestClass";
            const bool forInstance = false;

            // Act
            generator.AddInitializer(forClass, mockNode.Object, forInstance, null);

            // Assert
            Dictionary<string, Resource> initializers = GetInitializers(generator);
            Assert.That(initializers.Count, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that AddInitializer returns early when child.State is null.
        /// Expects no resource to be added to the initializers dictionary.
        /// </summary>
        [Test]
        public void AddInitializer_WithChildHavingNullState_ReturnsEarlyWithoutAddingResource()
        {
            // Arrange
            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext();
            Mock<NodeDesign> mockNode = CreateMockNodeDesign();
            var mockChild = new Mock<NodeDesign>();
            mockChild.Setup(c => c.State).Returns((NodeState)null);
            var generator = new NodeStateGenerator(mockContext.Object, useXmlInitializers: false);
            const string forClass = "TestClass";
            const bool forInstance = false;

            // Act
            generator.AddInitializer(forClass, mockNode.Object, forInstance, mockChild.Object);

            // Assert
            Dictionary<string, Resource> initializers = GetInitializers(generator);
            Assert.That(initializers.Count, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that AddInitializer throws InvalidOperationException when duplicate resource name is added.
        /// Expects an InvalidOperationException with a message indicating the duplicate resource name.
        /// </summary>
        [Test]
        public void AddInitializer_WithDuplicateResourceName_ThrowsInvalidOperationException()
        {
            // Arrange
            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext();
            Mock<NodeDesign> mockNode = CreateMockNodeDesign();
            var generator = new NodeStateGenerator(mockContext.Object, useXmlInitializers: false);
            const string forClass = "TestClass";
            const bool forInstance = false;

            // Act
            generator.AddInitializer(forClass, mockNode.Object, forInstance, null);
            InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() =>
                generator.AddInitializer(forClass, mockNode.Object, forInstance, null));

            // Assert
            Assert.That(ex.Message, Does.Contain("Duplicate resource name"));
            Assert.That(ex.Message, Does.Contain("TestClassInitializers.Binary"));
        }

        /// <summary>
        /// Tests that AddInitializer handles null or empty forClass parameter.
        /// Expects the method to create a resource with an empty class name in the resource name.
        /// </summary>
        [TestCase(null, "Initializers.Binary")]
        [TestCase("", "Initializers.Binary")]
        [TestCase("   ", "   Initializers.Binary")]
        public void AddInitializer_WithNullOrEmptyForClass_CreatesResourceWithExpectedName(string forClass, string expectedKeyPrefix)
        {
            // Arrange
            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext();
            Mock<NodeDesign> mockNode = CreateMockNodeDesign();
            var generator = new NodeStateGenerator(mockContext.Object, useXmlInitializers: false);
            const bool forInstance = false;

            // Act
            generator.AddInitializer(forClass, mockNode.Object, forInstance, null);

            // Assert
            Dictionary<string, Resource> initializers = GetInitializers(generator);
            Assert.That(initializers.Count, Is.EqualTo(1));
            Assert.That(initializers.ContainsKey(expectedKeyPrefix), Is.True);
        }

        /// <summary>
        /// Tests that AddInitializer handles special characters in forClass parameter.
        /// Expects the method to create a resource with the special characters included in the resource name.
        /// </summary>
        [TestCase("Test$Class", "Test$ClassInitializers.Binary")]
        [TestCase("Test.Class", "Test.ClassInitializers.Binary")]
        [TestCase("Test<T>", "Test<T>Initializers.Binary")]
        public void AddInitializer_WithSpecialCharactersInForClass_CreatesResourceWithExpectedName(string forClass, string expectedKey)
        {
            // Arrange
            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext();
            Mock<NodeDesign> mockNode = CreateMockNodeDesign();
            var generator = new NodeStateGenerator(mockContext.Object, useXmlInitializers: false);
            const bool forInstance = false;

            // Act
            generator.AddInitializer(forClass, mockNode.Object, forInstance, null);

            // Assert
            Dictionary<string, Resource> initializers = GetInitializers(generator);
            Assert.That(initializers.Count, Is.EqualTo(1));
            Assert.That(initializers.ContainsKey(expectedKey), Is.True);
        }

        /// <summary>
        /// Tests that AddInitializer handles child with null SymbolicName.
        /// Expects the method to create a resource with an empty child name in the resource name.
        /// </summary>
        [Test]
        public void AddInitializer_WithChildHavingNullSymbolicName_CreatesResourceWithEmptyChildName()
        {
            // Arrange
            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext();
            Mock<NodeDesign> mockNode = CreateMockNodeDesign();
            Mock<NodeDesign> mockChild = CreateMockNodeDesign();
            mockChild.Setup(c => c.SymbolicName).Returns((XmlQualifiedName)null);
            var generator = new NodeStateGenerator(mockContext.Object, useXmlInitializers: false);
            const string forClass = "TestClass";
            const bool forInstance = false;

            // Act
            generator.AddInitializer(forClass, mockNode.Object, forInstance, mockChild.Object);

            // Assert
            Dictionary<string, Resource> initializers = GetInitializers(generator);
            Assert.That(initializers.Count, Is.EqualTo(1));
            Assert.That(initializers.ContainsKey("TestClassInitializers.Binary"), Is.True);
        }

        /// <summary>
        /// Tests that AddInitializer handles child with SymbolicName.Name being null.
        /// Expects the method to create a resource with an empty child name in the resource name.
        /// </summary>
        [Test]
        public void AddInitializer_WithChildHavingSymbolicNameWithNullName_CreatesResourceWithEmptyChildName()
        {
            // Arrange
            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext();
            Mock<NodeDesign> mockNode = CreateMockNodeDesign();
            Mock<NodeDesign> mockChild = CreateMockNodeDesign();
            mockChild.Setup(c => c.SymbolicName).Returns(new XmlQualifiedName(null, "namespace"));
            var generator = new NodeStateGenerator(mockContext.Object, useXmlInitializers: false);
            const string forClass = "TestClass";
            const bool forInstance = false;

            // Act
            generator.AddInitializer(forClass, mockNode.Object, forInstance, mockChild.Object);

            // Assert
            Dictionary<string, Resource> initializers = GetInitializers(generator);
            Assert.That(initializers.Count, Is.EqualTo(1));
            Assert.That(initializers.ContainsKey("TestClassInitializers.Binary"), Is.True);
        }

        /// <summary>
        /// Tests that AddInitializer correctly combines forClass, child name, and encoding string.
        /// Expects the method to create a resource with the correct combined name format.
        /// </summary>
        [TestCase("MyClass", "MyChild", false, "MyClassInitializers.MyChildBinary")]
        [TestCase("MyClass", "MyChild", true, "MyClassInitializers.MyChildXml")]
        [TestCase("MyClass", "", false, "MyClassInitializers.Binary")]
        [TestCase("MyClass", "", true, "MyClassInitializers.Xml")]
        public void AddInitializer_WithVariousCombinations_CreatesResourceWithCorrectName(
            string forClass, string childName, bool useXml, string expectedKey)
        {
            // Arrange
            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext();
            Mock<NodeDesign> mockNode = CreateMockNodeDesign();
            Mock<NodeDesign> mockChild = null;
            if (!string.IsNullOrEmpty(childName))
            {
                mockChild = CreateMockNodeDesignWithSymbolicName(childName);
            }
            var generator = new NodeStateGenerator(mockContext.Object, useXmlInitializers: useXml);
            const bool forInstance = false;

            // Act
            generator.AddInitializer(forClass, mockNode.Object, forInstance, mockChild?.Object);

            // Assert
            Dictionary<string, Resource> initializers = GetInitializers(generator);
            Assert.That(initializers.Count, Is.EqualTo(1));
            Assert.That(initializers.ContainsKey(expectedKey), Is.True);
        }

        /// <summary>
        /// Tests that AddInitializer handles forInstance true with null InstanceState.
        /// Expects no resource to be added when InstanceState is null.
        /// </summary>
        [Test]
        public void AddInitializer_WithForInstanceTrueAndNullInstanceState_ReturnsEarlyWithoutAddingResource()
        {
            // Arrange
            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext();
            Mock<NodeDesign> mockNode = CreateMockNodeDesign();
            mockNode.Setup(n => n.InstanceState).Returns((NodeState)null);
            var generator = new NodeStateGenerator(mockContext.Object, useXmlInitializers: false);
            const string forClass = "TestClass";
            const bool forInstance = true;

            // Act
            generator.AddInitializer(forClass, mockNode.Object, forInstance, null);

            // Assert
            Dictionary<string, Resource> initializers = GetInitializers(generator);
            Assert.That(initializers.Count, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that AddInitializer correctly prioritizes child state over node state.
        /// Expects the method to use child.State when child is provided, regardless of forInstance.
        /// </summary>
        [TestCase(true)]
        [TestCase(false)]
        public void AddInitializer_WithChildProvided_PrioritizesChildStateOverNodeState(bool forInstance)
        {
            // Arrange
            Mock<GeneratorContext> mockContext = CreateMockGeneratorContext();
            Mock<NodeDesign> mockNode = CreateMockNodeDesign();
            Mock<NodeDesign> mockChild = CreateMockNodeDesignWithSymbolicName("ChildNode");
            var generator = new NodeStateGenerator(mockContext.Object, useXmlInitializers: false);
            const string forClass = "TestClass";

            // Act
            generator.AddInitializer(forClass, mockNode.Object, forInstance, mockChild.Object);

            // Assert
            Dictionary<string, Resource> initializers = GetInitializers(generator);
            Assert.That(initializers.Count, Is.EqualTo(1));
            Assert.That(initializers.ContainsKey("TestClassInitializers.ChildNodeBinary"), Is.True);
        }

        private Mock<GeneratorContext> CreateMockGeneratorContext()
        {
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockDictionary = new Mock<ModelDesign>();
            var mockNamespaceUris = new Mock<NamespaceTable>();

            mockDictionary.Setup(d => d.NamespaceUris).Returns(mockNamespaceUris.Object);
            mockValidator.Setup(v => v.Dictionary).Returns(mockDictionary.Object);

            var mockContext = new Mock<GeneratorContext>();
            mockContext.Setup(c => c.Telemetry).Returns(mockTelemetry.Object);
            mockContext.Setup(c => c.Validator).Returns(mockValidator.Object);

            return mockContext;
        }

        private Mock<NodeDesign> CreateMockNodeDesign()
        {
            var mockNode = new Mock<NodeDesign>();
            Mock<NodeState> mockState = CreateMockNodeState();
            mockNode.Setup(n => n.State).Returns(mockState.Object);
            mockNode.Setup(n => n.InstanceState).Returns(mockState.Object);
            return mockNode;
        }

        private Mock<NodeDesign> CreateMockNodeDesignWithInstanceState()
        {
            var mockNode = new Mock<NodeDesign>();
            Mock<NodeState> mockState = CreateMockNodeState();
            Mock<NodeState> mockInstanceState = CreateMockNodeState();
            mockNode.Setup(n => n.State).Returns(mockState.Object);
            mockNode.Setup(n => n.InstanceState).Returns(mockInstanceState.Object);
            return mockNode;
        }

        private Mock<NodeDesign> CreateMockNodeDesignWithSymbolicName(string name)
        {
            Mock<NodeDesign> mockNode = CreateMockNodeDesign();
            mockNode.Setup(n => n.SymbolicName).Returns(new XmlQualifiedName(name, "namespace"));
            return mockNode;
        }

        private Mock<NodeState> CreateMockNodeState()
        {
            var mockState = new Mock<NodeState>();
            mockState.Setup(s => s.GetChildren(It.IsAny<ISystemContext>(), It.IsAny<IList<BaseInstanceState>>()));
            mockState.Setup(s => s.SaveAsXml(It.IsAny<ISystemContext>(), It.IsAny<Stream>()))
                .Callback<ISystemContext, Stream>((ctx, stream) =>
                {
                    byte[] data = [0x3C, 0x78, 0x6D, 0x6C, 0x3E]; // "<xml>"
                    stream.Write(data, 0, data.Length);
                });
            mockState.Setup(s => s.SaveAsBinary(It.IsAny<ISystemContext>(), It.IsAny<Stream>()))
                .Callback<ISystemContext, Stream>((ctx, stream) =>
                {
                    byte[] data = [0x01, 0x02, 0x03, 0x04, 0x05];
                    stream.Write(data, 0, data.Length);
                });
            return mockState;
        }

        private Dictionary<string, Resource> GetInitializers(NodeStateGenerator generator)
        {
            FieldInfo field = typeof(NodeStateGenerator).GetField("m_initializers",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            return (Dictionary<string, Resource>)field.GetValue(generator);
        }
    }
}
