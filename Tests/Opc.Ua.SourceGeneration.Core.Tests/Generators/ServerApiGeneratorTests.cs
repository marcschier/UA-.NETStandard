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

using Moq;
using NUnit.Framework;
using Opc.Ua.Schema.Model;

namespace Opc.Ua.SourceGeneration.Generator.Tests
{
    /// <summary>
    /// Unit tests for the ServerApiGenerator class.
    /// </summary>
    [TestFixture]
    [Category("Generator")]
    [SetCulture("en-us")]
    [SetUICulture("en-us")]
    [Parallelizable]
    public class ServerApiGeneratorTests
    {
        /// <summary>
        /// Tests that the constructor successfully creates an instance when provided with a valid GeneratorContext.
        /// Input: Valid GeneratorContext with all required properties initialized.
        /// Expected: ServerApiGenerator instance is created without throwing exceptions.
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
                OutputFolder = "output",
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            // Act
            var generator = new ServerApiGenerator(context);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor accepts a null context parameter.
        /// Input: Null GeneratorContext.
        /// Expected: ServerApiGenerator instance is created without throwing exceptions during construction.
        /// </summary>
        [Test]
        public void Constructor_NullContext_CreatesInstance()
        {
            // Arrange
            GeneratorContext context = null;

            // Act
            var generator = new ServerApiGenerator(context);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor successfully creates an instance with minimal valid context configuration.
        /// Input: GeneratorContext with empty string for OutputFolder and mocked dependencies.
        /// Expected: ServerApiGenerator instance is created without throwing exceptions.
        /// </summary>
        [Test]
        public void Constructor_ContextWithEmptyOutputFolder_CreatesInstance()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockOptions = new Mock<GeneratorOptions>();

            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = string.Empty,
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            // Act
            var generator = new ServerApiGenerator(context);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor successfully creates an instance with a context containing a long output folder path.
        /// Input: GeneratorContext with a very long OutputFolder string.
        /// Expected: ServerApiGenerator instance is created without throwing exceptions.
        /// </summary>
        [Test]
        public void Constructor_ContextWithLongOutputFolder_CreatesInstance()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockOptions = new Mock<GeneratorOptions>();

            string longPath = new('a', 10000);
            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = longPath,
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };

            // Act
            var generator = new ServerApiGenerator(context);

            // Assert
            Assert.That(generator, Is.Not.Null);
        }
    }
}
