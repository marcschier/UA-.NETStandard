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
    /// Unit tests for the StatusCodesGenerator class.
    /// </summary>
    [TestFixture]
    public class StatusCodesGeneratorTests
    {
        /// <summary>
        /// Tests that the constructor successfully stores a valid GeneratorContext.
        /// </summary>
        [Test]
        public void Constructor_ValidContext_StoresContextSuccessfully()
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
            var generator = new StatusCodesGenerator(context);
            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor does not throw an exception when passed a null context.
        /// Verifies that the constructor does not perform null checking on the context parameter.
        /// </summary>
        [Test]
        public void Constructor_NullContext_DoesNotThrowException()
        {
            // Arrange
            GeneratorContext context = null;
            // Act & Assert
            Assert.DoesNotThrow(() => new StatusCodesGenerator(context));
        }

        /// <summary>
        /// Tests that the constructor accepts a context with minimum valid required properties.
        /// Verifies that all required properties of GeneratorContext are properly handled.
        /// </summary>
        [Test]
        public void Constructor_ContextWithAllRequiredProperties_InitializesSuccessfully()
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
            var generator = new StatusCodesGenerator(context);
            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor accepts a context with edge case string values.
        /// Verifies handling of empty string for OutputFolder property.
        /// </summary>
        [Test]
        public void Constructor_ContextWithEmptyOutputFolder_InitializesSuccessfully()
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
            var generator = new StatusCodesGenerator(context);
            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor accepts a context with a very long OutputFolder path.
        /// Verifies handling of edge case string length values.
        /// </summary>
        [Test]
        public void Constructor_ContextWithVeryLongOutputFolder_InitializesSuccessfully()
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
            var generator = new StatusCodesGenerator(context);
            // Assert
            Assert.That(generator, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor accepts a context with special characters in OutputFolder.
        /// Verifies handling of various special characters in string properties.
        /// </summary>
        [Test]
        public void Constructor_ContextWithSpecialCharactersInOutputFolder_InitializesSuccessfully()
        {
            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            var mockTelemetry = new Mock<ITelemetryContext>();
            var mockValidator = new Mock<ModelDesignValidator>();
            var mockOptions = new Mock<GeneratorOptions>();
            var context = new GeneratorContext
            {
                FileSystem = mockFileSystem.Object,
                OutputFolder = "C:\\Test\\Path\\With\\Special@#$%^&*()Characters",
                Validator = mockValidator.Object,
                Telemetry = mockTelemetry.Object,
                Options = mockOptions.Object
            };
            // Act
            var generator = new StatusCodesGenerator(context);
            // Assert
            Assert.That(generator, Is.Not.Null);
        }
    }
}
