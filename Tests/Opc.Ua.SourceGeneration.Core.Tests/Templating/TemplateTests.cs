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
using NUnit.Framework;

namespace Opc.Ua.SourceGeneration.Templating.Tests
{
    /// <summary>
    /// Unit tests for the <see cref="Template"/> class constructor.
    /// </summary>
    [TestFixture]
    public partial class TemplateTests
    {
        /// <summary>
        /// Tests that the constructor successfully creates a Template instance with valid parameters.
        /// Validates that the Template object is created and can be used for basic operations.
        /// </summary>
        [Test]
        public void Constructor_WithValidParameters_CreatesTemplateSuccessfully()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            using var writer = new TemplateWriter(stringWriter);
            TemplateString templateString = "test template content";

            // Act
            var template = new Template(writer, templateString);

            // Assert
            Assert.That(template, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor accepts an empty TemplateString.
        /// Validates that the Template can be created with an empty template.
        /// </summary>
        [Test]
        public void Constructor_WithEmptyTemplateString_CreatesTemplateSuccessfully()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            using var writer = new TemplateWriter(stringWriter);
            TemplateString templateString = TemplateString.Empty;

            // Act
            var template = new Template(writer, templateString);

            // Assert
            Assert.That(template, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the constructor accepts a null TemplateWriter parameter.
        /// The constructor does not validate parameters, so null is stored and may cause issues during later usage.
        /// Expected result: Constructor succeeds without throwing.
        /// </summary>
        [Test]
        public void Constructor_WithNullWriter_DoesNotThrow()
        {
            // Arrange
            TemplateString templateString = "test template content";

            // Act & Assert
            Assert.DoesNotThrow(() => new Template(null, templateString));
        }

        /// <summary>
        /// Tests that the constructor accepts a null TemplateString parameter.
        /// The constructor does not validate parameters, so null is stored and may cause issues during later usage.
        /// Expected result: Constructor succeeds without throwing.
        /// </summary>
        [Test]
        public void Constructor_WithNullTemplateString_DoesNotThrow()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            using var writer = new TemplateWriter(stringWriter);

            // Act & Assert
            Assert.DoesNotThrow(() => new Template(writer, null));
        }

        /// <summary>
        /// Tests that the constructor accepts both null parameters.
        /// The constructor does not validate parameters, so nulls are stored and may cause issues during later usage.
        /// Expected result: Constructor succeeds without throwing.
        /// </summary>
        [Test]
        public void Constructor_WithBothParametersNull_DoesNotThrow()
        {
            // Act & Assert
            Assert.DoesNotThrow(() => new Template(null, null));
        }

        /// <summary>
        /// Tests that a Template created with valid parameters can successfully add replacements.
        /// Validates that the internal initialization (including default replacements) works correctly.
        /// </summary>
        [Test]
        public void Constructor_WithValidParameters_AllowsAddingReplacements()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            using var writer = new TemplateWriter(stringWriter);
            TemplateString templateString = "test template content";

            // Act
            var template = new Template(writer, templateString);

            // Assert
            Assert.DoesNotThrow(() => template.AddReplacement("TestToken", "TestValue"));
        }

        /// <summary>
        /// Tests that a Template can be created with a template string containing special characters.
        /// Validates that the constructor handles various string content correctly.
        /// </summary>
        [Test]
        public void Constructor_WithSpecialCharactersInTemplateString_CreatesTemplateSuccessfully()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            using var writer = new TemplateWriter(stringWriter);
            TemplateString templateString = "template with special chars: \n\r\t@#$%^&*(){}[]<>|\\";

            // Act
            var template = new Template(writer, templateString);

            // Assert
            Assert.That(template, Is.Not.Null);
        }

        /// <summary>
        /// Tests that a Template can be created with a very long template string.
        /// Validates that the constructor handles large string content without issues.
        /// </summary>
        [Test]
        public void Constructor_WithVeryLongTemplateString_CreatesTemplateSuccessfully()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            using var writer = new TemplateWriter(stringWriter);
            TemplateString templateString = (string)new('x', 10000);

            // Act
            var template = new Template(writer, templateString);

            // Assert
            Assert.That(template, Is.Not.Null);
        }

        /// <summary>
        /// Tests that a Template can be created with a whitespace-only template string.
        /// Validates that the constructor handles whitespace content correctly.
        /// </summary>
        [Test]
        public void Constructor_WithWhitespaceOnlyTemplateString_CreatesTemplateSuccessfully()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            using var writer = new TemplateWriter(stringWriter);
            TemplateString templateString = "   \t\n\r   ";

            // Act
            var template = new Template(writer, templateString);

            // Assert
            Assert.That(template, Is.Not.Null);
        }

        /// <summary>
        /// Tests that AddReplacement with valid token and replacement strings stores the values correctly
        /// and can be rendered successfully.
        /// </summary>
        [Test]
        public void AddReplacement_ValidTokenAndReplacement_StoresValueSuccessfully()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            Template template;
            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);

            // Act
            // Assert - verify no exception is thrown
            Assert.DoesNotThrow(() => template.AddReplacement("TestToken", "TestReplacement"));
        }

        /// <summary>
        /// Tests that AddReplacement with empty string token stores the value successfully.
        /// </summary>
        [Test]
        public void AddReplacement_EmptyToken_StoresValueSuccessfully()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            Template template;
            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);

            // Act & Assert
            Assert.DoesNotThrow(() => template.AddReplacement(string.Empty, "TestReplacement"));
        }

        /// <summary>
        /// Tests that AddReplacement with whitespace-only token stores the value successfully.
        /// </summary>
        [Test]
        public void AddReplacement_WhitespaceToken_StoresValueSuccessfully()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            Template template;
            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);

            // Act & Assert
            Assert.DoesNotThrow(() => template.AddReplacement("   ", "TestReplacement"));
        }

        /// <summary>
        /// Tests that AddReplacement with null replacement stores the null value successfully.
        /// </summary>
        [Test]
        public void AddReplacement_NullReplacement_StoresValueSuccessfully()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            Template template;
            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);

            // Act & Assert
            Assert.DoesNotThrow(() => template.AddReplacement("TestToken", (string)null));
        }

        /// <summary>
        /// Tests that AddReplacement with empty replacement string stores the value successfully.
        /// </summary>
        [Test]
        public void AddReplacement_EmptyReplacement_StoresValueSuccessfully()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            Template template;
            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);

            // Act & Assert
            Assert.DoesNotThrow(() => template.AddReplacement("TestToken", string.Empty));
        }

        /// <summary>
        /// Tests that AddReplacement with whitespace-only replacement stores the value successfully.
        /// </summary>
        [Test]
        public void AddReplacement_WhitespaceReplacement_StoresValueSuccessfully()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            Template template;
            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);

            // Act & Assert
            Assert.DoesNotThrow(() => template.AddReplacement("TestToken", "   "));
        }

        /// <summary>
        /// Tests that AddReplacement with very long token string stores the value successfully.
        /// </summary>
        [Test]
        public void AddReplacement_VeryLongToken_StoresValueSuccessfully()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            Template template;
            string veryLongToken = new('A', 10000);
            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);

            // Act & Assert
            Assert.DoesNotThrow(() => template.AddReplacement(veryLongToken, "TestReplacement"));
        }

        /// <summary>
        /// Tests that AddReplacement with very long replacement string stores the value successfully.
        /// </summary>
        [Test]
        public void AddReplacement_VeryLongReplacement_StoresValueSuccessfully()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            Template template;
            string veryLongReplacement = new('B', 10000);
            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);

            // Act & Assert
            Assert.DoesNotThrow(() => template.AddReplacement("TestToken", veryLongReplacement));
        }

        /// <summary>
        /// Tests that AddReplacement with special characters in token stores the value successfully.
        /// </summary>
        /// <param name="token">The token with special characters.</param>
        [TestCase("Test\nToken")]
        [TestCase("Test\rToken")]
        [TestCase("Test\tToken")]
        [TestCase("Test\0Token")]
        [TestCase("Test\"Token")]
        [TestCase("Test'Token")]
        [TestCase("Test\\Token")]
        [TestCase("Test!@#$%^&*()Token")]
        [TestCase("Test<>Token")]
        [TestCase("Test{}Token")]
        [TestCase("Test[]Token")]
        public void AddReplacement_TokenWithSpecialCharacters_StoresValueSuccessfully(string token)
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            Template template;
            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);

            // Act & Assert
            Assert.DoesNotThrow(() => template.AddReplacement(token, "TestReplacement"));
        }

        /// <summary>
        /// Tests that AddReplacement with special characters in replacement stores the value successfully.
        /// </summary>
        /// <param name="replacement">The replacement with special characters.</param>
        [TestCase("Test\nReplacement")]
        [TestCase("Test\rReplacement")]
        [TestCase("Test\tReplacement")]
        [TestCase("Test\0Replacement")]
        [TestCase("Test\"Replacement")]
        [TestCase("Test'Replacement")]
        [TestCase("Test\\Replacement")]
        [TestCase("Test!@#$%^&*()Replacement")]
        [TestCase("Test<>Replacement")]
        [TestCase("Test{}Replacement")]
        [TestCase("Test[]Replacement")]
        public void AddReplacement_ReplacementWithSpecialCharacters_StoresValueSuccessfully(string replacement)
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            Template template;
            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);

            // Act & Assert
            Assert.DoesNotThrow(() => template.AddReplacement("TestToken", replacement));
        }

        /// <summary>
        /// Tests that AddReplacement updates existing token when called multiple times with the same token.
        /// </summary>
        [Test]
        public void AddReplacement_CalledTwiceWithSameToken_UpdatesValue()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            Template template;
            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);

            // Act
            template.AddReplacement("TestToken", "FirstValue");

            // Assert - should not throw when updating
            Assert.DoesNotThrow(() => template.AddReplacement("TestToken", "SecondValue"));
        }

        /// <summary>
        /// Tests that AddReplacement can store multiple distinct tokens.
        /// </summary>
        [Test]
        public void AddReplacement_MultipleDistinctTokens_StoresAllValuesSuccessfully()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            Template template;
            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);

            // Act & Assert
            Assert.DoesNotThrow(() =>
            {
                template.AddReplacement("Token1", "Value1");
                template.AddReplacement("Token2", "Value2");
                template.AddReplacement("Token3", "Value3");
            });
        }

        /// <summary>
        /// Tests that AddReplacement works correctly with unicode characters in token.
        /// </summary>
        [Test]
        public void AddReplacement_UnicodeToken_StoresValueSuccessfully()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            Template template;
            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);

            // Act & Assert
            Assert.DoesNotThrow(() => template.AddReplacement("Test\u00E9\u4E2D\u0416Token", "TestReplacement"));
        }

        /// <summary>
        /// Tests that AddReplacement works correctly with unicode characters in replacement.
        /// </summary>
        [Test]
        public void AddReplacement_UnicodeReplacement_StoresValueSuccessfully()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            Template template;
            using var templateWriter = new TemplateWriter(writer);
            template = new Template(templateWriter, templateString);

            // Act & Assert
            Assert.DoesNotThrow(() => template.AddReplacement("TestToken", "Test\u00E9\u4E2D\u0416Replacement"));
        }

        /// <summary>
        /// Tests that AddReplacement integrates correctly with Render method using actual token replacements.
        /// </summary>
        [Test]
        public void AddReplacement_IntegrationWithRender_ReplacesTokenCorrectly()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseNames_cs;
            using (var templateWriter = new TemplateWriter(writer))
            {
                var template = new Template(templateWriter, templateString);

                // Act
                template.AddReplacement(Tokens.SymbolicName, "MyTestName");
                template.AddReplacement(Tokens.BrowseName, "MyTestBrowseName");

                template.Render();
            }
            string result = writer.ToString();

            // Assert
            Assert.That(result, Does.Contain("MyTestName"));
            Assert.That(result, Does.Contain("MyTestBrowseName"));
        }

        /// <summary>
        /// Tests that Render returns false when the template string has no operations.
        /// Input: Empty template string.
        /// Expected: Returns false, no output written.
        /// </summary>
        [Test]
        public void Render_EmptyTemplate_ReturnsFalse()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = string.Empty;
            using var templateWriter = new TemplateWriter(writer);
            var template = new Template(templateWriter, templateString);

            // Act
            bool result = template.Render();

            // Assert
            Assert.That(result, Is.False);
            Assert.That(writer.ToString(), Is.Empty);
        }

        /// <summary>
        /// Tests that Render writes a literal and returns true.
        /// Input: Template with single literal operation.
        /// Expected: Returns true, literal is written to output.
        /// </summary>
        [Test]
        public void Render_LiteralOnly_WritesLiteralAndReturnsTrue()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = "Hello World";
            using var templateWriter = new TemplateWriter(writer);
            var template = new Template(templateWriter, templateString);

            // Act
            bool result = template.Render();

            // Assert
            Assert.That(result, Is.True);
            Assert.That(writer.ToString(), Is.EqualTo("Hello World"));
        }

        /// <summary>
        /// Tests that Render writes whitespace and returns true.
        /// Input: Template with whitespace operation.
        /// Expected: Returns true, whitespace is written to output.
        /// </summary>
        [Test]
        public void Render_WhitespaceOnly_WritesWhitespaceAndReturnsTrue()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = "    ";
            using var templateWriter = new TemplateWriter(writer);
            var template = new Template(templateWriter, templateString);

            // Act
            bool result = template.Render();

            // Assert
            Assert.That(result, Is.True);
            Assert.That(writer.ToString(), Is.EqualTo("    "));
        }

        /// <summary>
        /// Tests that Render writes a newline and returns true.
        /// Input: Template with line break operation.
        /// Expected: Returns true, newline is written to output.
        /// </summary>
        [Test]
        public void Render_LineBreakOnly_WritesNewLineAndReturnsTrue()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = "\n";
            using var templateWriter = new TemplateWriter(writer);
            var template = new Template(templateWriter, templateString);

            // Act
            bool result = template.Render();

            // Assert
            Assert.That(result, Is.True);
            Assert.That(writer.ToString(), Is.EqualTo(Environment.NewLine));
        }

        /// <summary>
        /// Tests that Render writes multiple line breaks correctly.
        /// Input: Template with multiple line break operations.
        /// Expected: Returns true, multiple newlines are written to output.
        /// </summary>
        [Test]
        public void Render_MultipleLineBreaks_WritesNewLinesAndReturnsTrue()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = "Line1\nLine2\nLine3";
            using var templateWriter = new TemplateWriter(writer);
            var template = new Template(templateWriter, templateString);

            // Act
            bool result = template.Render();

            // Assert
            Assert.That(result, Is.True);
            string expected = $"Line1{Environment.NewLine}Line2{Environment.NewLine}Line3";
            Assert.That(writer.ToString(), Is.EqualTo(expected));
        }

        /// <summary>
        /// Tests that Render handles extreme edge case of very long string literal.
        /// Input: Template with very long literal string.
        /// Expected: Returns true, entire string is written.
        /// </summary>
        [Test]
        public void Render_VeryLongLiteral_WritesEntireString()
        {
            // Arrange
            using var writer = new StringWriter();
            string longString = new('A', 10000);
            TemplateString templateString = longString;
            using var templateWriter = new TemplateWriter(writer);
            var template = new Template(templateWriter, templateString);

            // Act
            bool result = template.Render();

            // Assert
            Assert.That(result, Is.True);
            Assert.That(writer.ToString(), Is.EqualTo(longString));
        }
    }
}
