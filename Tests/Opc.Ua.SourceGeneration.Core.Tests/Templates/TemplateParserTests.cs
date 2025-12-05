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

using System.Linq;
using NUnit.Framework;

namespace Opc.Ua.SourceGeneration.Tests.Templating
{
    [TestFixture]
    public class TemplateParserTests
    {
        [Test]
        public void CreateFromParser_WithLiteralsOnly_CreatesValidTemplateString()
        {
            // Arrange
            var parser = new TemplateParser(10, 0);
            parser.AppendLiteral("Hello");
            parser.AppendLiteral(" ");
            parser.AppendLiteral("World");

            // Act
            var templateString = TemplateString.Parse(parser);

            // Assert
            Assert.That(templateString, Is.Not.Null);
            Assert.That(templateString.ParsedTemplate, Is.Not.Null);
            Assert.That(templateString.ParsedTemplate.LiteralLength, Is.EqualTo(10));
            Assert.That(templateString.ParsedTemplate.FormattedCount, Is.EqualTo(0));
        }

        [Test]
        public void CreateFromParser_WithTokens_CreatesValidTemplateString()
        {
            // Arrange
            var parser = new TemplateParser(5, 2);
            parser.AppendLiteral("Hello");
            parser.AppendFormatted("World");
            parser.AppendLiteral(" ");
            parser.AppendFormatted(42);

            // Act
            var templateString = TemplateString.Parse(parser);

            // Assert
            Assert.That(templateString, Is.Not.Null);
            Assert.That(templateString.ParsedTemplate, Is.Not.Null);
            Assert.That(templateString.ParsedTemplate.LiteralLength, Is.EqualTo(5));
            Assert.That(templateString.ParsedTemplate.FormattedCount, Is.EqualTo(2));
        }

        [Test]
        public void Constructor_InitializesCorrectly()
        {
            // Arrange & Act
            var parser = new TemplateParser(10, 5);

            // Assert
            Assert.That(parser.Parsed, Is.Not.Null);
            Assert.That(parser.Parsed.LiteralLength, Is.EqualTo(10));
            Assert.That(parser.Parsed.FormattedCount, Is.EqualTo(5));
        }

        [Test]
        public void AppendLiteral_AddsLiteralCorrectly()
        {
            // Arrange
            var parser = new TemplateParser(5, 0);
            const string literal = "Hello";

            // Act
            parser.AppendLiteral(literal);

            // Assert
            var operations = parser.Parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(1));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.Literal));
            Assert.That(operations[0].Item, Is.EqualTo(literal));
        }

        [Test]
        public void AppendFormatted_AddsTokenCorrectly()
        {
            // Arrange
            var parser = new TemplateParser(0, 1);
            const string value = "TestValue";

            // Act
            parser.AppendFormatted(value);

            // Assert
            var operations = parser.Parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(1));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.Token));
            Assert.That(operations[0].Item, Is.EqualTo(value));
        }

        [Test]
        public void AppendFormatted_WithInteger_ConvertsToString()
        {
            // Arrange
            var parser = new TemplateParser(0, 1);
            const int value = 42;

            // Act
            parser.AppendFormatted(value);

            // Assert
            var operations = parser.Parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(1));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.Value));
            Assert.That(operations[0].Item, Is.EqualTo("42"));
        }

        [Test]
        public void GetFormattedText_ReturnsCorrectString()
        {
            // Arrange
            var parser = new TemplateParser(6, 1);
            parser.AppendLiteral("Hello ");
            parser.AppendFormatted("World");

            // Act
            string result = parser.GetFormattedText();

            // Assert
            Assert.That(result, Is.EqualTo("Hello World"));
        }
    }
}
