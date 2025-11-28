/* ========================================================================
 * Copyright (c) 2005-2024 The OPC Foundation, Inc. All rights reserved.
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
using System.Globalization;
using System.Linq;
using NUnit.Framework;

namespace Opc.Ua.SourceGeneration.Tests.Templating
{
    [TestFixture]
    public class ParsedTemplateStringTests
    {
        [Test]
        public void FromString_SimpleString_ParsesCorrectly()
        {
            // Arrange
            const string input = "Hello World";

            // Act
            var parsed = ParsedTemplateString.FromString(input);

            // Assert
            Assert.That(parsed.LiteralLength, Is.EqualTo(input.Length));
            Assert.That(parsed.FormattedCount, Is.EqualTo(0));
            Assert.That(parsed.ArgumentCount, Is.EqualTo(0));
            Assert.That(parsed.Format, Is.EqualTo(input));
        }

        [Test]
        public void FromString_WithNewlines_ParsesLineBreaksCorrectly()
        {
            // Arrange
            const string input = "Line1\nLine2\r\nLine3";

            // Act
            var parsed = ParsedTemplateString.FromString(input);

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations.Any(op => op.Type == ParsedTemplateString.OpType.LineBreak), Is.True);
            Assert.That(operations.Count(op => op.Type == ParsedTemplateString.OpType.LineBreak), Is.EqualTo(2));
        }

        [Test]
        public void FromString_WithWhitespace_ParsesWhitespaceCorrectly()
        {
            // Arrange
            const string input = "   \t   ";

            // Act
            var parsed = ParsedTemplateString.FromString(input);

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(1));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.WhiteSpace));
            Assert.That(operations[0].Item, Is.EqualTo(input));
        }

        [Test]
        public void AddLiteral_EmptyString_DoesNotAddOperation()
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 0);

            // Act
            parsed.AddLiteral(string.Empty);

            // Assert
            Assert.That(parsed.Operations.Count, Is.EqualTo(0));
        }

        [Test]
        public void AddLiteral_MultilineText_SplitsIntoCorrectOperations()
        {
            // Arrange
            var parsed = new ParsedTemplateString(20, 0);
            const string multilineText = "Line1\nLine2\nLine3";

            // Act
            parsed.AddLiteral(multilineText);

            // Assert
            var operations = parsed.Operations.ToList();
            var literalOps = operations.Where(op => op.Type == ParsedTemplateString.OpType.Literal).ToList();
            var lineBreakOps = operations.Where(op => op.Type == ParsedTemplateString.OpType.LineBreak).ToList();

            Assert.That(literalOps, Has.Count.EqualTo(3));
            Assert.That(lineBreakOps, Has.Count.EqualTo(2));
            Assert.That(literalOps[0].Item, Is.EqualTo("Line1"));
            Assert.That(literalOps[1].Item, Is.EqualTo("Line2"));
            Assert.That(literalOps[2].Item, Is.EqualTo("Line3"));
        }

        [Test]
        public void AddFormatted_AddsTokenOperation()
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 1);
            const string token = "TestToken";

            // Act
            parsed.AddFormatted(token, typeof(string));

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(1));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.Token));
            Assert.That(operations[0].Item, Is.EqualTo(token));
        }

        [Test]
        public void GetArguments_WithTokens_ReturnsCorrectArguments()
        {
            // Arrange
            var parsed = new ParsedTemplateString(10, 2);
            parsed.AddLiteral("Hello ");
            parsed.AddFormatted("World", typeof(string));
            parsed.AddLiteral(" ");
            parsed.AddFormatted("42", typeof(int));

            // Act
            object[] arguments = parsed.GetArguments();

            // Assert
            Assert.That(arguments, Has.Length.EqualTo(2));
            Assert.That(arguments[0], Is.EqualTo("World"));
            Assert.That(arguments[1], Is.EqualTo("42"));
        }

        [Test]
        public void GetArgument_ValidIndex_ReturnsCorrectArgument()
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 1);
            parsed.AddFormatted("TestValue", typeof(string));

            // Act
            object argument = parsed.GetArgument(0);

            // Assert
            Assert.That(argument, Is.EqualTo("TestValue"));
        }

        [Test]
        public void GetArgument_InvalidIndex_ThrowsIndexOutOfRangeException()
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 0);

            // Act & Assert
            Assert.Throws<IndexOutOfRangeException>(() => parsed.GetArgument(0));
        }

        [Test]
        public void ToString_WithFormatProvider_FormatsCorrectly()
        {
            // Arrange
            var parsed = new ParsedTemplateString(6, 1);
            parsed.AddLiteral("Hello ");
            parsed.AddFormatted("World", typeof(string));

            // Act
            string result = parsed.ToString(CultureInfo.InvariantCulture);

            // Assert
            Assert.That(result, Is.EqualTo("Hello World"));
        }

        [Test]
        public void Format_Property_ReturnsCorrectFormatString()
        {
            // Arrange
            var parsed = new ParsedTemplateString(6, 1);
            parsed.AddLiteral("Hello ");
            parsed.AddFormatted("World", typeof(string));

            // Act
            string format = parsed.Format;

            // Assert
            Assert.That(format, Is.EqualTo("Hello World"));
        }

        [Test]
        public void Operations_Property_ReturnsAllOperations()
        {
            // Arrange
            var parsed = new ParsedTemplateString(10, 1);
            parsed.AddLiteral("Hello ");
            parsed.AddFormatted("World", typeof(string));
            parsed.AddLiteral("!");

            // Act
            var operations = parsed.Operations.ToList();

            // Assert
            Assert.That(operations, Has.Count.EqualTo(3));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.Literal));
            Assert.That(operations[1].Type, Is.EqualTo(ParsedTemplateString.OpType.Token));
            Assert.That(operations[2].Type, Is.EqualTo(ParsedTemplateString.OpType.Literal));
        }

        [Test]
        public void Operation_Record_PropertiesSetCorrectly()
        {
            // Arrange & Act
            var op = new ParsedTemplateString.Op(
                ParsedTemplateString.OpType.Literal,
                "TestItem",
                5,
                2);

            // Assert
            Assert.That(op.Type, Is.EqualTo(ParsedTemplateString.OpType.Literal));
            Assert.That(op.Item, Is.EqualTo("TestItem"));
            Assert.That(op.Offset, Is.EqualTo(5));
            Assert.That(op.LineNumber, Is.EqualTo(2));
        }

        [Test]
        public void AddLiteral_OnlyNewlines_CreatesLineBreakOperationsOnly()
        {
            // Arrange
            var parsed = new ParsedTemplateString(2, 0);

            // Act
            parsed.AddLiteral("\n\r");

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(2));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.LineBreak));
            Assert.That(operations[1].Type, Is.EqualTo(ParsedTemplateString.OpType.WhiteSpace));
        }

        [Test]
        public void LineNumberAndOffset_TrackedCorrectly()
        {
            // Arrange
            var parsed = new ParsedTemplateString(15, 1);

            // Act
            parsed.AddLiteral("First\nSecond");
            parsed.AddFormatted("Token", typeof(string));

            // Assert
            var operations = parsed.Operations.ToList();

            // First literal should be on line 0
            Assert.That(operations[0].LineNumber, Is.EqualTo(0));
            Assert.That(operations[0].Offset, Is.EqualTo(0));

            // Line break should be on line 0
            Assert.That(operations[1].LineNumber, Is.EqualTo(0));
            Assert.That(operations[1].Offset, Is.EqualTo(5));

            // Second literal should be on line 1
            Assert.That(operations[2].LineNumber, Is.EqualTo(1));
            Assert.That(operations[2].Offset, Is.EqualTo(0));

            // Token should be on line 1
            Assert.That(operations[3].LineNumber, Is.EqualTo(1));
            Assert.That(operations[3].Offset, Is.EqualTo(6));
        }
    }
}
