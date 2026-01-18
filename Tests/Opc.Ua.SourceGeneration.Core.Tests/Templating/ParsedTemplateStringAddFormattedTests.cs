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
using System.Linq;
using NUnit.Framework;

namespace Opc.Ua.SourceGeneration.Templating.Tests
{
    /// <summary>
    /// Unit tests for the AddFormatted method of ParsedTemplateString class.
    /// </summary>
    [TestFixture]
    public partial class ParsedTemplateStringAddFormattedTests
    {
        /// <summary>
        /// Tests that AddFormatted with string type creates a Token operation.
        /// Input: item = "TestToken", type = typeof(string)
        /// Expected: Operation with OpType.Token is added to Operations list.
        /// </summary>
        [Test]
        public void AddFormatted_WithStringType_AddsTokenOperation()
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 1);
            const string item = "TestToken";

            // Act
            parsed.AddFormatted(item, typeof(string));

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(1));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.Token));
            Assert.That(operations[0].Item, Is.EqualTo(item));
            Assert.That(operations[0].Offset, Is.EqualTo(0));
            Assert.That(operations[0].LineNumber, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that AddFormatted with non-string types creates a Value operation.
        /// Input: item with various non-string types (int, double, object, bool, decimal)
        /// Expected: Operation with OpType.Value is added for each type.
        /// </summary>
        [TestCase(typeof(int), "42")]
        [TestCase(typeof(double), "3.14")]
        [TestCase(typeof(object), "Object")]
        [TestCase(typeof(bool), "True")]
        [TestCase(typeof(decimal), "100.50")]
        [TestCase(typeof(long), "9223372036854775807")]
        [TestCase(typeof(char), "A")]
        public void AddFormatted_WithNonStringType_AddsValueOperation(Type type, string item)
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 1);

            // Act
            parsed.AddFormatted(item, type);

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(1));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.Value));
            Assert.That(operations[0].Item, Is.EqualTo(item));
        }

        /// <summary>
        /// Tests that AddFormatted with empty string adds operation and maintains offset at zero.
        /// Input: item = "", type = typeof(string)
        /// Expected: Operation is added with empty item, offset remains 0.
        /// </summary>
        [Test]
        public void AddFormatted_WithEmptyString_AddsOperationAndMaintainsOffset()
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 1);
            const string item = "";

            // Act
            parsed.AddFormatted(item, typeof(string));

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(1));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.Token));
            Assert.That(operations[0].Item, Is.EqualTo(item));
            Assert.That(operations[0].Offset, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that AddFormatted with null string throws NullReferenceException.
        /// Input: item = null, type = typeof(string)
        /// Expected: NullReferenceException is thrown when accessing item.Length.
        /// </summary>
        [Test]
        public void AddFormatted_WithNullString_ThrowsNullReferenceException()
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 1);

            // Act & Assert
            Assert.Throws<NullReferenceException>(() => parsed.AddFormatted(null, typeof(string)));
        }

        /// <summary>
        /// Tests that AddFormatted correctly increments offset after adding operation.
        /// Input: item = "Test" (length 4), type = typeof(string)
        /// Expected: Offset in operation is 0, subsequent operation would have offset 4.
        /// </summary>
        [Test]
        public void AddFormatted_SingleCall_IncrementsOffsetCorrectly()
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 2);
            const string firstItem = "Test";
            const string secondItem = "Value";

            // Act
            parsed.AddFormatted(firstItem, typeof(string));
            parsed.AddFormatted(secondItem, typeof(int));

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(2));
            Assert.That(operations[0].Offset, Is.EqualTo(0));
            Assert.That(operations[1].Offset, Is.EqualTo(firstItem.Length));
        }

        /// <summary>
        /// Tests that multiple calls to AddFormatted accumulate operations correctly.
        /// Input: Multiple AddFormatted calls with different items and types
        /// Expected: All operations are added, offsets increment correctly.
        /// </summary>
        [Test]
        public void AddFormatted_MultipleCalls_AccumulatesOperationsAndOffsetsCorrectly()
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 3);
            const string item1 = "Hello";
            const string item2 = "123";
            const string item3 = "World";

            // Act
            parsed.AddFormatted(item1, typeof(string));
            parsed.AddFormatted(item2, typeof(int));
            parsed.AddFormatted(item3, typeof(string));

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(3));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.Token));
            Assert.That(operations[0].Item, Is.EqualTo(item1));
            Assert.That(operations[0].Offset, Is.EqualTo(0));
            Assert.That(operations[1].Type, Is.EqualTo(ParsedTemplateString.OpType.Value));
            Assert.That(operations[1].Item, Is.EqualTo(item2));
            Assert.That(operations[1].Offset, Is.EqualTo(item1.Length));
            Assert.That(operations[2].Type, Is.EqualTo(ParsedTemplateString.OpType.Token));
            Assert.That(operations[2].Item, Is.EqualTo(item3));
            Assert.That(operations[2].Offset, Is.EqualTo(item1.Length + item2.Length));
        }

        /// <summary>
        /// Tests that AddFormatted handles strings with special characters correctly.
        /// Input: item with special characters, type = typeof(string)
        /// Expected: Operation is added with the exact string including special characters.
        /// </summary>
        [TestCase("Hello\tWorld")]
        [TestCase("Line1\nLine2")]
        [TestCase("Quote\"Test")]
        [TestCase("Backslash\\Test")]
        [TestCase("Unicode\u00A9\u00AE")]
        [TestCase("Mixed!@#$%^&*()")]
        public void AddFormatted_WithSpecialCharacters_AddsOperationCorrectly(string item)
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 1);

            // Act
            parsed.AddFormatted(item, typeof(string));

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(1));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.Token));
            Assert.That(operations[0].Item, Is.EqualTo(item));
            Assert.That(operations[0].Offset, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that AddFormatted handles very long strings correctly.
        /// Input: Very long string (1000+ characters), type = typeof(string)
        /// Expected: Operation is added with correct offset increment.
        /// </summary>
        [Test]
        public void AddFormatted_WithLongString_AddsOperationAndIncrementsOffsetCorrectly()
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 1);
            string longString = new('A', 10000);

            // Act
            parsed.AddFormatted(longString, typeof(string));

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(1));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.Token));
            Assert.That(operations[0].Item, Is.EqualTo(longString));
            Assert.That(operations[0].Item.Length, Is.EqualTo(10000));
            Assert.That(operations[0].Offset, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that AddFormatted captures the correct line number in the operation.
        /// Input: item = "Test", type = typeof(string)
        /// Expected: Operation is added with LineNumber = 0 (default initial value).
        /// </summary>
        [Test]
        public void AddFormatted_CapturesLineNumberCorrectly()
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 1);
            const string item = "Test";

            // Act
            parsed.AddFormatted(item, typeof(string));

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(1));
            Assert.That(operations[0].LineNumber, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that AddFormatted with whitespace-only string adds operation correctly.
        /// Input: item = "   " (spaces only), type = typeof(string)
        /// Expected: Operation is added as Token with the whitespace string.
        /// </summary>
        [Test]
        public void AddFormatted_WithWhitespaceOnlyString_AddsOperationCorrectly()
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 1);
            const string item = "   ";

            // Act
            parsed.AddFormatted(item, typeof(string));

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(1));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.Token));
            Assert.That(operations[0].Item, Is.EqualTo(item));
            Assert.That(operations[0].Offset, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that AddFormatted with single character string adds operation correctly.
        /// Input: item = "X" (single character), type = typeof(string)
        /// Expected: Operation is added with offset incremented by 1.
        /// </summary>
        [Test]
        public void AddFormatted_WithSingleCharacterString_AddsOperationCorrectly()
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 1);
            const string item = "X";

            // Act
            parsed.AddFormatted(item, typeof(string));

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(1));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.Token));
            Assert.That(operations[0].Item, Is.EqualTo(item));
            Assert.That(operations[0].Item.Length, Is.EqualTo(1));
        }

        /// <summary>
        /// Tests that AddFormatted with control characters adds operation correctly.
        /// Input: item with various control characters, type = typeof(string)
        /// Expected: Operation is added with the exact string including control characters.
        /// </summary>
        [TestCase("\r")]
        [TestCase("\n")]
        [TestCase("\r\n")]
        [TestCase("\t")]
        [TestCase("\0")]
        public void AddFormatted_WithControlCharacters_AddsOperationCorrectly(string item)
        {
            // Arrange
            var parsed = new ParsedTemplateString(0, 1);

            // Act
            parsed.AddFormatted(item, typeof(string));

            // Assert
            var operations = parsed.Operations.ToList();
            Assert.That(operations, Has.Count.EqualTo(1));
            Assert.That(operations[0].Type, Is.EqualTo(ParsedTemplateString.OpType.Token));
            Assert.That(operations[0].Item, Is.EqualTo(item));
        }
    }
}
