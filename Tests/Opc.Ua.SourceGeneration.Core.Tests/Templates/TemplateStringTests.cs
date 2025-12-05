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
using NUnit.Framework;

namespace Opc.Ua.SourceGeneration.Tests.Templating
{
    [TestFixture]
    public class TemplateStringTests
    {
        [Test]
        public void CreateFromString_SimpleText_CreatesValidTemplateString()
        {
            // Arrange
            const string input = "Hello World";

            // Act
            TemplateString templateString = input;

            // Assert
            Assert.That(templateString, Is.Not.Null);
            Assert.That(templateString.ParsedTemplate, Is.Not.Null);
            Assert.That(templateString.ParsedTemplate.LiteralLength, Is.EqualTo(input.Length));
            Assert.That(templateString.ParsedTemplate.FormattedCount, Is.EqualTo(0));
        }

        [Test]
        public void CreateFromString_EmptyString_CreatesValidTemplateString()
        {
            // Act
            TemplateString templateString = string.Empty;

            // Assert
            Assert.That(templateString, Is.Not.Null);
            Assert.That(templateString.ParsedTemplate, Is.Not.Null);
            Assert.That(templateString.ParsedTemplate.LiteralLength, Is.EqualTo(0));
            Assert.That(templateString.ParsedTemplate.FormattedCount, Is.EqualTo(0));
        }

        [Test]
        public void CreateFromString_NullString_CreatesValidTemplateString()
        {
            // Act
            TemplateString templateString = (string)null;

            // Assert
            Assert.That(templateString, Is.Not.Null);
            Assert.That(templateString.ParsedTemplate, Is.Not.Null);
            Assert.That(templateString.ParsedTemplate.LiteralLength, Is.EqualTo(0));
            Assert.That(templateString.ParsedTemplate.FormattedCount, Is.EqualTo(0));
        }

        [Test]
        public void CreateFromInterpolatedStringCreatesValidTemplateString()
        {
            // Act
            var templateString = TemplateString.Parse(
                $$"""
                Hello {World} {{DateTime.UtcNow}}
                {{DateTime.UtcNow}}

                    {{typeof(TemplateStringTests).FullName}}
                """);

            // Assert
            Assert.That(templateString, Is.Not.Null);
            Assert.That(templateString.ParsedTemplate, Is.Not.Null);
            Assert.That(templateString.ParsedTemplate.LiteralLength, Is.EqualTo(24));
            Assert.That(templateString.ParsedTemplate.FormattedCount, Is.EqualTo(3));
            Assert.That(templateString.ParsedTemplate.Operations.Count, Is.EqualTo(8));
        }
    }
}
