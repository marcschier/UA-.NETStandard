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
using Moq;
using NUnit.Framework;

namespace Opc.Ua.SourceGeneration.Templating.Tests
{
    /// <summary>
    /// Unit tests for the <see cref="TemplateDefinition"/> class.
    /// </summary>
    [TestFixture]
    public class TemplateDefinitionTests
    {
        /// <summary>
        /// Tests that Render throws NullReferenceException when context parameter is null.
        /// </summary>
        [Test]
        public void Render_NullContext_ThrowsNullReferenceException()
        {
            // Arrange
            var templateDefinition = new TemplateDefinition();

            // Act & Assert
            Assert.Throws<NullReferenceException>(() => templateDefinition.Render(null));
        }

        /// <summary>
        /// Tests that Render calls OnTemplateWrite delegate and returns true when OnTemplateWrite is set and returns true.
        /// </summary>
        [Test]
        public void Render_OnTemplateWriteSetReturnsTrue_ReturnsTrue()
        {
            // Arrange
            var templateDefinition = new TemplateDefinition();
            var mockContext = new Mock<IWriteContext>();
            bool delegateCalled = false;

            templateDefinition.OnTemplateWrite = (ctx) =>
            {
                delegateCalled = true;
                return true;
            };

            // Act
            bool result = templateDefinition.Render(mockContext.Object);

            // Assert
            Assert.That(result, Is.True);
            Assert.That(delegateCalled, Is.True);
        }

        /// <summary>
        /// Tests that Render calls OnTemplateWrite delegate and returns false when OnTemplateWrite is set and returns false.
        /// </summary>
        [Test]
        public void Render_OnTemplateWriteSetReturnsFalse_ReturnsFalse()
        {
            // Arrange
            var templateDefinition = new TemplateDefinition();
            var mockContext = new Mock<IWriteContext>();
            bool delegateCalled = false;

            templateDefinition.OnTemplateWrite = (ctx) =>
            {
                delegateCalled = true;
                return false;
            };

            // Act
            bool result = templateDefinition.Render(mockContext.Object);

            // Assert
            Assert.That(result, Is.False);
            Assert.That(delegateCalled, Is.True);
        }

        /// <summary>
        /// Tests that Render passes the correct context to OnTemplateWrite delegate.
        /// </summary>
        [Test]
        public void Render_OnTemplateWriteSet_PassesCorrectContext()
        {
            // Arrange
            var templateDefinition = new TemplateDefinition();
            var mockContext = new Mock<IWriteContext>();
            IWriteContext receivedContext = null;

            templateDefinition.OnTemplateWrite = (ctx) =>
            {
                receivedContext = ctx;
                return true;
            };

            // Act
            templateDefinition.Render(mockContext.Object);

            // Assert
            Assert.That(receivedContext, Is.SameAs(mockContext.Object));
        }

        /// <summary>
        /// Tests that Render calls Template.Render and returns true when OnTemplateWrite is null and Template.Render returns true.
        /// </summary>
        [Test]
        public void Render_OnTemplateWriteNullTemplateRenderReturnsTrue_ReturnsTrue()
        {
            // Arrange
            var templateDefinition = new TemplateDefinition();
            var mockContext = new Mock<IWriteContext>();
            var mockTemplate = new Mock<Template>();

            mockTemplate.Setup(t => t.Render()).Returns(true);
            mockContext.Setup(c => c.Template).Returns(mockTemplate.Object);

            // Act
            bool result = templateDefinition.Render(mockContext.Object);

            // Assert
            Assert.That(result, Is.True);
            mockTemplate.Verify(t => t.Render(), Times.Once);
        }

        /// <summary>
        /// Tests that Render calls Template.Render and returns false when OnTemplateWrite is null and Template.Render returns false.
        /// </summary>
        [Test]
        public void Render_OnTemplateWriteNullTemplateRenderReturnsFalse_ReturnsFalse()
        {
            // Arrange
            var templateDefinition = new TemplateDefinition();
            var mockContext = new Mock<IWriteContext>();
            var mockTemplate = new Mock<Template>();

            mockTemplate.Setup(t => t.Render()).Returns(false);
            mockContext.Setup(c => c.Template).Returns(mockTemplate.Object);

            // Act
            bool result = templateDefinition.Render(mockContext.Object);

            // Assert
            Assert.That(result, Is.False);
            mockTemplate.Verify(t => t.Render(), Times.Once);
        }

        /// <summary>
        /// Tests that Render does not call Template.Render when OnTemplateWrite is set.
        /// Verifies that the custom handler overrides the default behavior.
        /// </summary>
        [Test]
        public void Render_OnTemplateWriteSet_DoesNotCallTemplateRender()
        {
            // Arrange
            var templateDefinition = new TemplateDefinition();
            var mockContext = new Mock<IWriteContext>();
            var mockTemplate = new Mock<Template>();

            mockContext.Setup(c => c.Template).Returns(mockTemplate.Object);
            templateDefinition.OnTemplateWrite = (ctx) => true;

            // Act
            templateDefinition.Render(mockContext.Object);

            // Assert
            mockTemplate.Verify(t => t.Render(), Times.Never);
        }

        /// <summary>
        /// Tests that Render throws NullReferenceException when OnTemplateWrite is null and context.Template is null.
        /// This tests the error condition when the default rendering path is taken but Template is not available.
        /// </summary>
        [Test]
        public void Render_OnTemplateWriteNullAndTemplateNull_ThrowsNullReferenceException()
        {
            // Arrange
            var templateDefinition = new TemplateDefinition();
            var mockContext = new Mock<IWriteContext>();
            mockContext.Setup(c => c.Template).Returns((Template)null);

            // Act & Assert
            Assert.Throws<NullReferenceException>(() => templateDefinition.Render(mockContext.Object));
        }

        /// <summary>
        /// Tests that Load returns context.TemplateString when OnTemplateLoad is null.
        /// Input: OnTemplateLoad is null, valid context with TemplateString.
        /// Expected: Returns the TemplateString from the context.
        /// </summary>
        [Test]
        public void Load_OnTemplateLoadIsNull_ReturnsContextTemplateString()
        {
            // Arrange
            var templateDefinition = new TemplateDefinition
            {
                OnTemplateLoad = null
            };

            var expectedTemplateString = (TemplateString)"test template content";
            var mockContext = new Mock<ILoadContext>();
            mockContext.Setup(c => c.TemplateString).Returns(expectedTemplateString);

            // Act
            TemplateString result = templateDefinition.Load(mockContext.Object);

            // Assert
            Assert.That(result, Is.EqualTo(expectedTemplateString));
        }

        /// <summary>
        /// Tests that Load returns context.TemplateString when context.TemplateString is null and OnTemplateLoad is null.
        /// Input: OnTemplateLoad is null, context.TemplateString is null.
        /// Expected: Returns null.
        /// </summary>
        [Test]
        public void Load_OnTemplateLoadIsNullAndContextTemplateStringIsNull_ReturnsNull()
        {
            // Arrange
            var templateDefinition = new TemplateDefinition
            {
                OnTemplateLoad = null
            };

            var mockContext = new Mock<ILoadContext>();
            mockContext.Setup(c => c.TemplateString).Returns((TemplateString)null);

            // Act
            TemplateString result = templateDefinition.Load(mockContext.Object);

            // Assert
            Assert.That(result, Is.Null);
        }

        /// <summary>
        /// Tests that Load invokes OnTemplateLoad delegate when it is not null and returns its result.
        /// Input: OnTemplateLoad is set to a delegate that returns a specific TemplateString.
        /// Expected: Returns the TemplateString from the delegate invocation.
        /// </summary>
        [Test]
        public void Load_OnTemplateLoadIsNotNull_InvokesDelegateAndReturnsResult()
        {
            // Arrange
            var expectedTemplateString = (TemplateString)"delegate result template";
            var mockContext = new Mock<ILoadContext>();

            var templateDefinition = new TemplateDefinition
            {
                OnTemplateLoad = (ctx) => expectedTemplateString
            };

            // Act
            TemplateString result = templateDefinition.Load(mockContext.Object);

            // Assert
            Assert.That(result, Is.EqualTo(expectedTemplateString));
        }

        /// <summary>
        /// Tests that Load passes the correct context parameter to the OnTemplateLoad delegate.
        /// Input: OnTemplateLoad is set, valid context provided.
        /// Expected: The delegate receives the same context instance.
        /// </summary>
        [Test]
        public void Load_OnTemplateLoadIsNotNull_PassesCorrectContextToDelegate()
        {
            // Arrange
            var mockContext = new Mock<ILoadContext>();
            ILoadContext capturedContext = null;
            var returnTemplateString = (TemplateString)"result";

            var templateDefinition = new TemplateDefinition
            {
                OnTemplateLoad = (ctx) =>
                {
                    capturedContext = ctx;
                    return returnTemplateString;
                }
            };

            // Act
            templateDefinition.Load(mockContext.Object);

            // Assert
            Assert.That(capturedContext, Is.SameAs(mockContext.Object));
        }

        /// <summary>
        /// Tests that Load returns null when OnTemplateLoad delegate returns null.
        /// Input: OnTemplateLoad returns null.
        /// Expected: Returns null without throwing exception.
        /// </summary>
        [Test]
        public void Load_OnTemplateLoadReturnsNull_ReturnsNull()
        {
            // Arrange
            var mockContext = new Mock<ILoadContext>();

            var templateDefinition = new TemplateDefinition
            {
                OnTemplateLoad = (ctx) => null
            };

            // Act
            TemplateString result = templateDefinition.Load(mockContext.Object);

            // Assert
            Assert.That(result, Is.Null);
        }

        /// <summary>
        /// Tests that Load throws NullReferenceException when context is null and OnTemplateLoad is null.
        /// Input: Context is null, OnTemplateLoad is null.
        /// Expected: NullReferenceException is thrown when accessing context.TemplateString.
        /// </summary>
        [Test]
        public void Load_ContextIsNullAndOnTemplateLoadIsNull_ThrowsNullReferenceException()
        {
            // Arrange
            var templateDefinition = new TemplateDefinition
            {
                OnTemplateLoad = null
            };

            // Act & Assert
            Assert.Throws<NullReferenceException>(() => templateDefinition.Load(null));
        }

        /// <summary>
        /// Tests that Load invokes OnTemplateLoad with null context when context is null and OnTemplateLoad is not null.
        /// Input: Context is null, OnTemplateLoad is set.
        /// Expected: Delegate is invoked with null parameter and returns its result.
        /// </summary>
        [Test]
        public void Load_ContextIsNullAndOnTemplateLoadIsNotNull_InvokesDelegateWithNull()
        {
            // Arrange
            var capturedContext = (ILoadContext)(object)1; // Initialize with non-null sentinel value
            var expectedTemplateString = (TemplateString)"result from null context";

            var templateDefinition = new TemplateDefinition
            {
                OnTemplateLoad = (ctx) =>
                {
                    capturedContext = ctx;
                    return expectedTemplateString;
                }
            };

            // Act
            TemplateString result = templateDefinition.Load(null);

            // Assert
            Assert.That(result, Is.EqualTo(expectedTemplateString));
            Assert.That(capturedContext, Is.Null);
        }
    }

    /// <summary>
    /// Unit tests for the <see cref="TemplateContext"/> class.
    /// </summary>
    [TestFixture]
    public class TemplateContextTests
    {
        /// <summary>
        /// Tests that the constructor initializes all properties correctly with valid parameters.
        /// Input: Valid TemplateWriter, non-empty token string, and valid TemplateString.
        /// Expected: All properties are set correctly, Index is initialized to 0, Target and Template are null.
        /// </summary>
        [Test]
        public void Constructor_ValidParameters_InitializesAllPropertiesCorrectly()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            var writer = new TemplateWriter(stringWriter);
            const string token = "testToken";
            TemplateString templateString = "testTemplate";

            // Act
            var context = new TemplateContext(writer, token, templateString);

            // Assert
            Assert.That(context.Out, Is.SameAs(writer));
            Assert.That(context.Token, Is.EqualTo(token));
            Assert.That(context.TemplateString, Is.SameAs(templateString));
            Assert.That(context.Index, Is.EqualTo(0));
            Assert.That(context.Target, Is.Null);
            Assert.That(context.Template, Is.Null);
        }

        /// <summary>
        /// Tests that the constructor accepts null writer parameter.
        /// Input: Null TemplateWriter, valid token string, and valid TemplateString.
        /// Expected: Out property is set to null, other properties are set correctly.
        /// </summary>
        [Test]
        public void Constructor_NullWriter_SetsOutToNull()
        {
            // Arrange
            const string token = "testToken";
            TemplateString templateString = "testTemplate";

            // Act
            var context = new TemplateContext(null, token, templateString);

            // Assert
            Assert.That(context.Out, Is.Null);
            Assert.That(context.Token, Is.EqualTo(token));
            Assert.That(context.TemplateString, Is.SameAs(templateString));
            Assert.That(context.Index, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that the constructor accepts null token parameter.
        /// Input: Valid TemplateWriter, null token string, and valid TemplateString.
        /// Expected: Token property is set to null, other properties are set correctly.
        /// </summary>
        [Test]
        public void Constructor_NullToken_SetsTokenToNull()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            var writer = new TemplateWriter(stringWriter);
            TemplateString templateString = "testTemplate";

            // Act
            var context = new TemplateContext(writer, null, templateString);

            // Assert
            Assert.That(context.Out, Is.SameAs(writer));
            Assert.That(context.Token, Is.Null);
            Assert.That(context.TemplateString, Is.SameAs(templateString));
            Assert.That(context.Index, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that the constructor accepts empty token string.
        /// Input: Valid TemplateWriter, empty token string, and valid TemplateString.
        /// Expected: Token property is set to empty string, other properties are set correctly.
        /// </summary>
        [Test]
        public void Constructor_EmptyToken_SetsTokenToEmpty()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            var writer = new TemplateWriter(stringWriter);
            const string token = "";
            TemplateString templateString = "testTemplate";

            // Act
            var context = new TemplateContext(writer, token, templateString);

            // Assert
            Assert.That(context.Out, Is.SameAs(writer));
            Assert.That(context.Token, Is.Empty);
            Assert.That(context.TemplateString, Is.SameAs(templateString));
            Assert.That(context.Index, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that the constructor accepts whitespace-only token string.
        /// Input: Valid TemplateWriter, whitespace token string, and valid TemplateString.
        /// Expected: Token property is set to whitespace string, other properties are set correctly.
        /// </summary>
        [Test]
        public void Constructor_WhitespaceToken_SetsTokenToWhitespace()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            var writer = new TemplateWriter(stringWriter);
            const string token = "   \t\n";
            TemplateString templateString = "testTemplate";

            // Act
            var context = new TemplateContext(writer, token, templateString);

            // Assert
            Assert.That(context.Out, Is.SameAs(writer));
            Assert.That(context.Token, Is.EqualTo(token));
            Assert.That(context.TemplateString, Is.SameAs(templateString));
            Assert.That(context.Index, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that the constructor accepts null TemplateString parameter.
        /// Input: Valid TemplateWriter, valid token string, and null TemplateString.
        /// Expected: TemplateString property is set to null, other properties are set correctly.
        /// </summary>
        [Test]
        public void Constructor_NullTemplateString_SetsTemplateStringToNull()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            var writer = new TemplateWriter(stringWriter);
            const string token = "testToken";

            // Act
            var context = new TemplateContext(writer, token, null);

            // Assert
            Assert.That(context.Out, Is.SameAs(writer));
            Assert.That(context.Token, Is.EqualTo(token));
            Assert.That(context.TemplateString, Is.Null);
            Assert.That(context.Index, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that the constructor handles token with special characters correctly.
        /// Input: Valid TemplateWriter, token with special characters, and valid TemplateString.
        /// Expected: Token property preserves special characters, other properties are set correctly.
        /// </summary>
        [Test]
        public void Constructor_TokenWithSpecialCharacters_PreservesSpecialCharacters()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            var writer = new TemplateWriter(stringWriter);
            const string token = "!@#$%^&*()_+-={}[]|:;<>?,./~`";
            TemplateString templateString = "testTemplate";

            // Act
            var context = new TemplateContext(writer, token, templateString);

            // Assert
            Assert.That(context.Out, Is.SameAs(writer));
            Assert.That(context.Token, Is.EqualTo(token));
            Assert.That(context.TemplateString, Is.SameAs(templateString));
            Assert.That(context.Index, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that the constructor handles very long token string correctly.
        /// Input: Valid TemplateWriter, very long token string (1000+ characters), and valid TemplateString.
        /// Expected: Token property preserves the long string, other properties are set correctly.
        /// </summary>
        [Test]
        public void Constructor_VeryLongToken_PreservesLongString()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            var writer = new TemplateWriter(stringWriter);
            string token = new('a', 10000);
            TemplateString templateString = "testTemplate";

            // Act
            var context = new TemplateContext(writer, token, templateString);

            // Assert
            Assert.That(context.Out, Is.SameAs(writer));
            Assert.That(context.Token, Is.EqualTo(token));
            Assert.That(context.Token.Length, Is.EqualTo(10000));
            Assert.That(context.TemplateString, Is.SameAs(templateString));
            Assert.That(context.Index, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that the constructor handles all null parameters correctly.
        /// Input: Null values for all parameters.
        /// Expected: All properties are set to null except Index which is 0.
        /// </summary>
        [Test]
        public void Constructor_AllNullParameters_InitializesWithNulls()
        {
            // Act
            var context = new TemplateContext(null, null, null);

            // Assert
            Assert.That(context.Out, Is.Null);
            Assert.That(context.Token, Is.Null);
            Assert.That(context.TemplateString, Is.Null);
            Assert.That(context.Index, Is.EqualTo(0));
            Assert.That(context.Target, Is.Null);
            Assert.That(context.Template, Is.Null);
        }

        /// <summary>
        /// Tests that the constructor handles token with Unicode characters correctly.
        /// Input: Valid TemplateWriter, token with Unicode characters, and valid TemplateString.
        /// Expected: Token property preserves Unicode characters, other properties are set correctly.
        /// </summary>
        [Test]
        public void Constructor_TokenWithUnicodeCharacters_PreservesUnicodeCharacters()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            var writer = new TemplateWriter(stringWriter);
            const string token = "Hello世界🌍مرحبا";
            TemplateString templateString = "testTemplate";

            // Act
            var context = new TemplateContext(writer, token, templateString);

            // Assert
            Assert.That(context.Out, Is.SameAs(writer));
            Assert.That(context.Token, Is.EqualTo(token));
            Assert.That(context.TemplateString, Is.SameAs(templateString));
            Assert.That(context.Index, Is.EqualTo(0));
        }

        /// <summary>
        /// Tests that the constructor handles token with control characters correctly.
        /// Input: Valid TemplateWriter, token with control characters, and valid TemplateString.
        /// Expected: Token property preserves control characters, other properties are set correctly.
        /// </summary>
        [Test]
        public void Constructor_TokenWithControlCharacters_PreservesControlCharacters()
        {
            // Arrange
            using var stringWriter = new StringWriter();
            var writer = new TemplateWriter(stringWriter);
            const string token = "test\0\a\b\f\r\n\ttoken";
            TemplateString templateString = "testTemplate";

            // Act
            var context = new TemplateContext(writer, token, templateString);

            // Assert
            Assert.That(context.Out, Is.SameAs(writer));
            Assert.That(context.Token, Is.EqualTo(token));
            Assert.That(context.TemplateString, Is.SameAs(templateString));
            Assert.That(context.Index, Is.EqualTo(0));
        }
    }
}
