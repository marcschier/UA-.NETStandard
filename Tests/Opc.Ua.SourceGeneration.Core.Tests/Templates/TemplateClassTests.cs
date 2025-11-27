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

using System.IO;
using NUnit.Framework;

namespace Opc.Ua.SourceGeneration.Tests.Templating
{
    [TestFixture]
    public class TemplateClassTests
    {
        [Test]
        public void Template_CanBeCreated_ReturnsNotNull()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = "Test";

            // Act
            var template = new Template(writer, templateString);

            // Assert
            Assert.That(template, Is.Not.Null);
        }

        [Test]
        public void WriteTemplate_WithNamespaceUriTemplate_RendersCorrectly()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.NamespaceUri_cs;
            var template = new Template(writer, templateString);

            template.AddReplacement(Tokens.Name, "MyNamespace");
            template.AddReplacement(Tokens.CodeName, "My.Namespace");
            template.AddReplacement(Tokens.NamespaceUri, "http://mynamespace.org/UA/");

            // Act
            template.WriteTemplate();
            string result = writer.ToString();

            // Assert
            const string expected =
                """
                /// <summary>
                /// The URI for the MyNamespace namespace (.NET code namespace is 'My.Namespace').
                /// </summary>
                public const string MyNamespace = "http://mynamespace.org/UA/";
                """;
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void WriteTemplate_WithBrowseNameTemplate_RendersCorrectly()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseName_cs;
            var template = new Template(writer, templateString);

            template.AddReplacement(Tokens.SymbolicName, "MyBrowseName");
            template.AddReplacement(Tokens.BrowseName, "MyBrowseName");

            // Act
            template.WriteTemplate();
            string result = writer.ToString();

            // Assert
            const string expected = """public const string MyBrowseName = "MyBrowseName";""";
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void WriteTemplate_WithIdDeclarationTemplate_RendersCorrectly()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.IdDeclaration_cs;
            var template = new Template(writer, templateString);

            template.AddReplacement(Tokens.IdType, "uint");
            template.AddReplacement(Tokens.SymbolicName, "MyId");
            template.AddReplacement(Tokens.Identifier, "12345");

            // Act
            template.WriteTemplate();
            string result = writer.ToString();

            // Assert
            const string expected = "public const uint MyId = 12345;";
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void WriteTemplate_WithHelpersFileTemplate_RendersCorrectly()
        {
            // Arrange
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.Helpers_File_cs;
            var template = new Template(writer, templateString);

            template.AddReplacement(Tokens.ListOfImports, "using System;");
            template.AddReplacement(Tokens.NamespacePrefix, "My.Prefix");
            template.AddReplacement(Tokens.Namespace, "MyNamespace");
            template.AddReplacement(Tokens.Encoding, "Binary");

            // Act
            template.WriteTemplate();
            string result = writer.ToString();

            // Assert
            Assert.That(result, Does.Contain("namespace My.Prefix"));
            Assert.That(result, Does.Contain("public static partial class MyNamespaceExtensions"));
            Assert.That(result, Does.Contain("AddMyNamespace("));
            Assert.That(result, Does.Contain("predefinedNodes.LoadFromBinary(context, stream, true);"));
        }

        [Test]
        public void AddReplacement_Generic_RendersCorrectly()
        {
            // Arrange
            using var writer = new StringWriter();
            const string myToken = nameof(myToken);
            var templateString = TemplateString.Parse($"Value is {myToken}");
            var template = new Template(writer, templateString);

            template.AddReplacement(myToken, 123.45);

            // Act
            template.WriteTemplate();
            string result = writer.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("Value is 123.45"));
        }

        [Test]
        public void AddReplacement_Bool_RendersCorrectly()
        {
            // Arrange
            using var writer = new StringWriter();
            const string myToken = nameof(myToken);
            var templateString = TemplateString.Parse($"Value is {myToken}");
            var template = new Template(writer, templateString);

            template.AddReplacement(myToken, true);

            // Act
            template.WriteTemplate();
            string result = writer.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("Value is true"));
        }

        [Test]
        public void AddReplacement_String_RendersCorrectly()
        {
            // Arrange
            using var writer = new StringWriter();
            const string myToken = nameof(myToken);
            var templateString = TemplateString.Parse($"Value is {myToken}");
            var template = new Template(writer, templateString);

            template.AddReplacement(myToken, "test");

            // Act
            template.WriteTemplate();
            string result = writer.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("Value is test"));
        }

        [Test]
        public void AddTemplate_WithListOfTargets_RendersCorrectly()
        {
            // Arrange
            using var writer = new StringWriter();
            const string myList = nameof(myList);
            const string itemValue = nameof(itemValue);
            var template = new Template(writer, TemplateString.Parse(
                $$"""

                {{myList}}
                """));
            string[] targets = ["One", "Two", "Three"];
            var itemTemplate = TemplateString.Parse($"Item: {itemValue}");

            template.AddTemplate(myList, itemTemplate, targets, (t, c) =>
            {
                t.AddReplacement(itemValue, (string)c.Target);
                return t.WriteTemplate(c);
            });

            // Act
            template.WriteTemplate();
            string result = writer.ToString();

            // Assert
            const string expected =
                """
                Item: One
                Item: Two
                Item: Three

                """;
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void AddTemplate_WithSingleTarget_RendersCorrectly()
        {
            // Arrange
            using var writer = new StringWriter();
            const string myList = nameof(myList);
            const string itemValue = nameof(itemValue);
#pragma warning disable RCS1214 // Unnecessary interpolated string
            var template = new Template(writer, TemplateString.Parse($"{myList}"));
#pragma warning restore RCS1214 // Unnecessary interpolated string
            var itemTemplate = TemplateString.Parse($"Item: {itemValue}");

            template.AddTemplate(myList, itemTemplate, "Single", (t, c) =>
            {
                t.AddReplacement(itemValue, (string)c.Target);
                return t.WriteTemplate(c);
            });

            // Act
            template.WriteTemplate();
            string result = writer.ToString();

            // Assert
            const string expected =
                """
                Item: Single

                """;
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void AddTemplate_WithSingleTargetAndLoadHandler_RendersCorrectly()
        {
            // Arrange
            using var writer = new StringWriter();
            const string myItem = nameof(myItem);
            const string itemValue = nameof(itemValue);
#pragma warning disable RCS1214 // Unnecessary interpolated string
            var template = new Template(writer, TemplateString.Parse($"{myItem}"));
#pragma warning restore RCS1214 // Unnecessary interpolated string
            var itemTemplate1 = TemplateString.Parse($"Template1: {itemValue}");
            var itemTemplate2 = TemplateString.Parse($"Template2: {itemValue}");

            template.AddTemplate(myItem, "Single",
                onLoad: (t, c) => (string)c.Target == "Single" ? itemTemplate1 : itemTemplate2,
                onWrite: (t, c) =>
                {
                    t.AddReplacement(itemValue, (string)c.Target);
                    return t.WriteTemplate(c);
                });

            // Act
            template.WriteTemplate();
            string result = writer.ToString();

            // Assert
            const string expected =
                """
                Template1: Single

                """;
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void AddTemplate_WithListOfTargetsAndLoadHandler_RendersCorrectly()
        {
            // Arrange
            using var writer = new StringWriter();
            const string myList = nameof(myList);
            const string itemValue = nameof(itemValue);
#pragma warning disable RCS1214 // Unnecessary interpolated string
            var template = new Template(writer, TemplateString.Parse($"{myList}"));
#pragma warning restore RCS1214 // Unnecessary interpolated string
            string[] targets = ["One", "Two"];
            var itemTemplate1 = TemplateString.Parse($"Template1: {itemValue}");
            var itemTemplate2 = TemplateString.Parse($"Template2: {itemValue}");

            template.AddTemplate(myList, targets,
                onLoad: (t, c) => (string)c.Target == "One" ? itemTemplate1 : itemTemplate2,
                onWrite: (t, c) =>
                {
                    t.AddReplacement(itemValue, (string)c.Target);
                    return t.WriteTemplate(c);
                });

            // Act
            template.WriteTemplate();
            string result = writer.ToString();

            // Assert
            const string expected =
                """
                Template1: One
                Template2: Two

                """;
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void AddTemplate_NestedTemplate_RendersCorrectly()
        {
            // Arrange
            using var writer = new StringWriter();
            const string subTemplate = nameof(subTemplate);
            const string innerTemplate = nameof(innerTemplate);
            const string myValue = nameof(myValue);

            var mainTemplate = new Template(writer, TemplateString.Parse(
                $$"""
                Main:
                    {{subTemplate}}
                """));

            var subTemplateString = TemplateString.Parse(
                $$"""
                Sub:
                    {{innerTemplate}}
                """);
            var innerTemplateString = TemplateString.Parse(
                $$"""
                1, This is my value: {{myValue}}
                2. This is my value: {{myValue}}
                3. This is my value: {{myValue}}
                """);

            mainTemplate.AddTemplate(
                subTemplate,
                subTemplateString,
                ["target"],
                onWrite: (subTemplate, subContext) =>
                {
                    subTemplate.AddTemplate(
                        innerTemplate,
                        innerTemplateString,
                        ["inner_target"],
                        onWrite: (innerTemplate, innerContext) =>
                        {
                            innerTemplate.AddReplacement(myValue, 123);
                            return innerTemplate.WriteTemplate(innerContext);
                        }
                    );
                    return subTemplate.WriteTemplate(subContext);
                }
            );

            // Act
            mainTemplate.WriteTemplate();
            string result = writer.ToString();

            // Assert
            const string expected =
                """
                Main:
                    Sub:
                        1. This is my value: 123
                        2. This is my value: 123
                        3. This is my value: 123

                """;
            Assert.That(result, Is.EqualTo(expected));
        }
    }
}
