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
            using var writer = new StringWriter();
            TemplateString templateString = "Test";

            using var templateWriter = new TemplateWriter(writer);
            var template = new Template(templateWriter, templateString);

            Assert.That(template, Is.Not.Null);
        }

        [Test]
        public void WriteTemplate_WithNamespaceUriTemplate_RendersCorrectly()
        {
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.NamespaceUri_cs;
            using (var templateWriter = new TemplateWriter(writer))
            {
                var template = new Template(templateWriter, templateString);

                template.AddReplacement(Tokens.Name, "MyNamespace");
                template.AddReplacement(Tokens.CodeName, "My.Namespace");
                template.AddReplacement(Tokens.NamespaceUri, "http://mynamespace.org/UA/");

                template.Render();
            }
            string result = writer.ToString();

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
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.BrowseName_cs;
            using (var templateWriter = new TemplateWriter(writer))
            {
                var template = new Template(templateWriter, templateString);

                template.AddReplacement(Tokens.SymbolicName, "MyBrowseName");
                template.AddReplacement(Tokens.BrowseName, "MyBrowseName");

                template.Render();
            }
            string result = writer.ToString();

            const string expected = """
                public const string MyBrowseName = "MyBrowseName";

                """;
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void WriteTemplate_WithIdDeclarationTemplate_RendersCorrectly()
        {
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.IdDeclaration_cs;
            using (var templateWriter = new TemplateWriter(writer))
            {
                var template = new Template(templateWriter, templateString);

                template.AddReplacement(Tokens.IdType, "uint");
                template.AddReplacement(Tokens.SymbolicName, "MyId");
                template.AddReplacement(Tokens.Identifier, "12345");

                template.Render();
            }
            string result = writer.ToString();

            const string expected = """
                public const uint MyId = 12345;

                """;
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void WriteTemplate_WithHelpersFileTemplate_RendersCorrectly()
        {
            using var writer = new StringWriter();
            TemplateString templateString = CodeTemplates.Helpers_File_cs;
            using (var templateWriter = new TemplateWriter(writer))
            {
                var template = new Template(templateWriter, templateString);

                template.AddReplacement(Tokens.ListOfImports, "using System;");
                template.AddReplacement(Tokens.NamespacePrefix, "My.Prefix");
                template.AddReplacement(Tokens.Namespace, "MyNamespace");
                template.AddReplacement(Tokens.Encoding, "Binary");

                template.Render();
            }
            string result = writer.ToString();

            Assert.That(result, Does.Contain("namespace My.Prefix"));
            Assert.That(result, Does.Contain("public static partial class MyNamespaceExtensions"));
            Assert.That(result, Does.Contain("AddMyNamespace("));
            Assert.That(result, Does.Contain("predefinedNodes.LoadFromBinary(context, stream, true);"));
        }

        [Test]
        public void AddReplacement_Generic_RendersCorrectly()
        {
            using var writer = new StringWriter();
            const string myToken = nameof(myToken);
            var templateString = TemplateString.Parse($"Value is {myToken}");
            using (var templateWriter = new TemplateWriter(writer))
            {
                var template = new Template(templateWriter, templateString);

                template.AddReplacement(myToken, 123.45);

                template.Render();
            }
            string result = writer.ToString();

            Assert.That(result, Is.EqualTo("Value is 123.45"));
        }

        [Test]
        public void AddReplacement_Bool_RendersCorrectly()
        {
            using var writer = new StringWriter();
            const string myToken = nameof(myToken);
            var templateString = TemplateString.Parse($"Value is {myToken}");
            using (var templateWriter = new TemplateWriter(writer))
            {
                var template = new Template(templateWriter, templateString);

                template.AddReplacement(myToken, true);

                template.Render();
            }
            string result = writer.ToString();

            Assert.That(result, Is.EqualTo("Value is true"));
        }

        [Test]
        public void AddReplacement_String_RendersCorrectly()
        {
            using var writer = new StringWriter();
            const string myToken = nameof(myToken);
            var templateString = TemplateString.Parse($"Value is {myToken}");
            using (var templateWriter = new TemplateWriter(writer))
            {
                var template = new Template(templateWriter, templateString);

                template.AddReplacement(myToken, "test");

                template.Render();
            }
            string result = writer.ToString();

            Assert.That(result, Is.EqualTo("Value is test"));
        }

        [Test]
        public void AddReplacement_WithListOfTargets_RendersCorrectly()
        {
            using var writer = new StringWriter();
            const string myList = nameof(myList);
            const string itemValue = nameof(itemValue);
            using (var templateWriter = new TemplateWriter(writer))
            {
                var template = new Template(templateWriter, TemplateString.Parse(
                $$"""

                {{myList}}
                """));
                string[] targets = ["One", "Two", "Three"];
                var itemTemplate = TemplateString.Parse($"Item: {itemValue} ");

                template.AddReplacement(myList, itemTemplate, targets, c =>
                {
                    c.Template.AddReplacement(itemValue, (string)c.Target);
                    return c.Template.Render();
                });

                template.Render();
            }
            string result = writer.ToString();

            // There is no line break in the item value template, so the
            // result of mylist substitution will be on a single line.
            const string expected =
                """

                Item: One Item: Two Item: Three
                """;
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void AddReplacement_WithSingleTarget_RendersCorrectly()
        {
            using var writer = new StringWriter();
            const string myList = nameof(myList);
            const string itemValue = nameof(itemValue);
            using (var templateWriter = new TemplateWriter(writer))
            {
#pragma warning disable RCS1214 // Unnecessary interpolated string
                var template = new Template(templateWriter, TemplateString.Parse($"{myList}"));
#pragma warning restore RCS1214 // Unnecessary interpolated string
                var itemTemplate = TemplateString.Parse($"Item: {itemValue}");

                template.AddReplacement(myList, itemTemplate, "Single", c =>
                {
                    c.Template.AddReplacement(itemValue, (string)c.Target);
                    return c.Template.Render();
                });

                template.Render();
            }
            string result = writer.ToString();

            const string expected =
                """
                Item: Single
                """;
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void AddReplacement_WithMissingReplacement_RendersCorrectly()
        {
            using var writer = new StringWriter();
            const string myList = nameof(myList);
            const string itemValue = nameof(itemValue);
            using (var templateWriter = new TemplateWriter(writer))
            {
                var template = new Template(templateWriter, TemplateString.Parse(
            $$"""
            {
                {{myList}}
                {{itemValue}}
            }
            """));

                var itemTemplate = TemplateString.Parse($"Item: {itemValue}");
                template.AddReplacement(myList, itemTemplate, ["Single"], c =>
                {
                    c.Template.AddReplacement(itemValue, (string)c.Target);
                    return c.Template.Render();
                });

                template.Render();
            }
            string result = writer.ToString();

            const string expected =
                """
                {
                    Item: Single
                }
                """;
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void AddReplacement_WithSingleTargetAndLoadHandler_RendersCorrectly()
        {
            using var writer = new StringWriter();
            const string myItem = nameof(myItem);
            const string itemValue = nameof(itemValue);
            using (var templateWriter = new TemplateWriter(writer))
            {
#pragma warning disable RCS1214 // Unnecessary interpolated string
                var template = new Template(templateWriter, TemplateString.Parse($"{myItem}"));
#pragma warning restore RCS1214 // Unnecessary interpolated string
                var itemTemplate1 = TemplateString.Parse($"Template1: {itemValue}");
                var itemTemplate2 = TemplateString.Parse($"Template2: {itemValue}");

                template.AddReplacement(myItem, "Single",
                    onLoad: c => (string)c.Target == "Single" ? itemTemplate1 : itemTemplate2,
                    onWrite: c =>
                    {
                        c.Template.AddReplacement(itemValue, (string)c.Target);
                        return c.Template.Render();
                    });

                template.Render();
            }
            string result = writer.ToString();

            const string expected =
                """
                Template1: Single
                """;
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void AddReplacement_WithListOfTargetsAndLoadHandler_RendersCorrectly()
        {
            using var writer = new StringWriter();
            const string myList = nameof(myList);
            const string itemValue = nameof(itemValue);
            using (var templateWriter = new TemplateWriter(writer))
            {
#pragma warning disable RCS1214 // Unnecessary interpolated string
                var template = new Template(templateWriter, TemplateString.Parse($"{myList}"));
#pragma warning restore RCS1214 // Unnecessary interpolated string
                string[] targets = ["One", "Two"];
                var itemTemplate1 = TemplateString.Parse($"Template1: {itemValue}\r\n");
                var itemTemplate2 = TemplateString.Parse($"Template2: {itemValue}");

                template.AddReplacement(myList, targets,
                    onLoad: c => (string)c.Target == "One" ? itemTemplate1 : itemTemplate2,
                    onWrite: c =>
                    {
                        c.Template.AddReplacement(itemValue, (string)c.Target);
                        return c.Template.Render();
                    });

                template.Render();
            }
            string result = writer.ToString();

            const string expected =
                """
                Template1: One

                Template2: Two
                """;
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void AddReplacement_WithListOfTargetsAndFinalLineBreakRendersCorrectly()
        {
            using var writer = new StringWriter();
            const string myList = nameof(myList);
            const string itemValue = nameof(itemValue);
            using (var templateWriter = new TemplateWriter(writer))
            {
#pragma warning disable RCS1214 // Unnecessary interpolated string
                var template = new Template(templateWriter, TemplateString.Parse($"{myList}"));
#pragma warning restore RCS1214 // Unnecessary interpolated string
                string[] targets = ["One", "Two"];
                var itemTemplate1 = TemplateString.Parse($"Template1: {itemValue}\r\n\t");
                var itemTemplate2 = TemplateString.Parse($"Template2: {itemValue}");

                template.AddReplacement(myList, targets,
                    onLoad: c => (string)c.Target == "Two" ? itemTemplate1 : itemTemplate2,
                    onWrite: c =>
                    {
                        c.Template.AddReplacement(itemValue, (string)c.Target);
                        return c.Template.Render();
                    });

                template.Render();
            }
            string result = writer.ToString();

            const string expected =
                """
                Template2: OneTemplate1: Two

                """ +
                "\t";
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void AddReplacement_WithMessageTemplate_RendersCorrectly()
        {
            using var writer = new StringWriter();
            using (var templateWriter = new TemplateWriter(writer))
            {
                var template = new Template(templateWriter, CodeTemplates.Messages_File_cs);
                template.AddReplacement(Tokens.Prefix, "MyNamespace");
                template.AddReplacement(Tokens.Header, string.Empty);
                template.AddReplacement(
                    Tokens.TypeList,
                    CodeTemplates.Classes_ServiceMessage_cs,
                    ["Type1", "Type2", "Type3"],
                    context =>
                    {
                        context.Template.AddReplacement(Tokens.Name, (string)context.Target);
                        return context.Template.Render();
                    });

                template.Render();
            }
            string result = writer.ToString();

            const string expected =
                """


                namespace MyNamespace
                {
                    /// <summary>
                    /// The request message for the Type1 service.
                    /// </summary>
                    public partial class Type1Request : global::Opc.Ua.IServiceRequest
                    {
                    }

                    /// <summary>
                    /// The response message for the Type1 service.
                    /// </summary>
                    public partial class Type1Response : global::Opc.Ua.IServiceResponse
                    {
                    }

                    /// <summary>
                    /// The request message for the Type2 service.
                    /// </summary>
                    public partial class Type2Request : global::Opc.Ua.IServiceRequest
                    {
                    }

                    /// <summary>
                    /// The response message for the Type2 service.
                    /// </summary>
                    public partial class Type2Response : global::Opc.Ua.IServiceResponse
                    {
                    }

                    /// <summary>
                    /// The request message for the Type3 service.
                    /// </summary>
                    public partial class Type3Request : global::Opc.Ua.IServiceRequest
                    {
                    }

                    /// <summary>
                    /// The response message for the Type3 service.
                    /// </summary>
                    public partial class Type3Response : global::Opc.Ua.IServiceResponse
                    {
                    }
                }
                """;
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void AddReplacement_NestedTemplate_RendersCorrectly()
        {
            using var writer = new StringWriter();
            const string subTemplate = nameof(subTemplate);
            const string innerTemplate = nameof(innerTemplate);
            const string myValue = nameof(myValue);

            using (var templateWriter = new TemplateWriter(writer))
            {
                var mainTemplate = new Template(templateWriter, TemplateString.Parse(
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
                1. This is my value: {{myValue}}
                2. This is my value: {{myValue}}
                3. This is my value: {{myValue}}
                """);

                mainTemplate.AddReplacement(
                    subTemplate,
                    subTemplateString,
                    ["target"],
                    onWrite: subContext =>
                    {
                        subContext.Template.AddReplacement(
                            innerTemplate,
                            innerTemplateString,
                            ["inner_target"],
                            onWrite: innerContext =>
                            {
                                innerContext.Template.AddReplacement(myValue, 123);
                                return innerContext.Template.Render();
                            }
                        );
                        return subContext.Template.Render();
                    }
                );

                mainTemplate.Render();
            }
            string result = writer.ToString();

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
