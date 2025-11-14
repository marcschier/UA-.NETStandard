/* ========================================================================
 * Copyright (c) 2005-2020 The OPC Foundation, Inc. All rights reserved.
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
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Test Client Services.
    /// </summary>
    [TestFixture]
    [Category("SourceGeneration")]
    [SetCulture("en-us")]
    [SetUICulture("en-us")]
    public class TemplateTests
    {
        [Test]
        public async Task TestFormattableAsync()
        {
            // Arrange
            FormattableString formattableString = FormattableTest.Test;
            var values = new Dictionary<string, object>
            {
                { FormattableTest._NAME_, "MyService" },
                { FormattableTest._ServiceSet_, () => "MyServiceSet" }
            };

            // Act
            string result = FormattableTest.Format(formattableString, values);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result, Is.InstanceOf<string>());
        }

        [Test]
        public void HandlerTest()
        {
            Log.Message(
                $"""
                Test
                Test
                    {DateTime.UtcNow}
                Test
                """);
        }
    }

    /// <summary>
    /// Test formattable string
    /// </summary>
    public static class FormattableTest
    {
        /// <summary>
        /// Replace _name_ with service name
        /// </summary>
        public const string _NAME_ = "_NAME_";

        /// <summary>
        /// Replace _ServiceSet_ with service set name
        /// </summary>
        public const string _ServiceSet_ = "_ServiceSet_";

        /// <summary>
        /// StackGenerator.cs  line#1189
        /// </summary>
        public static FormattableString Test => $$"""
            // ***START***
            #if (!OPCUA_EXCLUDE_{{_NAME_}})
            /// <summary>
            /// Invokes the {{_NAME_}} service.
            /// </summary>
            public {{_NAME_}}Response {{_NAME_}}({{_NAME_}}Request request)
            {
                BinaryMessageContext context = CreateContext();
                byte[] buffer = BinaryEncoder.EncodeMessage(request, context);

                InvokeServiceResponseMessage response = null;

                try
                {
                    response = Channel.InvokeService(new InvokeServiceMessage(buffer));
                }
                catch (FaultException<ServiceFault> e)
                {
                    throw HandleSoapFault(e);
                }

                CheckForFault(response);

                return ({{_NAME_}}Response)BinaryDecoder.DecodeMessage(response.InvokeServiceResponse, typeof({{_NAME_}}Response), context);
            }

            /// <summary>
            /// The client side implementation of the {{_NAME_}} service contract.
            /// </summary>
            {{_NAME_}}ResponseMessage I{{_ServiceSet_}}Endpoint.{{_NAME_}}({{_NAME_}}Message request)
            {
                {{_NAME_}}Response response = {{_NAME_}}(request.{{_NAME_}}Request);
                return new {{_NAME_}}ResponseMessage(response);
            }

            /// <summary>
            /// Invokes the {{_NAME_}} service.
            /// </summary>
            public IAsyncResult Begin{{_NAME_}}({{_NAME_}}Request request, AsyncCallback callback, object asyncState)
            {
                byte[] buffer = BinaryEncoder.EncodeMessage(request, CreateContext());
                return Channel.BeginInvokeService(new InvokeServiceMessage(buffer), callback, asyncState);
            }

            /// <summary>
            /// The client side implementation of the Begin{{_NAME_}} service contract.
            /// </summary>
            IAsyncResult I{{_ServiceSet_}}Channel.Begin{{_NAME_}}({{_NAME_}}Message request, AsyncCallback callback, object asyncState)
            {
                return Begin{{_NAME_}}(request.{{_NAME_}}Request, callback, asyncState);
            }

            /// <summary>
            /// The client side implementation of the End{{_NAME_}} service contract.
            /// </summary>
            {{_NAME_}}ResponseMessage I{{_ServiceSet_}}Channel.End{{_NAME_}}(IAsyncResult result)
            {
                {{_NAME_}}Response response = End{{_NAME_}}(result);
                return new {{_NAME_}}ResponseMessage(response);
            }

            /// <summary>
            /// Completes the {{_NAME_}} service.
            /// </summary>
            public {{_NAME_}}Response End{{_NAME_}}(IAsyncResult result)
            {
                InvokeServiceResponseMessage response = null;

                try
                {
                    response = Channel.EndInvokeService(result);
                }
                catch (FaultException<ServiceFault> e)
                {
                    throw HandleSoapFault(e);
                }

                CheckForFault(response);

                return ({{_NAME_}}Response)BinaryDecoder.DecodeMessage(response.InvokeServiceResponse, typeof({{_NAME_}}Response), CreateContext());
            }
            #endif
            // ***END***
            """;

        /// <summary>
        /// Format formattable string with replacements from dictionary
        /// </summary>
        /// <param name="formattableString"></param>
        /// <param name="values"></param>
        /// <returns></returns>
        public static string Format(FormattableString formattableString, Dictionary<string, object> values)
        {
            object[] args = [.. Enumerable
                .Range(0, formattableString.ArgumentCount)
                .Select(i => GetSubstitute(formattableString, values, i))];
            return CoreUtils.Format(formattableString.Format, args);

            static object GetSubstitute(
                FormattableString formattableString,
                Dictionary<string, object> values,
                int i)
            {
                object argument = values.TryGetValue(
                    formattableString.GetArgument(i).ToString(),
                    out object value) ? value : null;
                return value is Func<string> factory ? factory() : value;
            }
        }
    }
}
