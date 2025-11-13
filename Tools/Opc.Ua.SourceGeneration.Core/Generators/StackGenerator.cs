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

using Opc.Ua.Schema.Types;
using Opc.Ua.SourceGeneration.Shared;
using Opc.Ua.Types;
using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Generates code based on a UA Type Dictionary.
    /// </summary>
    public class StackGenerator
    {
        // Constructors
        /// <summary>
        /// Generates the code from the contents of the address space.
        /// </summary>
        public StackGenerator(
            string inputPath,
            string outputDirectory,
            Dictionary<string, string> knownFiles,
            IReadOnlyList<string> exclusions)
        {
            // load and validate type dictionary.
            Validator = new TypeDictionaryValidator(knownFiles);
            Validator.Validate(inputPath);

            // save output directory.
            OutputDirectory = outputDirectory;
            DictionariesToExport = [];
            Exclusions = exclusions;
        }

        /// <summary>
        /// The validator used to verify the type dictionary.
        /// </summary>
        internal TypeDictionaryValidator Validator { get; }

        /// <summary>
        /// The dictionary being processed.
        /// </summary>
        internal TypeDictionary Dictionary => Validator.Dictionary;

        /// <summary>
        /// The name of the dictionary being processed.
        /// </summary>
        internal string DictionaryName { get; set; }

        /// <summary>
        /// The directory used to place any output files.
        /// </summary>
        internal string OutputDirectory { get; }

        /// <summary>
        /// The dictionaries that should be exported in addition to the target dictionary.
        /// </summary>
        public IReadOnlyList<string> DictionariesToExport { get; set; }

        /// <summary>
        /// The types to exclude.
        /// </summary>
        internal IReadOnlyList<string> Exclusions { get; }

        // Public Methods
        /// <summary>
        /// Generates the datatype files.
        /// </summary>
        public virtual void Generate(string namespacePrefix, string dictionaryName, bool exportAll)
        {
            DictionaryName = dictionaryName;

            m_namespaceConstant = "OpcUa";
            m_schemaNamespaceConstant = "OpcUaXsd";
            m_wsdlNamespaceConstant = "OpcUaWsdl";

            m_exportAll = exportAll;

            WriteTemplate_Messages(namespacePrefix);
            WriteTemplate_Interfaces(namespacePrefix);
            WriteTemplate_Channels(namespacePrefix);
            WriteTemplate_ClientApi(namespacePrefix);
            WriteTemplate_ServerApi(namespacePrefix);
            WriteTemplate_Endpoints(namespacePrefix);
        }

        /// <summary>
        /// Writes the classes and interaces that implement a UA endpoint.
        /// </summary>
        private void WriteTemplate_Endpoints(string namespacePrefix)
        {
            List<ServiceSet> serviceSets =
            [
                new ServiceSet("Session", InterfaceType.Discovery, InterfaceType.Session, InterfaceType.Test),
                new ServiceSet("Discovery", InterfaceType.Discovery, InterfaceType.Registration)
            ];

            var writer = new StreamWriter(CoreUtils.Format(
                @"{0}\{1}.Endpoints.cs",
                OutputDirectory,
                namespacePrefix), false);

            try
            {
                var template = new Template(
                    writer,
                    TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Endpoints_File_cs);

                template.AddReplacement("_Date_", DateTime.Now);
                template.AddReplacement("_Prefix_", namespacePrefix);
                template.AddReplacement("_Namespace_", m_namespaceConstant);

                template.AddTemplate(
                    "// _SERVICESETS_",
                    TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Endpoints_ServiceSet_cs,
                    serviceSets,
                    null,
                    new WriteTemplateEventHandler(WriteTemplate_EndpointServiceSet));

                template.WriteTemplate(null);
            }
            finally
            {
                writer.Close();
            }
        }

        /// <summary>
        /// Copies the response paramaters into the request object.
        /// </summary>
        private bool WriteTemplate_EndpointServiceSet(Template template, Context context)
        {
            if (context.Target is not ServiceSet serviceSet)
            {
                return false;
            }

            // get datatypes.
            List<ServiceType> datatypes = GetListOfServices(serviceSet.Interfaces);

            if (datatypes.Count == 0)
            {
                return false;
            }

            template.AddReplacement("_ServiceSet_", serviceSet.Name);
            template.AddReplacement("_ServicesNamespace_", m_wsdlNamespaceConstant);

            if (serviceSet.Name == "Session")
            {
                template.AddReplacement("_IEndpoints_", "ISessionEndpoint, IDiscoveryEndpoint");
            }

            if (serviceSet.Name == "Discovery")
            {
                template.AddReplacement("_IEndpoints_", "IDiscoveryEndpoint, IRegistrationEndpoint");
            }

            template.AddTemplate(
                "// _MethodList_",
                TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Endpoints_Method_cs,
                datatypes,
                null,
                new WriteTemplateEventHandler(WriteTemplate_EndpointMethod));

            template.AddTemplate(
                "// AddKnownType",
                null,
                datatypes,
                new LoadTemplateEventHandler(LoadTemplate_KnownType),
                null);

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Copies the response paramaters into the request object.
        /// </summary>
        private bool WriteTemplate_EndpointMethod(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return false;
            }

            template.AddReplacement("_NAME_", serviceType.Name);

            template.AddTemplate(
                "// DeclareResponseParameters",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_InitializeResponseParameters),
                null);

            template.AddTemplate(
                "InvokeService();",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_InvokeServiceSyncParameters),
                null);

            template.AddTemplate(
                "InvokeServiceAsync();",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_InvokeServiceAsyncParameters),
                null);

            template.AddTemplate(
                "// SetResponseParameters",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_ResponseParameters),
                null);

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes a synchronous method declaration.
        /// </summary>
        private string LoadTemplate_InvokeServiceSyncParameters(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return null;
            }

            // write method declaration.
            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write("response.{0} = ServerInstance.{1}(", serviceType.Response[0].Name, serviceType.Name);

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write("   secureChannelContext");

            if (serviceType.Request != null || serviceType.Request.Length > 0)
            {
                bool first = false;

                foreach (FieldType field in serviceType.Request)
                {
                    if (first)
                    {
                        first = false;
                        template.WriteLine(string.Empty);
                    }
                    else
                    {
                        template.WriteLine(",");
                    }

                    template.Write(context.Prefix);
                    template.Write("   request.{0}", field.Name);
                }
            }

            if (serviceType.Response != null || serviceType.Response.Length > 0)
            {
                bool first = true;

                foreach (FieldType field in serviceType.Response)
                {
                    if (first)
                    {
                        first = false;
                        continue;
                    }

                    template.WriteLine(",");
                    template.Write(context.Prefix);
                    template.Write("   out {0}", field.Name.ToLowerCamelCase());
                }
            }

            template.WriteLine(");");

            return null;
        }

        /// <summary>
        /// Writes an asynchronous method declaration.
        /// </summary>
        private string LoadTemplate_InvokeServiceAsyncParameters(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return null;
            }

            // write method declaration.
            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write("response = await ServerInstance.{1}Async(", serviceType.Response[0].Name, serviceType.Name);

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write("   secureChannelContext");

            if (serviceType.Request != null || serviceType.Request.Length > 0)
            {
                bool first = false;

                foreach (FieldType field in serviceType.Request)
                {
                    if (first)
                    {
                        first = false;
                        template.WriteLine(string.Empty);
                    }
                    else
                    {
                        template.WriteLine(",");
                    }

                    template.Write(context.Prefix);
                    template.Write("   request.{0}", field.Name);
                }
            }

            template.Write(",");
            template.WriteLine("cancellationToken).ConfigureAwait(false);");

            return null;
        }

        /// <summary>
        /// Writes a synchronous method declaration.
        /// </summary>
        private string LoadTemplate_KnownType(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return null;
            }

            // write method declaration.
            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write("#if (OPCUA_INCLUDE_ASYNC && NET_STANDARD_OBSOLETE_SYNC && !OPCUA_EXCLUDE_{0} && !OPCUA_EXCLUDE_{0}_ASYNC)", serviceType.Name);

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write(
                "SupportedServices.Add(DataTypeIds.{0}Request, new ServiceDefinition(typeof({0}Request), new InvokeServiceAsyncEventHandler({0}Async)));",
                serviceType.Name);

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write("#elif (OPCUA_INCLUDE_ASYNC && !OPCUA_EXCLUDE_{0} && !OPCUA_EXCLUDE_{0}_ASYNC)", serviceType.Name);
            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write(
                "SupportedServices.Add(DataTypeIds.{0}Request, new ServiceDefinition(typeof({0}Request), new InvokeServiceEventHandler({0}), new InvokeServiceAsyncEventHandler({0}Async)));",
                serviceType.Name);

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write("#elif (!OPCUA_EXCLUDE_{0})", serviceType.Name);

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write(
                "SupportedServices.Add(DataTypeIds.{0}Request, new ServiceDefinition(typeof({0}Request), new InvokeServiceEventHandler({0})));",
                serviceType.Name);

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write("#endif");

            return null;
        }

        /// <summary>
        /// Writes the classes and interaces that implement a UA server.
        /// </summary>
        private void WriteTemplate_ServerApi(string namespacePrefix)
        {
            List<ServiceSet> serviceSets =
            [
                new ServiceSet("Session", InterfaceType.Discovery, InterfaceType.Session, InterfaceType.Test),
                new ServiceSet("Discovery", InterfaceType.Discovery, InterfaceType.Registration)
            ];

            var writer = new StreamWriter(CoreUtils.Format(@"{0}\{1}.ServerBase.cs", OutputDirectory, namespacePrefix), false);

            try
            {
                var template = new Template(writer, TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_ServerApi_File_cs);

                template.AddReplacement("_Date_", DateTime.Now);
                template.AddReplacement("_Prefix_", namespacePrefix);
                template.AddReplacement("_Namespace_", m_namespaceConstant);

                template.AddTemplate(
                    "// _SERVICESETS_",
                    TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_ServerApi_ServiceSet_cs,
                    serviceSets,
                    null,
                    new WriteTemplateEventHandler(WriteTemplate_ServerApiServiceSet));

                template.WriteTemplate(null);
            }
            finally
            {
                writer.Close();
            }
        }

        /// <summary>
        /// Copies the response paramaters into the request object.
        /// </summary>
        private bool WriteTemplate_ServerApiServiceSet(Template template, Context context)
        {
            if (context.Target is not ServiceSet serviceSet)
            {
                return false;
            }

            List<ServiceType> datatypes = GetListOfServices(serviceSet.Interfaces);

            if (datatypes.Count == 0)
            {
                return false;
            }

            template.AddReplacement("_ServiceSet_", serviceSet.Name);

            template.AddTemplate(
                "// _ServerApi_",
                TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_ServerApi_InterfaceMethod_cs,
                datatypes,
                null,
                new WriteTemplateEventHandler(WriteTemplate_InterfaceMethod));

            template.AddTemplate(
                "// _ServerStubs_",
                TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_ServerApi_Method_cs,
                datatypes,
                null,
                new WriteTemplateEventHandler(WriteTemplate_StubMethod));

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Copies the response paramaters into the request object.
        /// </summary>
        private bool WriteTemplate_InterfaceMethod(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return false;
            }

            template.AddReplacement("_NAME_", serviceType.Name);

            template.AddTemplate(
                "void Interface();",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_SyncParameters),
                null);

            template.AddTemplate(
                "void InterfaceAsync();",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_AsyncParameters),
                null);

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes a service.
        /// </summary>
        private bool WriteTemplate_StubMethod(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return false;
            }

            template.AddReplacement("_NAME_", serviceType.Name);
            template.AddReplacement("_Namespace_", m_namespaceConstant);

            template.AddTemplate(
                "void Stub()",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_SyncParameters),
                null);

            template.AddTemplate(
                "void StubAsync()",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_AsyncParameters),
                null);

            template.AddTemplate(
                "// ResponseParameters",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_InitializeResponseParameters),
                null);

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Copies the response paramaters into the request object.
        /// </summary>
        private string LoadTemplate_InitializeResponseParameters(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return null;
            }

            // calculate maximum parameter length.
            if (serviceType.Response != null)
            {
                bool first = true;

                foreach (FieldType field in serviceType.Response)
                {
                    if (first)
                    {
                        first = false;
                        continue;
                    }

                    template.WriteLine(string.Empty);
                    template.Write(context.Prefix);

                    if (context.Token.Contains("Declare", StringComparison.Ordinal))
                    {
                        template.Write(
                            "{1} {0} = ",
                            field.Name.ToLowerCamelCase(),
                            Validator.GetDotNetTypeName(field.DataType, field.ValueRank));
                    }
                    else
                    {
                        template.Write("{0} = ", field.Name.ToLowerCamelCase());
                    }

                    if (Validator.IsDotNetReferenceType(field))
                    {
                        template.Write("null;");
                    }
                    else
                    {
                        template.Write("{0};", Validator.GetDotNetDefaultValue(field));
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Writes the class that define the service types.
        /// </summary>
        private void WriteTemplate_ClientApi(string namespacePrefix)
        {
            List<ServiceSet> serviceSets = ServiceSets;

            var writer = new StreamWriter(CoreUtils.Format(@"{0}\{1}.Client.cs", OutputDirectory, namespacePrefix), false);

            try
            {
                var template = new Template(writer, TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_ClientApi_File_cs);

                template.AddReplacement("_Date_", DateTime.Now);
                template.AddReplacement("_Prefix_", namespacePrefix);
                template.AddReplacement("_Namespace_", m_namespaceConstant);

                template.AddTemplate(
                    "// _SERVICESETS_",
                    TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_ClientApi_ServiceSet_cs,
                    serviceSets,
                    null,
                    new WriteTemplateEventHandler(WriteTemplate_ClientApiServiceSet));

                template.WriteTemplate(null);
            }
            finally
            {
                writer.Close();
            }
        }

        /// <summary>
        /// Writes a service.
        /// </summary>
        private bool WriteTemplate_ClientApiServiceSet(Template template, Context context)
        {
            if (context.Target is not ServiceSet serviceSet)
            {
                return false;
            }

            // get datatypes.
            List<ServiceType> datatypes = GetListOfServices(serviceSet.Interfaces);

            if (datatypes.Count == 0)
            {
                return false;
            }

            template.AddReplacement("_ServiceSet_", serviceSet.Name);

            template.AddTemplate(
                "// _ClientInterface_",
                TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_ClientApi_Interface_cs,
                datatypes,
                null,
                new WriteTemplateEventHandler(WriteTemplate_Method));

            template.AddTemplate(
                "// _ClientApi_",
                TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_ClientApi_Method_cs,
                datatypes,
                null,
                new WriteTemplateEventHandler(WriteTemplate_Method));

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes a service.
        /// </summary>
        private bool WriteTemplate_Method(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return false;
            }

            bool semicolon = context.Token.Contains("Interface", StringComparison.Ordinal);

            template.AddReplacement("_NAME_", serviceType.Name);
            template.AddReplacement("_Namespace_", m_namespaceConstant);

            template.AddTemplate(
                $"void SyncCall(){(semicolon ? ";" : string.Empty)}",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_SyncParameters),
                null);

            template.AddTemplate(
                $"void AsyncCall(){(semicolon ? ";" : string.Empty)}",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_AsyncParameters),
                null);

            template.AddTemplate(
                $"void BeginAsyncCall(){(semicolon ? ";" : string.Empty)}",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_BeginAsyncParameters),
                null);

            template.AddTemplate(
                $"void EndAsyncCall(){(semicolon ? ";" : string.Empty)}",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_EndAsyncParameters),
                null);

            template.AddTemplate(
                "// RequestParameters",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_RequestParameters),
                null);

            template.AddTemplate(
                "// ResponseParameters",
                null,
                new ServiceType[] { serviceType },
                new LoadTemplateEventHandler(LoadTemplate_ResponseParameters),
                null);

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes a synchronous method declaration.
        /// </summary>
        private string LoadTemplate_SyncParameters(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return null;
            }

            int length = 0;

            List<string> types = [];
            List<string> names = [];

            CollectParameters(serviceType.Request, false, types, names, ref length);
            CollectParameters(serviceType.Response, true, types, names, ref length);

            if (context.Token.Contains("Stub", StringComparison.Ordinal) ||
                context.Token.Contains("Interface", StringComparison.Ordinal))
            {
                const string secureChannelContextType = "SecureChannelContext";
                if (secureChannelContextType.Length > length)
                {
                    length = secureChannelContextType.Length;
                }
                types.Add(secureChannelContextType);
                names.Add("secureChannelContext");
            }

            // write method declaration.
            template.WriteLine(string.Empty);
            template.Write(context.Prefix);

            // write method type if not writing an interface declaration.
            if (!context.Token.Contains(';', StringComparison.Ordinal))
            {
                template.Write("public virtual ");
            }

            template.Write("{0} {1}(", GetReturnType(serviceType), serviceType.Name);

            WriteParameters(template, context, types, names, length);

            // write closing semicolon for interface.
            if (context.Token.Contains(';', StringComparison.Ordinal))
            {
                template.Write(";");
            }

            return null;
        }

        /// <summary>
        /// Writes an asynchronous method declaration.
        /// </summary>
        private string LoadTemplate_AsyncParameters(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return null;
            }

            int length = 0;

            List<string> types = [];
            List<string> names = [];

            if (context.Token.Contains("Stub", StringComparison.Ordinal) ||
                context.Token.Contains("Interface", StringComparison.Ordinal))
            {
                const string secureChannelContextType = "SecureChannelContext";
                if (secureChannelContextType.Length > length)
                {
                    length = secureChannelContextType.Length;
                }
                types.Add(secureChannelContextType);
                names.Add("secureChannelContext");
            }

            CollectParameters(serviceType.Request, false, types, names, ref length);

            const string tokenType = "CancellationToken";
            if (tokenType.Length > length)
            {
                length = tokenType.Length;
            }

            types.Add(tokenType);
            names.Add("ct");

            // write method declaration.
            template.WriteLine(string.Empty);
            template.Write(context.Prefix);

            // write method type if not writing an interface declaration.
            if (!context.Token.Contains(';', StringComparison.Ordinal))
            {
                template.Write("public virtual async ");
            }

            template.Write("Task<{0}Response> {1}Async(", serviceType.Name, serviceType.Name);

            WriteParameters(template, context, types, names, length);

            // write closing semicolon for interface.
            if (context.Token.Contains(';', StringComparison.Ordinal))
            {
                template.Write(";");
            }

            return null;
        }

        /// <summary>
        /// Writes a begin asynchronous method declaration.
        /// </summary>
        private string LoadTemplate_BeginAsyncParameters(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return null;
            }

            int length = 0;

            List<string> types = [];
            List<string> names = [];

            CollectParameters(serviceType.Request, false, types, names, ref length);

            types.Add("AsyncCallback");
            names.Add("callback");

            types.Add("object");
            names.Add("asyncState");

            // write method declaration.
            template.WriteLine(string.Empty);
            template.Write(context.Prefix);

            if (!context.Token.Contains(';', StringComparison.Ordinal))
            {
                template.Write("public virtual ");
            }

            template.Write("IAsyncResult Begin{0}(", serviceType.Name);

            WriteParameters(template, context, types, names, length);

            // write closing semicolon for interface.
            if (context.Token.Contains(';', StringComparison.Ordinal))
            {
                template.Write(";");
            }

            return null;
        }

        /// <summary>
        /// Writes an end asynchronous method declaration.
        /// </summary>
        private string LoadTemplate_EndAsyncParameters(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return null;
            }

            int length = 0;

            List<string> types = [];
            List<string> names = [];

            types.Add("IAsyncResult");
            names.Add("result");

            CollectParameters(serviceType.Response, true, types, names, ref length);

            // write method declaration.
            template.WriteLine(string.Empty);
            template.Write(context.Prefix);

            if (!context.Token.Contains(';', StringComparison.Ordinal))
            {
                template.Write("public virtual ");
            }

            template.Write("{0} End{1}(", GetReturnType(serviceType), serviceType.Name);

            WriteParameters(template, context, types, names, length);

            // write closing semicolon for interface.
            if (context.Token.Contains(';', StringComparison.Ordinal))
            {
                template.Write(";");
            }

            return null;
        }

        /// <summary>
        /// Copies the request paramaters into the request object.
        /// </summary>
        private string LoadTemplate_RequestParameters(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return null;
            }

            // calculate maximum parameter length.
            if (serviceType.Request != null)
            {
                int length = 0;

                foreach (FieldType field in serviceType.Request)
                {
                    string fieldName = field.Name;

                    if (fieldName.Length > length)
                    {
                        length = fieldName.Length;
                    }
                }

                foreach (FieldType field in serviceType.Request)
                {
                    string padding = null;

                    if (field.Name.Length < length)
                    {
                        padding = new string(' ', length - field.Name.Length);
                    }

                    template.WriteLine(string.Empty);
                    template.Write(context.Prefix);
                    template.Write("request.{0}{1} = {2};", field.Name, padding, field.Name.ToLowerCamelCase());
                }
            }

            return null;
        }

        /// <summary>
        /// Copies the response paramaters into the request object.
        /// </summary>
        private string LoadTemplate_ResponseParameters(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return null;
            }

            // calculate maximum parameter length.
            if (serviceType.Response != null)
            {
                int length = 0;
                bool first = true;

                foreach (FieldType field in serviceType.Response)
                {
                    if (first)
                    {
                        first = false;
                        continue;
                    }

                    string fieldName = field.Name;

                    if (fieldName.Length > length)
                    {
                        length = fieldName.Length;
                    }
                }

                first = true;

                foreach (FieldType field in serviceType.Response)
                {
                    if (first)
                    {
                        first = false;
                        continue;
                    }

                    string padding = null;

                    if (field.Name.Length < length)
                    {
                        padding = new string(' ', length - field.Name.Length);
                    }

                    template.WriteLine(string.Empty);
                    template.Write(context.Prefix);

                    if (context.Token.Contains("Set", StringComparison.Ordinal))
                    {
                        template.Write("response.{2}{1} = {0};", field.Name.ToLowerCamelCase(), padding, field.Name);
                    }
                    else
                    {
                        template.Write("{0}{1} = response.{2};", field.Name.ToLowerCamelCase(), padding, field.Name);
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Returns a list of services filter by their interface type.
        /// </summary>
        private List<ServiceType> GetListOfServices(params InterfaceType[] interfaceTypes)
        {
            IReadOnlyList<DataType> datatypes = Validator.GetDataTypeList(
                typeof(ServiceType),
                DictionariesToExport,
                Exclusions,
                m_exportAll,
                true);

            List<ServiceType> services = [];

            for (int ii = 0; ii < datatypes.Count; ii++)
            {
                if (datatypes[ii] is ServiceType serviceType && interfaceTypes != null)
                {
                    foreach (InterfaceType interfaceType in interfaceTypes)
                    {
                        if (interfaceType == serviceType.InterfaceType)
                        {
                            services.Add(serviceType);
                            break;
                        }
                    }
                }
            }

            return services;
        }

        /// <summary>
        /// Writes the interfaces that define the service types.
        /// </summary>
        private void WriteTemplate_Interfaces(string namespacePrefix)
        {
            List<ServiceSet> serviceSets = ServiceSets;

            var writer = new StreamWriter(CoreUtils.Format(
                @"{0}\{1}.Interfaces.cs",
                OutputDirectory,
                namespacePrefix), false);

            try
            {
                var template = new Template(
                    writer,
                    TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Interfaces_File_cs);

                template.AddReplacement("_Prefix_", namespacePrefix);

                template.AddTemplate(
                    "// _SERVICESETS_",
                    TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Interfaces_ServiceSet_cs,
                    serviceSets,
                    null,
                    new WriteTemplateEventHandler(WriteTemplate_Interface));

                template.WriteTemplate(null);
            }
            finally
            {
                writer.Close();
            }
        }

        /// <summary>
        /// Writes the interfaces that define the service types.
        /// </summary>
        private bool WriteTemplate_Interface(Template template, Context context)
        {
            if (context.Target is not ServiceSet serviceSet)
            {
                return false;
            }

            List<ServiceType> datatypes = GetListOfServices(serviceSet.Interfaces);

            if (datatypes.Count == 0)
            {
                return false;
            }

            template.AddReplacement("_Namespace_", m_namespaceConstant);
            template.AddReplacement("_ServicesNamespace_", m_wsdlNamespaceConstant);
            template.AddReplacement("_ServiceSet_", serviceSet.Name);

            template.AddTemplate(
                "// _OPERATIONLIST_",
                TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Interfaces_Operation_cs,
                datatypes,
                null,
                new WriteTemplateEventHandler(WriteTemplate_Service));

            template.AddTemplate(
                "// _ASYNCENDPOINTOPERATIONLIST_",
                TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Interfaces_OperationAsyncEndpoint_cs,
                datatypes,
                null,
                new WriteTemplateEventHandler(WriteTemplate_Service));

            template.AddTemplate(
                "// _ASYNCOPERATIONLIST_",
                TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Interfaces_OperationAsync_cs,
                datatypes,
                null,
                new WriteTemplateEventHandler(WriteTemplate_Service));

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes the class that define the service types.
        /// </summary>
        private void WriteTemplate_Channels(string namespacePrefix)
        {
            List<ServiceSet> serviceSets = ServiceSets;

            var writer = new StreamWriter(CoreUtils.Format(
                @"{0}\{1}.Channels.cs",
                OutputDirectory,
                namespacePrefix), false);

            try
            {
                var template = new Template(
                    writer,
                    TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Channels_File_cs);

                template.AddReplacement("_Date_", DateTime.Now);
                template.AddReplacement("_Prefix_", namespacePrefix);
                template.AddReplacement("_Namespace_", m_namespaceConstant);

                template.AddTemplate(
                    "// _SERVICESETS_",
                    TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Channels_ServiceSet_cs,
                    serviceSets,
                    null,
                    new WriteTemplateEventHandler(WriteTemplate_ChannelsServiceSet));

                template.WriteTemplate(null);
            }
            finally
            {
                writer.Close();
            }
        }

        /// <summary>
        /// Writes a service.
        /// </summary>
        private bool WriteTemplate_ChannelsServiceSet(Template template, Context context)
        {
            if (context.Target is not ServiceSet serviceSet)
            {
                return false;
            }

            // get datatypes.
            List<ServiceType> datatypes = GetListOfServices(serviceSet.Interfaces);

            if (datatypes.Count == 0)
            {
                return false;
            }

            template.AddReplacement("_ServiceSet_", serviceSet.Name);

            template.AddTemplate(
                "// _XmlChannelMethodList_",
                TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Channels_XmlMethod_cs,
                datatypes,
                null,
                new WriteTemplateEventHandler(WriteTemplate_Service));

            template.AddTemplate(
                "// _BinaryChannelMethodList_",
                TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Channels_BinaryMethod_cs,
                datatypes,
                null,
                new WriteTemplateEventHandler(WriteTemplate_Service));

            template.AddTemplate(
                "// _XmlChannelAsyncMethodList_",
                TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Channels_XmlMethodAsync_cs,
                datatypes,
                null,
                new WriteTemplateEventHandler(WriteTemplate_Service));

            template.AddTemplate(
                "// _BinaryChannelAsyncMethodList_",
                TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Channels_BinaryMethodAsync_cs,
                datatypes,
                null,
                new WriteTemplateEventHandler(WriteTemplate_Service));

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes a service.
        /// </summary>
        private bool WriteTemplate_Service(Template template, Context context)
        {
            if (context.Container is ServiceSet serviceSet)
            {
                template.AddReplacement("_ServiceSet_", serviceSet.Name);
            }

            if (context.Target is not ServiceType serviceType)
            {
                return false;
            }

            template.AddReplacement("_NAME_", serviceType.Name);
            template.AddReplacement("_Namespace_", m_namespaceConstant);
            template.AddReplacement("_ServicesNamespace_", m_wsdlNamespaceConstant);
            template.AddReplacement("_TypesNamespace_", m_schemaNamespaceConstant);

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes classes that implement the data types.
        /// </summary>
        private void WriteTemplate_Messages(string namespacePrefix)
        {
            // get datatypes.
            IReadOnlyList<DataType> datatypes = Validator.GetDataTypeList(
                typeof(ServiceType),
                DictionariesToExport,
                Exclusions,
                m_exportAll,
                false);

            if (datatypes.Count == 0)
            {
                return;
            }

            var writer = new StreamWriter(CoreUtils.Format(
                @"{0}\{1}.Messages.cs",
                OutputDirectory,
                namespacePrefix), false);

            try
            {
                var template = new Template(
                    writer,
                    TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Classes_File_cs);

                template.AddReplacement("_Date_", DateTime.Now);
                template.AddReplacement("_Prefix_", namespacePrefix);

                template.AddTemplate(
                    "// _TypeList_",
                    null,
                    datatypes,
                    new LoadTemplateEventHandler(LoadTemplate_Class),
                    new WriteTemplateEventHandler(WriteTemplate_Class));

                template.WriteTemplate(null);
            }
            finally
            {
                writer.Close();
            }
        }

        /// <summary>
        /// Loads the template
        /// </summary>
        private string LoadTemplate_Class(Template template, Context context)
        {
            // do not publish type declarations as classes.
            if (typeof(TypeDeclaration).IsInstanceOfType(context.Target))
            {
                return null;
            }

            if (typeof(ComplexType).IsInstanceOfType(context.Target))
            {
                return TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Classes_Class_cs;
            }

            if (typeof(EnumeratedType).IsInstanceOfType(context.Target))
            {
                return TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Classes_Enumeration_cs;
            }

            if (typeof(ServiceType).IsInstanceOfType(context.Target))
            {
                return TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Classes_Service_cs;
            }

            // do not publish unrecognized sub-types.
            return null;
        }

        /// <summary>
        /// Writes a class.
        /// </summary>
        private bool WriteTemplate_Class(Template template, Context context)
        {
            if (context.Target is not DataType datatype)
            {
                return false;
            }

            template.AddReplacement("_NAME_", datatype.Name);
            template.AddReplacement("_Namespace_", m_namespaceConstant);
            template.AddReplacement("_TypesNamespace_", m_schemaNamespaceConstant);
            template.AddReplacement("// _XMLTYPE_", CoreUtils.Format(
                "[DataContract(Namespace = Namespaces.{0})]",
                m_schemaNamespaceConstant));

            template.AddTemplate(
                "// _COLLECTIONCLASS_",
                TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Classes_ClassCollection_cs,
                new DataType[] { datatype },
                null,
                new WriteTemplateEventHandler(WriteTemplate_Collection));

            template.AddTemplate(
                "// _ENUMCOLLECTIONCLASS_",
                TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Classes_EnumerationCollection_cs,
                new DataType[] { datatype },
                null,
                new WriteTemplateEventHandler(WriteTemplate_Collection));

            if (datatype is ComplexType complexType)
            {
                string baseTypeName = null;

                if (!complexType.BaseType.IsNull())
                {
                    if (Validator.ResolveType(complexType.BaseType) is ComplexType baseType)
                    {
                        baseTypeName = baseType.Name;
                    }
                }
                else
                {
                    baseTypeName = "IEncodeable, IJsonEncodeable";
                }

                if (context.Token == "// _RequestMessage_")
                {
                    baseTypeName += ", IServiceRequest";
                }

                if (context.Token == "// _ResponseMessage_")
                {
                    baseTypeName += ", IServiceResponse";
                }

                template.AddReplacement("_BASETYPE_", baseTypeName);

                List<FieldType> fields = [];

                foreach (FieldType field in complexType.Field)
                {
                    if (!TypeDictionaryValidator.IsExcluded(Exclusions, field))
                    {
                        fields.Add(field);
                    }
                }

                template.AddTemplate(
                    "// _DEFAULTLIST_",
                    null,
                    fields,
                    new LoadTemplateEventHandler(LoadTemplate_DefaultValue),
                    null);

                template.AddTemplate(
                    "// _PROPERTYLIST_",
                    TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Classes_Property_cs,
                    fields,
                    new LoadTemplateEventHandler(LoadTemplate_Property),
                    new WriteTemplateEventHandler(WriteTemplate_Property));

                template.AddTemplate(
                    "// _MEMBERLIST_",
                    null,
                    fields,
                    new LoadTemplateEventHandler(LoadTemplate_Member),
                    null);

                template.AddTemplate(
                    "// _ENCODELIST_",
                    null,
                    fields,
                    new LoadTemplateEventHandler(LoadTemplate_Encode),
                    null);

                template.AddTemplate(
                    "// _DECODELIST_",
                    null,
                    fields,
                    new LoadTemplateEventHandler(LoadTemplate_Decode),
                    null);

                template.AddTemplate(
                    "// _ISEQUALLIST_",
                    null,
                    fields,
                    new LoadTemplateEventHandler(LoadTemplate_IsEqual),
                    null);

                template.AddTemplate(
                    "// _CLONELIST_",
                    null,
                    fields,
                    new LoadTemplateEventHandler(LoadTemplate_Clone),
                    null);

                template.AddTemplate(
                    "// _FIELDNAMES_",
                    null,
                    fields,
                    new LoadTemplateEventHandler(LoadTemplate_FieldNames),
                    null);

                template.AddTemplate(
                    "// _FIELDNAMESWITCH_",
                    null,
                    fields,
                    new LoadTemplateEventHandler(LoadTemplate_GetFieldNameSwitch),
                    null);
            }

            if (datatype is EnumeratedType enumeratedType)
            {
                var values = new List<EnumeratedValue>();

                foreach (EnumeratedValue value in enumeratedType.Value)
                {
                    if (!TypeDictionaryValidator.IsExcluded(Exclusions, value))
                    {
                        values.Add(value);
                    }
                }

                template.AddTemplate(
                    "// _VALUELIST_",
                    TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Classes_EnumerationValue_cs,
                    values,
                    null,
                    new WriteTemplateEventHandler(WriteTemplate_EnumerationValue));
            }

            if (datatype is ServiceType serviceType)
            {
                var requestType = new ComplexType
                {
                    Name = serviceType.Name + "Request"
                };
                requestType.QName = new XmlQualifiedName(
                    requestType.Name,
                    serviceType.QName.Namespace);
                requestType.Field = serviceType.Request;

                template.AddTemplate(
                    "// _RequestMessage_",
                    TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Classes_Class_cs,
                    new DataType[] { requestType },
                    null,
                    new WriteTemplateEventHandler(WriteTemplate_Class));

                var responseType = new ComplexType
                {
                    Name = serviceType.Name + "Response"
                };
                responseType.QName = new XmlQualifiedName(
                    responseType.Name,
                    serviceType.QName.Namespace);
                responseType.Field = serviceType.Response;

                template.AddTemplate(
                    "// _ResponseMessage_",
                    TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Classes_Class_cs,
                    new DataType[] { responseType },
                    null,
                    new WriteTemplateEventHandler(WriteTemplate_Class));
            }

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes the default value for a field.
        /// </summary>
        private string LoadTemplate_DefaultValue(Template template, Context context)
        {
            if (context.Target is not FieldType field)
            {
                return null;
            }

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write(
                "m_{0} = {1};",
                field.Name.ToLowerCamelCase(),
                Validator.GetDotNetDefaultValue(field));

            return null;
        }

        /// <summary>
        /// Loads the template for a property.
        /// </summary>
        private string LoadTemplate_Property(Template template, Context context)
        {
            if (context.Target is not FieldType field)
            {
                return null;
            }

            if (field.ValueRank >= 0)
            {
                return TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Classes_PropertyArray_cs;
            }

            if (Validator.ResolveType(field.DataType) is ComplexType)
            {
                return TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Classes_PropertyArray_cs;
            }

            return TemplateStrings.ModelCompiler_StackGenerator_DotNet_Templates_Classes_Property_cs;
        }

        /// <summary>
        /// Writes a property.
        /// </summary>
        private bool WriteTemplate_Property(Template template, Context context)
        {
            if (context.Target is not FieldType field)
            {
                return false;
            }

            template.AddReplacement(
                "// _XMLTYPE_",
                CoreUtils.Format(
                    "[DataMember(Name = \"{0}\", Order = {1}]",
                    field.Name,
                    context.Index + 1));
            template.AddReplacement("_INTERNALNAME_", field.Name.ToLowerCamelCase());
            template.AddReplacement("_EXTERNALNAME_", field.Name);
            template.AddReplacement(
                "_TYPE_",
                Validator.GetDotNetTypeName(field.DataType, field.ValueRank));

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes an enumeration value.
        /// </summary>
        private bool WriteTemplate_EnumerationValue(Template template, Context context)
        {
            if (context.Target is not EnumeratedValue value)
            {
                return false;
            }

            var enumeratedType = context.Container as EnumeratedType;

            template.AddReplacement(
                "// _XMLTYPE_",
                CoreUtils.Format("[EnumMember(Value = \"{0}_{1}\")]", value.Name, value.Value));
            template.AddReplacement("_NAME_", value.Name);

            if (context.Index < enumeratedType.Value.Length - 1)
            {
                template.AddReplacement("_VALUE_", value.Value + ",");
            }
            else
            {
                template.AddReplacement("_VALUE_", value.Value);
            }

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes a collection class.
        /// </summary>
        private bool WriteTemplate_Collection(Template template, Context context)
        {
            if (context.Target is not DataType datatype || !datatype.AllowArrays)
            {
                return false;
            }

            template.WriteLine(string.Empty);

            template.AddReplacement("_NAME_", datatype.Name);
            template.AddReplacement(
                "// _XMLARRAYTYPE_",
                CoreUtils.Format(
                    "[CollectionDataContract(Name = \"ListOf{0}\", Namespace = Namespaces.{1}, ItemName=\"{0}\")]",
                    datatype.Name,
                    m_schemaNamespaceConstant));

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes the class member for a field.
        /// </summary>
        private string LoadTemplate_FieldNames(Template template, Context context)
        {
            if (context.Target is not FieldType field)
            {
                return null;
            }

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write("/// <remarks />;");
            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write("public const string {0} = \"{0}\";", field.Name);

            return null;
        }

        /// <summary>
        /// Writes the class member for a field.
        /// </summary>
        private string LoadTemplate_GetFieldNameSwitch(Template template, Context context)
        {
            if (context.Target is not FieldType field)
            {
                return null;
            }

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write(
                "case Names.{0}: return m_{1};",
                field.Name,
                field.Name.ToLowerCamelCase());

            return null;
        }

        /// <summary>
        /// Writes the class member for a field.
        /// </summary>
        private string LoadTemplate_Member(Template template, Context context)
        {
            if (context.Target is not FieldType field)
            {
                return null;
            }

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write(
                "private {1} m_{0};",
                field.Name.ToLowerCamelCase(),
                Validator.GetDotNetTypeName(field.DataType, field.ValueRank));

            return null;
        }

        /// <summary>
        /// Writes the encode function for a field.
        /// </summary>
        private string LoadTemplate_Encode(Template template, Context context)
        {
            if (context.Target is not FieldType field)
            {
                return null;
            }

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);

            DataType datatype = Validator.ResolveType(field.DataType);

            if (datatype is EnumeratedType enumeratedType)
            {
                if (field.ValueRank >= 0)
                {
                    template.Write("encoder.WriteEnumeratedArray");
                    template.Write("(\"{0}\", ({1}[]){0}, typeof({1}));", field.Name, enumeratedType.Name);
                }
                else
                {
                    template.Write("encoder.WriteEnumerated");
                    template.Write("(\"{0}\", {0});", field.Name);
                }
            }
            else if (datatype.QName.Namespace == Namespaces.OpcUaBuiltInTypes)
            {
                if (field.ValueRank >= 0)
                {
                    template.Write("encoder.Write{0}Array", datatype.Name);
                }
                else
                {
                    template.Write("encoder.Write{0}", datatype.Name);
                }

                template.Write("(\"{0}\", {0});", field.Name);
            }
            else if (field.ValueRank >= 0)
            {
                template.Write("encoder.WriteEncodeableArray");
                template.Write("(\"{0}\", ({1}[]){0}, typeof({1}));", field.Name, datatype.Name);
            }
            else
            {
                template.Write("encoder.WriteEncodeable");
                template.Write("(\"{0}\", {0}, typeof({1}));", field.Name, datatype.Name);
            }

            return null;
        }

        /// <summary>
        /// Writes the decode function for a field.
        /// </summary>
        private string LoadTemplate_Decode(Template template, Context context)
        {
            if (context.Target is not FieldType field)
            {
                return null;
            }

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);

            DataType datatype = Validator.ResolveType(field.DataType);

            if (datatype is EnumeratedType enumeratedType)
            {
                if (field.ValueRank >= 0)
                {
                    template.Write("{0} = ({1}[])decoder.ReadEnumeratedArray", field.Name, enumeratedType.Name);
                    template.Write("(\"{0}\", typeof({1}));", field.Name, enumeratedType.Name);
                }
                else
                {
                    template.Write("{0} = ({1})decoder.ReadEnumerated", field.Name, enumeratedType.Name);
                    template.Write("(\"{0}\", typeof({1}));", field.Name, enumeratedType.Name);
                }
            }
            else if (datatype.QName.Namespace == Namespaces.OpcUaBuiltInTypes)
            {
                if (field.ValueRank >= 0)
                {
                    template.Write("{0} = decoder.Read{1}Array(\"{0}\");", field.Name, datatype.Name);
                }
                else
                {
                    template.Write("{0} = decoder.Read{1}(\"{0}\");", field.Name, datatype.Name);
                }
            }
            else if (field.ValueRank >= 0)
            {
                template.Write(
                    "{0} = ({1}Collection)decoder.ReadEncodeableArray(\"{0}\", typeof({1}));",
                    field.Name,
                    datatype.Name);
            }
            else
            {
                template.Write(
                    "{0} = ({1})decoder.ReadEncodeable(\"{0}\", typeof({1}));",
                    field.Name,
                    datatype.Name);
            }

            return null;
        }

        /// <summary>
        /// Writes the IsEqual statement for a field.
        /// </summary>
        private string LoadTemplate_IsEqual(Template template, Context context)
        {
            if (context.Target is not FieldType field)
            {
                return null;
            }

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write("if (!CoreUtils.IsEqual(m_{0}, value.m_{0})) return false;", field.Name.ToLowerCamelCase());

            return null;
        }

        /// <summary>
        /// Writes the clone function for a field.
        /// </summary>
        private string LoadTemplate_Clone(Template template, Context context)
        {
            if (context.Target is not FieldType field)
            {
                return null;
            }

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write(
                "clone.m_{0} = ({1})CoreUtils.Clone(this.m_{0});",
                field.Name.ToLowerCamelCase(),
                Validator.GetDotNetTypeName(field.DataType, field.ValueRank));

            return null;
        }

        // Private Methods
        /// <summary>
        /// Collects the parameters to write.
        /// </summary>
        private void CollectParameters(
            FieldType[] fields,
            bool output,
            List<string> types,
            List<string> names,
            ref int length)
        {
            if (fields != null)
            {
                bool first = true;

                foreach (FieldType field in fields)
                {
                    // first parameter is the return parameter.
                    if (first && output)
                    {
                        first = false;
                        continue;
                    }

                    DataType datatype = Validator.ResolveType(field.DataType);

                    string typeName = Validator.GetDotNetTypeName(datatype.QName, field.ValueRank);

                    // prefix out parameters.
                    if (output)
                    {
                        typeName = "out " + typeName;
                    }

                    if (length < typeName.Length)
                    {
                        length = typeName.Length;
                    }

                    types.Add(typeName);
                    names.Add(field.Name.ToLowerCamelCase());
                }
            }
        }

        /// <summary>
        /// Writes a set of method parameters.
        /// </summary>
        private static void WriteParameters(
            Template template,
            Context context,
            List<string> types,
            List<string> names,
            int length)
        {
            for (int ii = 0; ii < types.Count; ii++)
            {
                string typeName = types[ii];

                if (typeName.Length < length)
                {
                    typeName += new string(' ', length - typeName.Length);
                }

                template.WriteLine(string.Empty);
                template.Write(context.Prefix);
                template.Write("    {0} {1}", typeName, names[ii]);

                if (ii < types.Count - 1)
                {
                    template.Write(",");
                }
                else
                {
                    template.Write(")");
                }
            }
        }

        /// <summary>
        /// Gets the return type for the service.
        /// </summary>
        private string GetReturnType(ServiceType serviceType)
        {
            string returnType = "void";

            if (serviceType.Response != null && serviceType.Response.Length > 0)
            {
                DataType datatype = Validator.ResolveType(serviceType.Response[0].DataType);

                if (datatype != null)
                {
                    returnType = Validator.GetDotNetTypeName(datatype.QName, serviceType.Response[0].ValueRank);
                }
            }

            return returnType;
        }

        /// <summary>
        /// A set of services that are grouped into a single interface.
        /// </summary>
        private sealed class ServiceSet
        {
            public ServiceSet(string serviceSet, params InterfaceType[] interfaces)
            {
                Name = serviceSet;
                Interfaces = interfaces;
            }

            public string Name { get; set; }
            public InterfaceType[] Interfaces { get; set; }
        }

        /// <summary>
        /// Returns the service sets available.
        /// </summary>
        private static List<ServiceSet> ServiceSets =>
        [
            new ServiceSet("Session", InterfaceType.Session, InterfaceType.Test),
            new ServiceSet("Discovery", InterfaceType.Discovery),
            new ServiceSet("Registration", InterfaceType.Registration)
        ];

        private bool m_exportAll;
        private string m_namespaceConstant;
        private string m_schemaNamespaceConstant;
        private string m_wsdlNamespaceConstant;
    }
}
