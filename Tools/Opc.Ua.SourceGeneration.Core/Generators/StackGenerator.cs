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
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using Opc.Ua.Schema.Types;
using Opc.Ua.SourceGeneration.Shared;
using Opc.Ua.Types;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Generates code based on a UA Type Dictionary.
    /// </summary>
    internal class StackGenerator
    {
        // Constructors
        /// <summary>
        /// Generates the code from the contents of the address space.
        /// </summary>
        public StackGenerator(
            IFileSystem fileSystem,
            string outputDirectory,
            IReadOnlyList<string> exclusions,
            GeneratorOptions options)
        {
            // load and validate type dictionary.
            var nodeDictionaries = new Dictionary<string, string>();
            Validator = new TypeDictionaryValidator(
                fileSystem,
                nodeDictionaries);

            Validator.Validate(BuiltInDesignFiles.UACoreServicesXml);

            // save output directory.
            m_outputFolder = outputDirectory ?? string.Empty;
            m_fileSystem = fileSystem ?? LocalFileSystem.Instance;
            Exclusions = exclusions;
            Options = options;
        }

        /// <summary>
        /// The validator used to verify the type dictionary.
        /// </summary>
        public TypeDictionaryValidator Validator { get; }

        /// <summary>
        /// The dictionary being processed.
        /// </summary>
        public TypeDictionary Dictionary => Validator.Dictionary;

        /// <summary>
        /// Generator options
        /// </summary>
        public GeneratorOptions Options { get; }

        /// <summary>
        /// The types to exclude.
        /// </summary>
        public IReadOnlyList<string> Exclusions { get; }

        /// <summary>
        /// Generates stack code.
        /// </summary>
        public void Emit(StackGenerationType stackType)
        {
            if ((stackType & StackGenerationType.Stack) != 0)
            {
                GenerateClientApi();
                GenerateServerApi();
                GenerateEndpoints();
                GenerateSchemas();
            }
            if ((stackType & StackGenerationType.Models) != 0)
            {
                GenerateMessages();
                GenerateAttributes();
                GenerateStatusCodes();
            }
        }

        /// <summary>
        /// Generate schemas
        /// </summary>
        private void GenerateSchemas()
        {
            bool validateSchemas = !Options.OptimizeForCompileSpeed;
            var typeDictionaries = new Dictionary<string, string>();
            var xmlSchema = new XmlSchemaGenerator(
                m_fileSystem,
                BuiltInDesignFiles.UACoreServicesXml,
                m_outputFolder,
                typeDictionaries,
                Exclusions);
            TextFileResource xmlSchemaResource = xmlSchema.Emit(
                kNamespacePrefix,
                validateOutput: validateSchemas);

            typeDictionaries = [];
            var binarySchema = new BinarySchemaGenerator(
                m_fileSystem,
                BuiltInDesignFiles.UACoreServicesXml,
                m_outputFolder,
                typeDictionaries,
                Exclusions);
            TextFileResource binarySchemaResource = binarySchema.Emit(
                kNamespacePrefix,
                Namespaces.OpcUa,
                validateOutput: validateSchemas);

            // Embed schemas
            var schemaResources = new ResourceGenerator(
                m_fileSystem,
                m_outputFolder,
                Options);
            schemaResources.Embed(
                kNamespacePrefix,
                "XmlSchemas",
                false,
                binarySchemaResource,
                xmlSchemaResource);
        }

        /// <summary>
        /// Writes the classes and interaces that implement a UA server.
        /// </summary>
        private void GenerateServerApi()
        {
            List<ServiceSet> serviceSets =
            [
                new ServiceSet("Session", InterfaceType.Discovery, InterfaceType.Session, InterfaceType.Test),
                new ServiceSet("Discovery", InterfaceType.Discovery, InterfaceType.Registration)
            ];

            using TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(
                m_outputFolder,
                CoreUtils.Format("{0}.ServerBase.g.cs", kNamespacePrefix)));
            var template = new Template(writer, CodeTemplates.ServerApi_File_cs);

            template.AddReplacement(Tokens.Prefix, kNamespacePrefix);
            template.AddReplacement(Tokens.Namespace, kNamespaceConstant);

            template.AddReplacement(
                Tokens.ServiceSets,
                CodeTemplates.ServerApi_ServiceSet_cs,
                serviceSets,
                WriteTemplate_ServerApiServiceSet);

            template.WriteTemplate();
        }

        /// <summary>
        /// Writes the class that define the service types.
        /// </summary>
        private void GenerateClientApi()
        {
            List<ServiceSet> serviceSets = ServiceSets;

            using TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(
                m_outputFolder,
                CoreUtils.Format("{0}.Client.g.cs", kNamespacePrefix)));
            var template = new Template(writer, CodeTemplates.ClientApi_File_cs);

            template.AddReplacement(Tokens.Prefix, kNamespacePrefix);
            template.AddReplacement(Tokens.Namespace, kNamespaceConstant);

            template.AddReplacement(
                Tokens.ServiceSets,
                CodeTemplates.ClientApi_ServiceSet_cs,
                serviceSets,
                WriteTemplate_ClientApiServiceSet);

            template.WriteTemplate();
        }

        /// <summary>
        /// Writes the classes and interaces that implement a UA endpoint.
        /// </summary>
        private void GenerateEndpoints()
        {
            List<ServiceSet> serviceSets =
            [
                new ServiceSet("Session", InterfaceType.Discovery, InterfaceType.Session, InterfaceType.Test),
                new ServiceSet("Discovery", InterfaceType.Discovery, InterfaceType.Registration)
            ];

            using TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(
                m_outputFolder,
                CoreUtils.Format("{0}.Endpoints.g.cs", kNamespacePrefix)));
            var template = new Template(writer, CodeTemplates.Endpoints_File_cs);

            template.AddReplacement(Tokens.Prefix, kNamespacePrefix);
            template.AddReplacement(Tokens.Namespace, kNamespaceConstant);

            template.AddReplacement(
                Tokens.ServiceSets,
                CodeTemplates.Endpoints_ServiceSet_cs,
                serviceSets,
                WriteTemplate_EndpointServiceSet);

            template.WriteTemplate();
        }

        /// <summary>
        /// Attach the service interfaces to the partial data types
        /// </summary>
        private void GenerateMessages()
        {
            // get datatypes.
            IReadOnlyList<DataType> serviceTypes = Validator.GetDataTypeList(
                typeof(ServiceType),
                [],
                Exclusions,
                true,
                false);

            if (serviceTypes.Count == 0)
            {
                return;
            }

            using TextWriter writer = m_fileSystem.CreateTextWriter(Path.Combine(
                m_outputFolder,
                CoreUtils.Format("{0}.Messages.g.cs", kNamespacePrefix)));
            var template = new Template(writer, CodeTemplates.Messages_File_cs);

            template.AddReplacement(Tokens.Prefix, kNamespacePrefix);

            template.AddReplacement(
                Tokens.TypeList,
                CodeTemplates.Classes_ServiceMessage_cs,
                serviceTypes,
                WriteTemplate_ServiceMessage);

            template.WriteTemplate();
        }

        /// <summary>
        /// Write status codes
        /// </summary>
        private void GenerateStatusCodes()
        {
            string fileName = Path.Combine(m_outputFolder,
                CoreUtils.Format("{0}.StatusCodes.g.cs", kNamespacePrefix));
            using TextWriter writer = m_fileSystem.CreateTextWriter(fileName);

            var template = new Template(writer, CodeTemplates.Constants_File_cs);
            m_className = "StatusCodes";

            template.AddReplacement(Tokens.Prefix, kNamespacePrefix);
            template.AddReplacement(Tokens.ClassName, m_className);

            Validator.Validate(BuiltInDesignFiles.UAStatusCodesXml);
            Dictionary<string, int> identifiers = LoadIdentifiers(BuiltInDesignFiles.StatusCodesCsv);
            var constants = new List<Constant>
            {
                new() { Severity = Severity.Good, Name = nameof(Severity.Good) },
                new() { Severity = Severity.Bad, Name = nameof(Severity.Bad) },
                new() { Severity = Severity.Uncertain, Name = nameof(Severity.Uncertain) }
            };
            foreach (DataType datatype in Dictionary.Items)
            {
                if (!TypeDictionaryValidator.IsExcluded(Exclusions, datatype) &&
                    datatype is Constant constant &&
                    identifiers.TryGetValue(constant.Name, out int id))
                {
                    if (constant.Name.StartsWith(nameof(Severity.Bad), StringComparison.Ordinal))
                    {
                        constant.Severity = Severity.Bad;
                    }
                    else if (constant.Name.StartsWith(nameof(Severity.Good), StringComparison.Ordinal))
                    {
                        constant.Severity = Severity.Good;
                    }
                    else if (constant.Name.StartsWith(nameof(Severity.Uncertain), StringComparison.Ordinal))
                    {
                        constant.Severity = Severity.Uncertain;
                    }
                    constant.Identifier = id;
                    constant.IdentifierSpecified = true;
                    constants.Add(constant);
                }
            }

            // collect datatypes with the specified type.
            template.AddReplacement(
                Tokens.ListOfIdentifiers,
                CodeTemplates.Constants_Constant_cs,
                constants,
                WriteTemplate_Constant);

            var context = new Context();
            template.WriteTemplate();
        }

        /// <summary>
        /// Write attributes
        /// </summary>
        private void GenerateAttributes()
        {
            string fileName = Path.Combine(m_outputFolder,
                CoreUtils.Format("{0}.Attributes.g.cs", kNamespacePrefix));
            using TextWriter writer = m_fileSystem.CreateTextWriter(fileName);

            var template = new Template(writer, CodeTemplates.Constants_File_cs);
            m_className = "Attributes";

            template.AddReplacement(Tokens.Prefix, kNamespacePrefix);
            template.AddReplacement(Tokens.ClassName, m_className);

            Validator.Validate(BuiltInDesignFiles.UAAttributesXml);
            Dictionary<string, int> identifiers = LoadIdentifiers(BuiltInDesignFiles.AttributesCsv);
            var constants = new List<Constant>();
            foreach (DataType datatype in Dictionary.Items)
            {
                if (!TypeDictionaryValidator.IsExcluded(Exclusions, datatype) &&
                    datatype is Constant constant &&
                    identifiers.TryGetValue(constant.Name, out int id))
                {
                    constant.Identifier = id;
                    constant.IdentifierSpecified = true;
                    constants.Add(constant);
                }
            }

            // collect datatypes with the specified type.
            template.AddReplacement(
                Tokens.ListOfIdentifiers,
                CodeTemplates.Constants_Constant_cs,
                constants,
                WriteTemplate_Constant);

            var context = new Context();
            template.WriteTemplate();
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

            template.AddReplacement(Tokens.ServiceSet, serviceSet.Name);

            template.AddReplacement(
                Tokens.MethodList,
                CodeTemplates.Endpoints_Method_cs,
                datatypes,
                WriteTemplate_EndpointMethod);

            template.AddReplacement(
                Tokens.AddKnownType,
                datatypes,
                LoadTemplate_KnownType);

            return template.WriteTemplate();
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

            template.AddReplacement(Tokens.Name, serviceType.Name);

            template.AddReplacement(
                Tokens.InvokeServiceAsync,
                [serviceType],
                LoadTemplate_InvokeServiceAsyncParameters);

            return template.WriteTemplate();
        }

        /// <summary>
        /// Writes an asynchronous method declaration.
        /// </summary>
        private TemplateString LoadTemplate_InvokeServiceAsyncParameters(
            Template template,
            Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return null;
            }

            // write method declaration.
            template.WriteAfterNewLine(
                "response = await ServerInstance.{0}Async(",
                serviceType.Name);
            template.WriteAfterNewLine("    secureChannelContext");

            if (serviceType.Request != null || serviceType.Request.Length > 0)
            {
                foreach (FieldType field in serviceType.Request)
                {
                    template.WriteLine(",");
                    template.Write("    request.{0}", field.Name);
                }
            }

            template.Write(",");
            template.WriteLine("cancellationToken).ConfigureAwait(false);");
            return null;
        }

        /// <summary>
        /// Writes a synchronous method declaration.
        /// </summary>
        private TemplateString LoadTemplate_KnownType(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return null;
            }

            // write method declaration.
            template.WriteNewLine();
            template.WriteAfterNewLine(
                "SupportedServices.Add(DataTypeIds.{0}Request, new ServiceDefinition(typeof({0}Request), new InvokeService({0}Async)));",
                serviceType.Name);
            template.WriteNewLine();

            return null;
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

            List<ServiceType> serviceTypes = GetListOfServices(serviceSet.Interfaces);

            if (serviceTypes.Count == 0)
            {
                return false;
            }

            template.AddReplacement(Tokens.ServiceSet, serviceSet.Name);

            template.AddReplacement(
                Tokens.ServerApi,
                CodeTemplates.ServerApi_InterfaceMethod_cs,
                serviceTypes,
                WriteTemplate_InterfaceMethod);

            template.AddReplacement(
                Tokens.ServerStubs,
                CodeTemplates.ServerApi_Method_cs,
                serviceTypes,
                WriteTemplate_ServerApiMethod);

            return template.WriteTemplate();
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

            template.AddReplacement(Tokens.Name, serviceType.Name);

            template.AddReplacement(
                Tokens.ServerMethodAsync,
                [serviceType],
                (template, context) => LoadTemplate_AsyncParameters(
                    template,
                    context,
                    isInterface: true,
                    isServerApi: true));

            return template.WriteTemplate();
        }

        /// <summary>
        /// Writes a service.
        /// </summary>
        private bool WriteTemplate_ServerApiMethod(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return false;
            }

            template.AddReplacement(Tokens.Name, serviceType.Name);
            template.AddReplacement(Tokens.Namespace, kNamespaceConstant);

            template.AddReplacement(
                Tokens.ServerMethodAsync,
                [serviceType],
                (template, context) => LoadTemplate_AsyncParameters(
                    template,
                    context,
                    isInterface: false,
                    isServerApi: true));

            return template.WriteTemplate();
        }

        /// <summary>
        /// Writes the client api.
        /// </summary>
        private bool WriteTemplate_ClientApiServiceSet(Template template, Context context)
        {
            if (context.Target is not ServiceSet serviceSet)
            {
                return false;
            }

            // get datatypes.
            List<ServiceType> serviceTypes = GetListOfServices(serviceSet.Interfaces);

            if (serviceTypes.Count == 0)
            {
                return false;
            }

            template.AddReplacement(Tokens.ServiceSet, serviceSet.Name);

            template.AddReplacement(
                Tokens.ClientMethod,
                CodeTemplates.ClientApi_InterfaceMethods_cs,
                serviceTypes,
                (template, context) => WriteTemplate_ClientApiMethod(
                    template,
                    context,
                    isInterface: true));

            template.AddReplacement(
                Tokens.ClientApi,
                CodeTemplates.ClientApi_MethodImplementations_cs,
                serviceTypes,
                (template, context) => WriteTemplate_ClientApiMethod(
                    template,
                    context,
                    isInterface: false));

            return template.WriteTemplate();
        }

        /// <summary>
        /// Writes a service.
        /// </summary>
        private bool WriteTemplate_ClientApiMethod(
            Template template,
            Context context,
            bool isInterface)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return false;
            }

            template.AddReplacement(Tokens.Name, serviceType.Name);
            template.AddReplacement(Tokens.Namespace, kNamespaceConstant);

            template.AddReplacement(
                Tokens.ClientMethodSync,
                [serviceType],
                (template, context) => LoadTemplate_SyncParameters(
                    template,
                    context,
                    isInterface));

            template.AddReplacement(
                Tokens.ClientMethodAsync,
                [serviceType],
                (template, context) => LoadTemplate_AsyncParameters(
                    template,
                    context,
                    isInterface,
                    isServerApi: false));

            template.AddReplacement(
                Tokens.ClientMethodBegin,
                [serviceType],
                (template, context) => LoadTemplate_BeginAsyncParameters(
                    template,
                    context,
                    isInterface));

            template.AddReplacement(
                Tokens.ClientMethodEnd,
                [serviceType],
                (template, context) => LoadTemplate_EndAsyncParameters(
                    template,
                    context,
                    isInterface));

            template.AddReplacement(
                Tokens.RequestParameters,
                [serviceType],
                LoadTemplate_RequestParameters);

            template.AddReplacement(
                Tokens.ResponseParameters,
                [serviceType],
                LoadTemplate_ResponseParameters);

            return template.WriteTemplate();
        }

        /// <summary>
        /// Writes a synchronous method declaration.
        /// </summary>
        private TemplateString LoadTemplate_SyncParameters(
            Template template,
            Context context,
            bool isInterface)
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

            // write method declaration.
            template.WriteNewLine();

            // write method type if not writing an interface declaration.
            if (!isInterface)
            {
                template.Write("public virtual ");
            }

            template.Write("{0} {1}(", GetReturnType(serviceType), serviceType.Name);

            WriteParameters(template, context, types, names, length);

            // write closing semicolon for interface.
            if (isInterface)
            {
                template.Write(";");
            }

            return null;
        }

        /// <summary>
        /// Writes an asynchronous method declaration.
        /// </summary>
        private TemplateString LoadTemplate_AsyncParameters(
            Template template,
            Context context,
            bool isInterface,
            bool isServerApi)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return null;
            }

            int length = 0;

            List<string> types = [];
            List<string> names = [];

            if (isServerApi)
            {
                const string secureChannelContextType = "global::Opc.Ua.SecureChannelContext";
                if (secureChannelContextType.Length > length)
                {
                    length = secureChannelContextType.Length;
                }
                types.Add(secureChannelContextType);
                names.Add("secureChannelContext");
            }

            CollectParameters(serviceType.Request, false, types, names, ref length);

            const string tokenType = "global::System.Threading.CancellationToken";
            if (tokenType.Length > length)
            {
                length = tokenType.Length;
            }

            types.Add(tokenType);
            names.Add("ct");

            // write method declaration.
            template.WriteNewLine();

            // write method type if not writing an interface declaration.
            if (!isInterface)
            {
                template.Write("public virtual async ");
            }

            template.Write(
                "global::System.Threading.Tasks.ValueTask<{0}Response> {1}Async(",
                serviceType.Name,
                serviceType.Name);

            WriteParameters(template, context, types, names, length);

            // write closing semicolon for interface.
            if (isInterface)
            {
                template.Write(";");
            }

            return null;
        }

        /// <summary>
        /// Writes a begin asynchronous method declaration.
        /// </summary>
        private TemplateString LoadTemplate_BeginAsyncParameters(
            Template template,
            Context context,
            bool isInterface)
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
            template.WriteNewLine();
            if (!isInterface)
            {
                template.Write("public virtual ");
            }

            template.Write("IAsyncResult Begin{0}(", serviceType.Name);

            WriteParameters(template, context, types, names, length);

            // write closing semicolon for interface.
            if (isInterface)
            {
                template.Write(";");
            }

            return null;
        }

        /// <summary>
        /// Writes an end asynchronous method declaration.
        /// </summary>
        private TemplateString LoadTemplate_EndAsyncParameters(
            Template template,
            Context context,
            bool isInterface)
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
            template.WriteNewLine();
            if (!isInterface)
            {
                template.Write("public virtual ");
            }

            template.Write("{0} End{1}(", GetReturnType(serviceType), serviceType.Name);

            WriteParameters(template, context, types, names, length);

            // write closing semicolon for interface.
            if (isInterface)
            {
                template.Write(";");
            }

            return null;
        }

        /// <summary>
        /// Copies the request paramaters into the request object.
        /// </summary>
        private TemplateString LoadTemplate_RequestParameters(Template template, Context context)
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
                    template.WriteAfterNewLine("request.");
                    template.Write(field.Name);
                    template.Write(" = ");
                    template.Write(field.Name.ToLowerCamelCase());
                    template.Write(";");
                }
            }

            return null;
        }

        /// <summary>
        /// Copies the response paramaters into the request object.
        /// </summary>
        private TemplateString LoadTemplate_ResponseParameters(Template template, Context context)
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
                    template.WriteAfterNewLine(field.Name.ToLowerCamelCase());
                    template.Write(" = response.");
                    template.Write(field.Name);
                    template.Write(";");
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
                [],
                Exclusions,
                true,
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
        /// Writes a service type.
        /// </summary>
        private bool WriteTemplate_ServiceMessage(Template template, Context context)
        {
            if (context.Target is not ServiceType serviceType)
            {
                return false;
            }

            template.AddReplacement(Tokens.Name, serviceType.Name);
            template.AddReplacement(Tokens.Namespace, kNamespaceConstant);
            template.AddReplacement(Tokens.TypesNamespace, kSchemaNamespaceConstant);

            return template.WriteTemplate();
        }

        /// <summary>
        /// Writes a constant.
        /// </summary>
        private bool WriteTemplate_Constant(Template template, Context context)
        {
            if (context.Target is not Constant constant)
            {
                return false;
            }

            if (string.IsNullOrEmpty(constant.Value))
            {
                if (constant.Severity != Severity.None)
                {
                    // Status codes
                    uint id = Convert.ToUInt32(constant.Identifier, CultureInfo.InvariantCulture);
                    id <<= 16;

                    switch (constant.Severity)
                    {
                        case Severity.Bad:
                            id += 0x80000000;
                            break;
                        case Severity.Uncertain:
                            id += 0x40000000;
                            break;
                    }
                    template.AddReplacement(Tokens.IdType, "uint");
                    template.AddReplacement(Tokens.Identifier, CoreUtils.Format("0x{0:X8}", id));
                }
                else
                {
                    // Other
                    template.AddReplacement(Tokens.IdType, "uint");
                    template.AddReplacement(Tokens.Identifier, constant.Identifier);
                }
            }
            else
            {
                template.AddReplacement(Tokens.IdType, "string"); // Never hit
                template.AddReplacement(
                    Tokens.Identifier,
                    CoreUtils.Format("\"{0}\"", constant.Value)); // TODO: Make string resource
            }

            string symbolicId = constant.Name;
            if (constant.Severity != Severity.None && constant.Identifier != 0)
            {
                // Status codes
                string name = constant.Name;
                int index = name.IndexOf('_', StringComparison.Ordinal);
                if (index != -1)
                {
                    name = name[(index + 1)..];
                }
                symbolicId = CoreUtils.Format("{0}{1}", constant.Severity, name);
            }
            template.AddReplacement(Tokens.SymbolicId, symbolicId);

            string description = constant.Documentation.GetDescription();
            if (string.IsNullOrEmpty(description))
            {
                // Never hit - remove
                description = CoreUtils.Format(
                    "The identifier for the {0} datatype.",
                    symbolicId);
            }
            template.AddReplacement(Tokens.Description, description);

            return template.WriteTemplate();
        }

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

                    string typeName = Validator.GetDotNetTypeName(
                        datatype.QName,
                        field.ValueRank,
                        nullable: true);

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

                template.WriteAfterNewLine("    {0} {1}", typeName, names[ii]);

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
                DataType datatype = Validator.ResolveType(
                    serviceType.Response[0].DataType);

                if (datatype != null)
                {
                    returnType = Validator.GetDotNetTypeName(
                        datatype.QName,
                        serviceType.Response[0].ValueRank,
                        nullable: true);
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
        /// Loads the identifiers from a CSV file.
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        private Dictionary<string, int> LoadIdentifiers(string identifiersFile)
        {
            var identifiers = new Dictionary<string, int>();
            int maxId = 1;

            using TextReader reader = m_fileSystem.CreateTextReader(identifiersFile);
            while (true)
            {
                string line = reader.ReadLine();
                if (line == null)
                {
                    break;
                }

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                int index = line.IndexOf(',', StringComparison.Ordinal);

                if (index == -1)
                {
                    continue;
                }

                // remove the node class if it is present.
                int lastIndex = line.LastIndexOf(',');

                if (lastIndex != -1 && index != lastIndex)
                {
                    line = line[..lastIndex];
                }

                string name = line[..index].Trim();

                int uid = Convert.ToInt32(
                    line[(index + 1)..].Trim(),
                    CultureInfo.InvariantCulture);

                if (maxId <= uid)
                {
                    maxId = uid + 1;
                }

                identifiers[name] = uid;
            }
            return identifiers;
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

        private const string kNamespaceConstant = "OpcUa";
        private const string kSchemaNamespaceConstant = "OpcUaXsd";
        private const string kNamespacePrefix = "Opc.Ua";

        private readonly IFileSystem m_fileSystem;
        private readonly string m_outputFolder;
        private string m_className;
    }
}
