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
using System.IO;
using System.Xml;
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
            string typeDictionary,
            string outputDirectory,
            IDictionary<string, string> knownFiles,
            IReadOnlyList<string> exclusions,
            GeneratorOptions options)
        {
            // load and validate type dictionary.
            Validator = new TypeDictionaryValidator(
                fileSystem,
                knownFiles);
            Validator.Validate(typeDictionary);

            // save output directory.
            OutputDirectory = outputDirectory;
            FileSystem = fileSystem ?? LocalFileSystem.Instance;
            DictionariesToExport = [];
            Exclusions = exclusions;
            Options = options;
        }

        /// <summary>
        /// File system used
        /// </summary>
        protected IFileSystem FileSystem { get; }

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

        /// <summary>
        /// Generator options
        /// </summary>
        public GeneratorOptions Options { get; }

        // Public Methods
        /// <summary>
        /// Generates the datatype files.
        /// </summary>
        public virtual void Generate(string namespacePrefix, string dictionaryName, bool exportAll)
        {
            DictionaryName = dictionaryName;

            m_namespaceConstant = "OpcUa";
            m_schemaNamespaceConstant = "OpcUaXsd";

            m_exportAll = exportAll;

            WriteTemplate_Messages(namespacePrefix);
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

            using TextWriter writer = FileSystem.CreateTextWriter(Path.Combine(
                OutputDirectory,
                CoreUtils.Format("{0}.Endpoints.g.cs", namespacePrefix)));
            var template = new Template(writer, CodeTemplateStrings.Endpoints_File_cs);

            template.AddReplacement(Tokens.Date, DateTime.Now);
            template.AddReplacement(Tokens.Prefix, namespacePrefix);
            template.AddReplacement(Tokens.Namespace, m_namespaceConstant);

            template.AddTemplate(
                Tokens.ServiceSets,
                CodeTemplateStrings.Endpoints_ServiceSet_cs,
                serviceSets,
                null,
                WriteTemplate_EndpointServiceSet);

            template.WriteTemplate(null);
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

            template.AddTemplate(
                Tokens.MethodList,
                CodeTemplateStrings.Endpoints_Method_cs,
                datatypes,
                null,
                WriteTemplate_EndpointMethod);

            template.AddTemplate(
                Tokens.AddKnownType,
                null,
                datatypes,
                LoadTemplate_KnownType,
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

            template.AddReplacement(Tokens.Name, serviceType.Name);

            template.AddTemplate(
                Tokens.InvokeServiceAsync,
                null,
                new ServiceType[] { serviceType },
                LoadTemplate_InvokeServiceAsyncParameters,
                null);

            return template.WriteTemplate(context);
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

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);
            template.Write(
                "SupportedServices.Add(DataTypeIds.{0}Request, new ServiceDefinition(typeof({0}Request), new InvokeService({0}Async)));",
                serviceType.Name);

            template.WriteLine(string.Empty);
            template.Write(context.Prefix);

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

            using TextWriter writer = FileSystem.CreateTextWriter(Path.Combine(
                OutputDirectory,
                CoreUtils.Format("{0}.ServerBase.g.cs", namespacePrefix)));
            var template = new Template(writer, CodeTemplateStrings.ServerApi_File_cs);

            template.AddReplacement(Tokens.Date, DateTime.Now);
            template.AddReplacement(Tokens.Prefix, namespacePrefix);
            template.AddReplacement(Tokens.Namespace, m_namespaceConstant);

            template.AddTemplate(
                Tokens.ServiceSets,
                CodeTemplateStrings.ServerApi_ServiceSet_cs,
                serviceSets,
                null,
                WriteTemplate_ServerApiServiceSet);

            template.WriteTemplate(null);
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

            template.AddReplacement(Tokens.ServiceSet, serviceSet.Name);

            template.AddTemplate(
                Tokens.ServerApi,
                CodeTemplateStrings.ServerApi_InterfaceMethod_cs,
                datatypes,
                null,
                WriteTemplate_InterfaceMethod);

            template.AddTemplate(
                Tokens.ServerStubs,
                CodeTemplateStrings.ServerApi_Method_cs,
                datatypes,
                null,
                WriteTemplate_StubMethod);

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

            template.AddReplacement(Tokens.Name, serviceType.Name);

            template.AddTemplate(
                Tokens.ServerInterfaceAsync,
                null,
                new ServiceType[] { serviceType },
                LoadTemplate_AsyncParameters,
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

            template.AddReplacement(Tokens.Name, serviceType.Name);
            template.AddReplacement(Tokens.Namespace, m_namespaceConstant);

            template.AddTemplate(
                Tokens.ServerStubAsync,
                null,
                new ServiceType[] { serviceType },
                LoadTemplate_AsyncParameters,
                null);

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes the class that define the service types.
        /// </summary>
        private void WriteTemplate_ClientApi(string namespacePrefix)
        {
            List<ServiceSet> serviceSets = ServiceSets;

            using TextWriter writer = FileSystem.CreateTextWriter(Path.Combine(
                OutputDirectory,
                CoreUtils.Format("{0}.Client.g.cs", namespacePrefix)));
            var template = new Template(writer, CodeTemplateStrings.ClientApi_File_cs);

            template.AddReplacement(Tokens.Date, DateTime.Now);
            template.AddReplacement(Tokens.Prefix, namespacePrefix);
            template.AddReplacement(Tokens.Namespace, m_namespaceConstant);

            template.AddTemplate(
                Tokens.ServiceSets,
                CodeTemplateStrings.ClientApi_ServiceSet_cs,
                serviceSets,
                null,
                WriteTemplate_ClientApiServiceSet);

            template.WriteTemplate(null);
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

            template.AddReplacement(Tokens.ServiceSet, serviceSet.Name);

            template.AddTemplate(
                Tokens.ClientInterface,
                CodeTemplateStrings.ClientApi_Interface_cs,
                datatypes,
                null,
                WriteTemplate_Method);

            template.AddTemplate(
                Tokens.ClientApi,
                CodeTemplateStrings.ClientApi_Method_cs,
                datatypes,
                null,
                WriteTemplate_Method);

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

            template.AddReplacement(Tokens.Name, serviceType.Name);
            template.AddReplacement(Tokens.Namespace, m_namespaceConstant);

            template.AddTemplate(
                $"void SyncCall(){(semicolon ? ";" : string.Empty)}",
                null,
                new ServiceType[] { serviceType },
                LoadTemplate_SyncParameters,
                null);

            template.AddTemplate(
                $"void AsyncCall(){(semicolon ? ";" : string.Empty)}",
                null,
                new ServiceType[] { serviceType },
                LoadTemplate_AsyncParameters,
                null);

            template.AddTemplate(
                $"void BeginAsyncCall(){(semicolon ? ";" : string.Empty)}",
                null,
                new ServiceType[] { serviceType },
                LoadTemplate_BeginAsyncParameters,
                null);

            template.AddTemplate(
                $"void EndAsyncCall(){(semicolon ? ";" : string.Empty)}",
                null,
                new ServiceType[] { serviceType },
                LoadTemplate_EndAsyncParameters,
                null);

            template.AddTemplate(
                Tokens.RequestParameters,
                null,
                new ServiceType[] { serviceType },
                LoadTemplate_RequestParameters,
                null);

            template.AddTemplate(
                Tokens.ResponseParameters,
                null,
                new ServiceType[] { serviceType },
                LoadTemplate_ResponseParameters,
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

            if (context.Token.Contains("Stub", StringComparison.Ordinal) ||
                context.Token.Contains("Interface", StringComparison.Ordinal))
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
            CollectParameters(serviceType.Response, true, types, names, ref length);

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
            template.WriteLine(string.Empty);
            template.Write(context.Prefix);

            // write method type if not writing an interface declaration.
            if (!context.Token.Contains(';', StringComparison.Ordinal))
            {
                template.Write("public virtual async ");
            }

            template.Write("global::System.Threading.Tasks.ValueTask<{0}Response> {1}Async(", serviceType.Name, serviceType.Name);

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

            using TextWriter writer = FileSystem.CreateTextWriter(Path.Combine(
                OutputDirectory,
                CoreUtils.Format("{0}.Messages.g.cs", namespacePrefix)));
            var template = new Template(writer, CodeTemplateStrings.Classes_File_cs);

            template.AddReplacement(Tokens.Date, DateTime.Now);
            template.AddReplacement(Tokens.Prefix, namespacePrefix);

            template.AddTemplate(
                Tokens.TypeList,
                null,
                datatypes,
                LoadTemplate_Class,
                WriteTemplate_Class);

            template.WriteTemplate(null);
        }

        /// <summary>
        /// Loads the template
        /// </summary>
        private string LoadTemplate_Class(Template template, Context context)
        {
            // do not publish type declarations as classes.
            if (context.Target is TypeDeclaration)
            {
                return null;
            }

            if (context.Target is ComplexType)
            {
                return CodeTemplateStrings.Classes_Class_cs;
            }

            if (context.Target is EnumeratedType)
            {
                return CodeTemplateStrings.Classes_Enumeration_cs;
            }

            if (context.Target is ServiceType)
            {
                return CodeTemplateStrings.Classes_Service_cs;
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

            template.AddReplacement(Tokens.Name, datatype.Name);
            template.AddReplacement(Tokens.Namespace, m_namespaceConstant);
            template.AddReplacement(Tokens.TypesNamespace, m_schemaNamespaceConstant);

            template.AddTemplate(
                Tokens.CollectionClass,
                CodeTemplateStrings.Classes_ClassCollection_cs,
                new DataType[] { datatype },
                null,
                WriteTemplate_Collection);

            template.AddTemplate(
                Tokens.EnumCollectionClass,
                CodeTemplateStrings.Classes_EnumerationCollection_cs,
                new DataType[] { datatype },
                null,
                WriteTemplate_Collection);

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
                    baseTypeName = "global::Opc.Ua.IEncodeable, global::Opc.Ua.IJsonEncodeable";
                }

                if (context.Token == Tokens.RequestMessage)
                {
                    baseTypeName += ", global::Opc.Ua.IServiceRequest";
                }

                if (context.Token == Tokens.ResponseMessage)
                {
                    baseTypeName += ", global::Opc.Ua.IServiceResponse";
                }

                template.AddReplacement(Tokens.BaseType, baseTypeName);

                List<FieldType> fields = [];

                foreach (FieldType field in complexType.Field)
                {
                    if (!TypeDictionaryValidator.IsExcluded(Exclusions, field))
                    {
                        fields.Add(field);
                    }
                }

                template.AddTemplate(
                    Tokens.DefaultList,
                    null,
                    fields,
                    LoadTemplate_DefaultValue,
                    null);

                template.AddTemplate(
                    Tokens.PropertyList,
                    CodeTemplateStrings.Classes_Property_cs,
                    fields,
                    LoadTemplate_Property,
                    WriteTemplate_Property);

                template.AddTemplate(
                    Tokens.MemberList,
                    null,
                    fields,
                    LoadTemplate_Member,
                    null);

                template.AddTemplate(
                    Tokens.EncodeList,
                    null,
                    fields,
                    LoadTemplate_Encode,
                    null);

                template.AddTemplate(
                    Tokens.DecodeList,
                    null,
                    fields,
                    LoadTemplate_Decode,
                    null);

                template.AddTemplate(
                    Tokens.IsEqualList,
                    null,
                    fields,
                    LoadTemplate_IsEqual,
                    null);

                template.AddTemplate(
                    Tokens.CloneList,
                    null,
                    fields,
                    LoadTemplate_Clone,
                    null);

                template.AddTemplate(
                    Tokens.FieldNames,
                    null,
                    fields,
                    LoadTemplate_FieldNames,
                    null);

                template.AddTemplate(
                    Tokens.FieldNameSwitch,
                    null,
                    fields,
                    LoadTemplate_GetFieldNameSwitch,
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
                    Tokens.ValueList,
                    CodeTemplateStrings.Classes_EnumerationValue_cs,
                    values,
                    null,
                    WriteTemplate_EnumerationValue);
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
                    Tokens.RequestMessage,
                    CodeTemplateStrings.Classes_Class_cs,
                    new DataType[] { requestType },
                    null,
                    WriteTemplate_Class);

                var responseType = new ComplexType
                {
                    Name = serviceType.Name + "Response"
                };
                responseType.QName = new XmlQualifiedName(
                    responseType.Name,
                    serviceType.QName.Namespace);
                responseType.Field = serviceType.Response;

                template.AddTemplate(
                    Tokens.ResponseMessage,
                    CodeTemplateStrings.Classes_Class_cs,
                    new DataType[] { responseType },
                    null,
                    WriteTemplate_Class);
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
                return CodeTemplateStrings.Classes_PropertyArray_cs;
            }

            if (Validator.ResolveType(field.DataType) is ComplexType)
            {
                return CodeTemplateStrings.Classes_PropertyArray_cs;
            }

            return CodeTemplateStrings.Classes_Property_cs;
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
                Tokens.XmlType,
                CoreUtils.Format(
                    "[global::System.Runtime.Serialization.DataMember(Name = \"{0}\", Order = {1}]",
                    field.Name,
                    context.Index + 1));
            template.AddReplacement(Tokens.InternalName, field.Name.ToLowerCamelCase());
            template.AddReplacement(Tokens.ExternalName, field.Name);
            template.AddReplacement(
                Tokens.Type,
                Validator.GetDotNetTypeName(
                    field.DataType,
                    field.ValueRank,
                    nullable: true));

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
                Tokens.XmlType,
                CoreUtils.Format("[global.System.Runtime.Serialization.EnumMember(Value = \"{0}_{1}\")]", value.Name, value.Value));
            template.AddReplacement(Tokens.Name, value.Name);

            if (context.Index < enumeratedType.Value.Length - 1)
            {
                template.AddReplacement(Tokens.Value, value.Value + ",");
            }
            else
            {
                template.AddReplacement(Tokens.Value, value.Value);
            }

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes a collection class.
        /// </summary>
        private bool WriteTemplate_Collection(Template template, Context context)
        {
            if (context.Target is not DataType datatype ||
                !datatype.AllowArrays)
            {
                return false;
            }

            template.WriteLine(string.Empty);

            template.AddReplacement(Tokens.Name, datatype.Name);
            template.AddReplacement(Tokens.XmlNamespaceUri, m_schemaNamespaceConstant);

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
                Validator.GetDotNetTypeName(
                    field.DataType,
                    field.ValueRank,
                    nullable: true));

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
                Validator.GetDotNetTypeName(
                    field.DataType,
                    field.ValueRank,
                    nullable: true));

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
    }
}
