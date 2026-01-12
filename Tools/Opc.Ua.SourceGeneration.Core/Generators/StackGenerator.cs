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

using System.Collections.Generic;
using Opc.Ua.Schema.Model;
using Opc.Ua.Types;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Generates code based on a UA Type Dictionary.
    /// </summary>
    internal class StackGenerator
    {
        public const string NamespaceConstant = "OpcUa";
        public const string NamespacePrefix = "Opc.Ua";

        /// <summary>
        /// Generates the code from the contents of the address space.
        /// </summary>
        public StackGenerator(
            IFileSystem fileSystem,
            string outputDirectory,
            ModelDesignValidator validator,
            GeneratorOptions options)
        {
            m_validator = validator;
            m_outputFolder = outputDirectory ?? string.Empty;
            m_fileSystem = fileSystem ?? LocalFileSystem.Instance;
            Options = options;
        }

        /// <summary>
        /// Generator options
        /// </summary>
        public GeneratorOptions Options { get; }

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
            }
            if ((stackType & StackGenerationType.Models) != 0)
            {
                GenerateSchemas();
                GenerateMessages();
                GenerateAttributes();
                GenerateStatusCodes();
            }
        }

        /// <summary>
        /// Generate status codes
        /// </summary>
        private void GenerateStatusCodes()
        {
            var statusCodesGenerator = new StatusCodesGenerator(
                m_fileSystem,
                m_outputFolder,
                Options);
            statusCodesGenerator.Emit();
        }

        /// <summary>
        /// Generate attributes
        /// </summary>
        private void GenerateAttributes()
        {
            var attributesGenerator = new AttributesGenerator(
                m_fileSystem,
                m_outputFolder,
                Options);
            attributesGenerator.Emit();
        }

        /// <summary>
        /// Generate endpoints
        /// </summary>
        private void GenerateEndpoints()
        {
            var endpointsGenerator = new EndpointsGenerator(
                m_fileSystem,
                m_outputFolder,
                m_validator,
                Options);
            endpointsGenerator.Emit();
        }

        /// <summary>
        /// Generate server api
        /// </summary>
        private void GenerateServerApi()
        {
            var serverApiGenerator = new ServerApiGenerator(
                m_fileSystem,
                m_outputFolder,
                m_validator,
                Options);
            serverApiGenerator.Emit();
        }

        /// <summary>
        /// Generate client api
        /// </summary>
        private void GenerateClientApi()
        {
            var clientApiGenerator = new ClientApiGenerator(
                m_fileSystem,
                m_outputFolder,
                m_validator,
                Options);
            clientApiGenerator.Emit();
        }

        /// <summary>
        /// Generate messages
        /// </summary>
        private void GenerateMessages()
        {
            var messagesGenerator = new MessagesGenerator(
                m_fileSystem,
                m_outputFolder,
                m_validator,
                Options);
            messagesGenerator.Emit();
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
                Options.Exclusions);
            TextFileResource xmlSchemaResource = xmlSchema.Emit(
                NamespacePrefix,
                validateOutput: validateSchemas);

            typeDictionaries = [];
            var binarySchema = new BinarySchemaGenerator(
                m_fileSystem,
                BuiltInDesignFiles.UACoreServicesXml,
                m_outputFolder,
                typeDictionaries,
                Options.Exclusions);
            TextFileResource binarySchemaResource = binarySchema.Emit(
                NamespacePrefix,
                Namespaces.OpcUa,
                validateOutput: validateSchemas);

            // Embed schemas
            var schemaResources = new ResourceGenerator(
                m_fileSystem,
                m_outputFolder,
                Options);
            schemaResources.Embed(
                NamespacePrefix,
                "XmlSchemas",
                false,
                binarySchemaResource,
                xmlSchemaResource);
        }

        private readonly IFileSystem m_fileSystem;
        private readonly string m_outputFolder;
        private readonly ModelDesignValidator m_validator;
    }
}
