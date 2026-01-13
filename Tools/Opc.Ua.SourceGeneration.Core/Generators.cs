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
using System.Collections.Generic;
using System.Threading;
using Opc.Ua.Schema.Model;
using Opc.Ua.Types;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Generator options
    /// </summary>
    public sealed class GeneratorOptions
    {
        /// <summary>
        /// Optimize generated code for compile speed.
        /// </summary>
        public bool OptimizeForCompileSpeed { get; set; }

        /// <summary>
        /// Exclusions to apply on the input
        /// </summary>
        public IReadOnlyList<string> Exclusions { get; set; } = [];

        /// <summary>
        /// Generation should be cancelled
        /// </summary>
        public CancellationToken Cancellation { get; set; }
    }

    /// <summary>
    /// What part of the stack to generate
    /// </summary>
    [Flags]
    public enum StackGenerationType
    {
        /// <summary>
        /// Generate nothing
        /// </summary>
        None,

        /// <summary>
        /// Generate the .NET stack code
        /// </summary>
        Stack,

        /// <summary>
        /// Generate the core models
        /// </summary>
        Models,

        /// <summary>
        /// Generate both stack and models
        /// </summary>
        All
    }

    /// <summary>
    /// Source Generation API
    /// </summary>
    public static class Generators
    {
        /// <summary>
        /// Generate code from design files
        /// </summary>
        /// <param name="designFiles">Design files to process</param>
        /// <param name="fileSystem">File system abstraction to use</param>
        /// <param name="outputDir">Output folder or null</param>
        /// <param name="telemetry">Telemetry context for logging</param>
        /// <param name="options">Generator options</param>
        /// <param name="useAllowSubtypes">allow subtypes</param>
        public static void GenerateCode(
            this DesignFileCollection designFiles,
            IFileSystem fileSystem,
            string outputDir,
            ITelemetryContext telemetry,
            GeneratorOptions options = null,
            bool useAllowSubtypes = false)
        {
            if (designFiles.DesignFiles.Count == 0)
            {
                return;
            }
            options ??= new GeneratorOptions();

            // Combine with embedded resources in this assembly.
            fileSystem = typeof(Generators).Assembly
                .AsFileSystem("Opc.Ua.SourceGeneration.Design")
                .WithFallback(fileSystem);

            // The rest of the input is processed as design files
            ModelDesignValidator modelDesign = fileSystem.OpenModelDesign(
                designFiles,
                null, // identifierFile,
                options.Exclusions,
                telemetry,
                useAllowSubtypes);

            var generator = new ModelGenerator(
                fileSystem,
                outputDir,
                modelDesign,
                telemetry,
                options);
            generator.Emit();
        }

        /// <summary>
        /// Generate from nodesets
        /// </summary>
        /// <param name="nodesets">Nodesets to process</param>
        /// <param name="fileSystem">File system abstraction to use</param>
        /// <param name="outputDir">Output folder or null</param>
        /// <param name="exclusions">Exclusion map</param>
        /// <param name="telemetry">Telemetry context for logging</param>
        /// <param name="options">Generator options</param>
        public static void GenerateCode(
            this NodesetFileCollection nodesets,
            IFileSystem fileSystem,
            string outputDir,
            string[] exclusions,
            ITelemetryContext telemetry,
            GeneratorOptions options = null)
        {
            if (nodesets.Files.Count == 0)
            {
                return;
            }
            options ??= new GeneratorOptions();

            // Combine with embedded resources in this assembly.
            fileSystem = typeof(Generators).Assembly
                .AsFileSystem("Opc.Ua.SourceGeneration.Design")
                .WithFallback(fileSystem);

            foreach (string modelUri in nodesets.ModelUris)
            {
                List<string> designFilesForModel =
                    nodesets.GetDesignFileListForModel(
                        modelUri,
                        out NodesetFile nodeset);
                if (designFilesForModel == null || nodeset.Info.Ignore)
                {
                    continue;
                }
                // The rest of the input is processed as design files
                ModelDesignValidator modelDesign = fileSystem.OpenModelDesign(
                    new DesignFileCollection
                    {
                        DesignFiles = designFilesForModel
                    },
                    null,
                    exclusions,
                    telemetry);

                var generator = new ModelGenerator(
                    fileSystem,
                    outputDir,
                    modelDesign,
                    telemetry,
                    options)
                {
                    AvailableNodeSets = nodesets.Files
                };
                generator.Emit();
            }
        }

        /// <summary>
        /// Generate the .net stack code
        /// </summary>
        /// <param name="generatorType">Generator type</param>
        /// <param name="fileSystem">The root file system to use</param>
        /// <param name="outputDir">Output folder or null</param>
        /// <param name="telemetry">A telemetry context for logging</param>
        /// <param name="options">Generator options</param>
        public static void GenerateStack(
            StackGenerationType generatorType,
            IFileSystem fileSystem,
            string outputDir,
            ITelemetryContext telemetry,
            GeneratorOptions options = null)
        {
            options ??= new GeneratorOptions();
            // Combine with embedded resources in this assembly.
            fileSystem = typeof(Generators).Assembly
                .AsFileSystem("Opc.Ua.SourceGeneration.Design")
                .WithFallback(fileSystem);

            ModelDesignValidator modelDesign = fileSystem.OpenModelDesign(
                new DesignFileCollection
                {
                    DesignFiles = [
                        BuiltInDesignFiles.StandardTypesXml,
                        BuiltInDesignFiles.UACoreServicesXml
                    ],
                    Options = new DesignFileOptions
                    {
                        StartId = 0,
                        ModelVersion = "1.05.06",
                        ModelPublicationDate = "2025-11-08",
                        ReleaseCandidate = true
                    }
                },
                BuiltInDesignFiles.StandardTypesCsv,
                options.Exclusions,
                telemetry,
                false);

            if ((generatorType & StackGenerationType.Stack) != 0)
            {
                var clientApiGenerator = new ClientApiGenerator(
                    fileSystem,
                    outputDir,
                    modelDesign,
                    options);
                clientApiGenerator.Emit();
                var serverApiGenerator = new ServerApiGenerator(
                    fileSystem,
                    outputDir,
                    modelDesign,
                    options);
                serverApiGenerator.Emit();
                var endpointsGenerator = new EndpointsGenerator(
                    fileSystem,
                    outputDir,
                    modelDesign,
                    options);
                endpointsGenerator.Emit();
            }

            if ((generatorType & StackGenerationType.Models) != 0)
            {
                bool validateSchemas = !options.OptimizeForCompileSpeed;
                var typeDictionaries = new Dictionary<string, string>();
                var xmlSchema = new XmlSchemaGeneratorCore(
                    fileSystem,
                    BuiltInDesignFiles.UACoreServicesXml,
                    outputDir,
                    typeDictionaries,
                    options.Exclusions);
                TextFileResource xmlSchemaResource = xmlSchema.Emit(
                    Constants.CoreNamespacePrefix,
                    validateOutput: validateSchemas);

                typeDictionaries = [];
                var binarySchema = new BinarySchemaGeneratorCore(
                    fileSystem,
                    BuiltInDesignFiles.UACoreServicesXml,
                    outputDir,
                    typeDictionaries,
                    options.Exclusions);
                TextFileResource binarySchemaResource = binarySchema.Emit(
                    Constants.CoreNamespacePrefix,
                    Namespaces.OpcUa,
                    validateOutput: validateSchemas);

                var schemaResources = new ResourceGenerator(
                    fileSystem,
                    outputDir,
                    options);
                schemaResources.Embed(
                    Constants.CoreNamespacePrefix,
                    "XmlSchemas",
                    false,
                    binarySchemaResource,
                    xmlSchemaResource);

                var messagesGenerator = new MessagesGenerator(
                    fileSystem,
                    outputDir,
                    modelDesign,
                    options);
                messagesGenerator.Emit();
                var attributesGenerator = new AttributesGenerator(
                    fileSystem,
                    outputDir,
                    options);
                attributesGenerator.Emit();
                var statusCodesGenerator = new StatusCodesGenerator(
                    fileSystem,
                    outputDir,
                    options);
                statusCodesGenerator.Emit();
                var modelGenerator = new ModelGenerator(
                    fileSystem,
                    outputDir,
                    modelDesign,
                    telemetry,
                    options);
                modelGenerator.Emit(skipSchemas: true);
            }
        }
    }
}
