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

using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using BenchmarkDotNet.Attributes;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using Opc.Ua.Tests;

namespace Opc.Ua.SourceGeneration.Tests
{
    /// <summary>
    /// Test generating and compiling stack
    /// </summary>
    [TestFixture]
    [Category("SourceGeneration")]
    [SetCulture("en-us")]
    [SetUICulture("en-us")]
    [MemoryDiagnoser]
    [DisassemblyDiagnoser]
    public class GeneratorTests
    {
        [DatapointSource]
        public OptimizationLevel[] OptimizationLevels = CompilerUtils.SupportedOptimizationLevels;

        [Test]
        public void GenerateTest()
        {
            ITelemetryContext telemetry = NUnitTelemetryContext.Create(logLevel: LogLevel.Error);
            GenerateStack(telemetry);
        }

        [Theory]
        public async Task GenerateAndCompileTestAsync(
            OptimizationLevel optimizationLevel,
            bool withAnalzers,
            bool withNodeLoader)
        {
            // Generate
            ITelemetryContext telemetry = NUnitTelemetryContext.Create(logLevel: LogLevel.Error);
            Dictionary<string, string> generatedText = GenerateStack(telemetry);
            if (withNodeLoader)
            {
                AddPredefinedNodeLoader(generatedText);
            }

            // Parse and compile the generated code
            var sw = Stopwatch.StartNew();
            using var peStream = new MemoryStream();
            using var xmlStream = new MemoryStream();
            bool success = optimizationLevel
                .CreateCompilation()
                .AddCode(generatedText.WithOpcUaCoreStubs(), LanguageVersion.Latest) // Only support latest - internal use only
                .WithAnalyzers(withAnalzers, out CompilationWithAnalyzers compilationWithAnalyzers)
                .Emit(peStream, xmlDocumentationStream: xmlStream)
                .Check(TestContext.Out, out int errorCount, out int warnCount);
            TestContext.Out.WriteLine("Compilation completed in {0} ms", sw.ElapsedMilliseconds);
            if (withAnalzers)
            {
                if (compilationWithAnalyzers == null)
                {
                    Assert.Ignore("Setup does not support analyzer testing");
                }
                AnalysisResult analysisResults =
                    await compilationWithAnalyzers.GetAnalysisResultAsync(default).ConfigureAwait(false);
                analysisResults.GetAllDiagnostics().Check(TestContext.Out,
                    out int analyzerErrors,
                    out int analzyerWarnings);
                Assert.That(analyzerErrors, Is.EqualTo(0), $"Analyzers produced {analyzerErrors} errors");
                TestContext.Out.WriteLine($"Analyzers produced {analzyerWarnings} warnings");
            }
            Assert.That(
                success,
                Is.True,
                $"Compilation failed with {errorCount} errors and {warnCount} warnings.");
            xmlStream.Position = 0;
            var xmlDoc = XDocument.Load(xmlStream);
            Assert.That(xmlDoc, Is.Not.Null);
        }

        [GlobalSetup(Target = nameof(GenerateToFile))]
        [GlobalCleanup(Target = nameof(GenerateToFile))]
        public void Setup()
        {
            try
            {
                Directory.Delete(Path.Combine(Directory.GetCurrentDirectory(), "Benchmark"), true);
            }
            catch
            {
                // Ignore
            }
        }

        [Benchmark]
        public void GenerateToFile()
        {
            ITelemetryContext telemetry = NUnitTelemetryContext.CreateForBenchmarks(logLevel: LogLevel.Error);
            Generators.GenerateStack(
                LocalFileSystem.Instance,
                Path.Combine(Directory.GetCurrentDirectory(), "Benchmark"), [], telemetry);
        }

        [Benchmark]
        public void GenerateToMemory()
        {
            ITelemetryContext telemetry = NUnitTelemetryContext.CreateForBenchmarks(logLevel: LogLevel.Error);
            GenerateStack(telemetry);
        }

        [Benchmark]
        [Arguments(OptimizationLevel.Release)]
        [Arguments(OptimizationLevel.Debug)]
        public void GenerateAndComile(OptimizationLevel optimizationLevel)
        {
            ITelemetryContext telemetry = NUnitTelemetryContext.CreateForBenchmarks(logLevel: LogLevel.Error);
            Dictionary<string, string> generatedText = GenerateStack(telemetry);
            using var peStream = new MemoryStream();
            using var xmlStream = new MemoryStream();
            bool success = optimizationLevel
                .CreateCompilation("Opc.Ua.Core")
                .AddCode(generatedText.WithOpcUaCoreStubs(), LanguageVersion.Latest)
                .Emit(peStream, xmlDocumentationStream: xmlStream)
                .Check(TestContext.Out, out int errorCount, out int warnCount);
        }

        /// <summary>
        /// Generate stack code
        /// </summary>
        /// <returns></returns>
        private static Dictionary<string, string> GenerateStack(ITelemetryContext telemetry)
        {
            // Generate
            var sw = Stopwatch.StartNew();
            using var fileSystem = new VirtualFileSystem();
            Generators.GenerateStack(fileSystem, string.Empty, [], telemetry);
            var generatedText = fileSystem.CreatedFiles
                .Where(c => Path.GetExtension(c) == ".cs")
                .ToDictionary(c => c, c => Encoding.UTF8.GetString(fileSystem.Get(c)));

            TestContext.Out.WriteLine("Generation completed in {0} ms", sw.ElapsedMilliseconds);
            Assert.That(generatedText.Values, Is.All.StartsWith("// <auto-generated />"));

            var generatedOther = fileSystem.CreatedFiles
                .Where(c => Path.GetExtension(c) != ".cs")
                .ToDictionary(c => c, c => Encoding.UTF8.GetString(fileSystem.Get(c)));
            return generatedText;
        }

        public void AddPredefinedNodeLoader(Dictionary<string, string> generated)
        {
            generated.Add("Test.cs",
                """
                namespace Opc.Ua
                {
                    public static partial class LoadingTestData
                    {
                        public static NodeStateCollection Load()
                        {
                            // Use predefined nodes
                            return new NodeStateCollection().AddOpcUa(new SystemContext(null));
                        }
                    }
                }
                """);
        }
    }
}
