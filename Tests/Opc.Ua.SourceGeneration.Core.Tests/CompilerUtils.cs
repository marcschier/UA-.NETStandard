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
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Emit;
using Microsoft.CodeAnalysis.Text;

namespace Opc.Ua.SourceGeneration
{
    public static class CompilerUtils
    {
        public static LanguageVersion[] SupportedLanguageVersions =>
        [
            LanguageVersion.CSharp7,
            LanguageVersion.CSharp7_1,
            LanguageVersion.CSharp7_2,
            LanguageVersion.CSharp7_3,
            LanguageVersion.CSharp8,
            LanguageVersion.CSharp9,
            LanguageVersion.CSharp10,
            LanguageVersion.CSharp11,
            LanguageVersion.CSharp12,
            LanguageVersion.CSharp13
         // LanguageVersion.CSharp14,
        ];

        public static OptimizationLevel[] SupportedOptimizationLevels =>
        [
            OptimizationLevel.Debug,
            OptimizationLevel.Release
        ];

        /// <summary>
        /// Get trusted platform assembly references
        /// </summary>
        public static IEnumerable<MetadataReference> TrustedReferences
        {
            get
            {
                string[] trustedAssembliesPaths = ((string)AppContext
                    .GetData("TRUSTED_PLATFORM_ASSEMBLIES"))?
                    .Split(Path.PathSeparator);
                if (trustedAssembliesPaths != null)
                {
                    return trustedAssembliesPaths
                        .Select(p => MetadataReference.CreateFromFile(p));
                }
                return [];
            }
        }

        public static MetadataReference[] DefaultReferences
        {
            get
            {
                string assemblyPath = Path.GetDirectoryName(typeof(object).Assembly.Location);
                string binPath = Path.GetDirectoryName(typeof(CompilerUtils).Assembly.Location);
                MetadataReference[] defaultReferences =
                [
                    MetadataReference.CreateFromFile(Path.Combine(binPath, "Opc.Ua.Types.dll")),
                    MetadataReference.CreateFromFile(Path.Combine(assemblyPath, "System.dll")),
                    MetadataReference.CreateFromFile(Path.Combine(assemblyPath, "System.Core.dll")),
                    MetadataReference.CreateFromFile(Path.Combine(assemblyPath, "System.Runtime.dll")),
                    MetadataReference.CreateFromFile(Path.Combine(assemblyPath, "System.Linq.dll")),
                    MetadataReference.CreateFromFile(Path.Combine(assemblyPath, "System.Xml.dll")),
                    MetadataReference.CreateFromFile(Path.Combine(assemblyPath, "netstandard.dll")),
                    MetadataReference.CreateFromFile(typeof(object).GetTypeInfo().Assembly.Location),
#if NETFRAMEWORK
                    MetadataReference.CreateFromFile(typeof(DataContractAttribute).GetTypeInfo().Assembly.Location),
                    MetadataReference.CreateFromFile(typeof(ReadOnlySpan<>).GetTypeInfo().Assembly.Location),
                    MetadataReference.CreateFromFile(typeof(List<>).GetTypeInfo().Assembly.Location),
                    MetadataReference.CreateFromFile(typeof(ValueTask<>).GetTypeInfo().Assembly.Location)
#else
                    MetadataReference.CreateFromFile(Path.Combine(assemblyPath, "System.Runtime.Serialization.Primitives.dll")),
                    MetadataReference.CreateFromFile(Path.Combine(assemblyPath, "System.Collections.dll")),
                    // MetadataReference.CreateFromFile(Path.Combine(binPath, "System.Threading.Tasks.Extensions.dll"))
                    MetadataReference.CreateFromFile(typeof(ValueTask<>).GetTypeInfo().Assembly.Location)
#endif
                ];
                return defaultReferences;
            }
        }

        /// <summary>
        /// Create a compilation with default references
        /// </summary>
        /// <param name="optimizationLevel"></param>
        /// <param name="assemblyName"></param>
        /// <returns></returns>
        public static CSharpCompilation CreateCompilation(
            this OptimizationLevel optimizationLevel,
            string assemblyName = null)
        {
            assemblyName ??= Path.GetRandomFileName();
            CSharpCompilationOptions compileOptions = new CSharpCompilationOptions(
                OutputKind.DynamicallyLinkedLibrary)
                    .WithOptimizationLevel(optimizationLevel)
                    .WithAllowUnsafe(false);
            return CSharpCompilation.Create(assemblyName)
                .WithOptions(compileOptions)
                .AddReferences(TrustedReferences)
                .AddReferences(DefaultReferences);
        }

        /// <summary>
        /// Add code files to compilation
        /// </summary>
        public static CSharpCompilation AddCode(
            this CSharpCompilation compilation,
            IReadOnlyDictionary<string, string> fileAndCode,
            LanguageVersion languageVersion)
        {
            CSharpParseOptions parseOptions = new CSharpParseOptions()
                .WithKind(SourceCodeKind.Regular)
                .WithLanguageVersion(languageVersion);
            SyntaxTree[] syntaxTrees =
                [.. fileAndCode
                    .Append(new KeyValuePair<string, string>(nameof(OpcUaCoreStubs), OpcUaCoreStubs))
                    .Select(c => CSharpSyntaxTree.ParseText(c.Value, parseOptions, c.Key))];
            return compilation.AddSyntaxTrees(syntaxTrees);
        }

        /// <summary>
        /// Check diagnostics
        /// </summary>
        /// <param name="diagnostics"></param>
        /// <param name="output"></param>
        /// <param name="errorCount"></param>
        /// <returns></returns>
        public static void Check(
            this ImmutableArray<Diagnostic> diagnostics,
            TextWriter output,
            out int errorCount,
            out int warnCount)
        {
            errorCount = 0;
            warnCount = 0;
            for (int ii = 0; ii < diagnostics.Length; ii++)
            {
                Diagnostic diag = diagnostics[ii];
                string sev;
                int beforeAfter;
                switch (diag.Severity)
                {
                    case DiagnosticSeverity.Error:
                        sev = "ERR";
                        beforeAfter = 30;
                        errorCount++;
                        break;
                    case DiagnosticSeverity.Warning:
                        beforeAfter = 2;
                        sev = "WRN";
                        warnCount++;
                        break;
                    default:
                        beforeAfter = 1;
                        sev = "INF";
                        break;
                }
                output.WriteLine();
                output.WriteLine(diag.ToString());
                TextLineCollection lines = diag.Location.SourceTree?.GetText().Lines;
                if (lines == null)
                {
                    continue;
                }
                FileLinePositionSpan span = diag.Location.GetLineSpan();
                int startLine = span.StartLinePosition.Line;
                int endLine = span.EndLinePosition.Line;
                for (int i = Math.Max(0, startLine - beforeAfter);
                    i <= Math.Min(endLine + beforeAfter, lines.Count - 1);
                    i++)
                {
                    // line error indicators are 0 based, but line positions are 1 based
                    output.Write("{0,4} ", i - 1);
                    output.Write(i >= startLine && i <= endLine ? sev + ">>>> " : "        ");
                    output.WriteLine(lines[i]);
                }
            }
        }

        public static CSharpCompilation WithAnalyzers(
            this CSharpCompilation compilation,
            bool withAnalzers,
            out CompilationWithAnalyzers compilationWithAnalyzers)
        {
            if (withAnalzers)
            {
                try
                {
                    Assembly dependencies = LoadFromNugetCache(
                        Path.Combine("microsoft.codeanalysis.workspaces.common", "4.14.0", "lib", "netstandard2.0"),
                        "Microsoft.CodeAnalysis.Workspaces.dll");
                    Assembly netAnalyzer = LoadFromNugetCache(
                        Path.Combine("microsoft.codeAnalysis.netanalyzers", "10.0.100", "analyzers", "dotnet"),
                        "Microsoft.CodeAnalysis.NetAnalyzers.dll");
                    if (netAnalyzer != null)
                    {
                        DiagnosticAnalyzer[] analyzers = [.. netAnalyzer.GetTypes()
                            .Where(t => t.GetCustomAttribute<DiagnosticAnalyzerAttribute>() is not null)
                            .Select(t => (DiagnosticAnalyzer)Activator.CreateInstance(t))];
                        compilationWithAnalyzers = compilation.WithAnalyzers(
                            ImmutableArray.Create(analyzers),
                            new CompilationWithAnalyzersOptions(null, null, true, true, true));
                        return (CSharpCompilation)compilationWithAnalyzers.Compilation;
                    }
                }
                catch
                {
                    // ignore errors loading analyzers
                }
            }
            compilationWithAnalyzers = null;
            return compilation;

            static Assembly LoadFromNugetCache(string path, string dll)
            {
                string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                string location = Path.Combine(
                    userProfile,
                    ".nuget",
                    "packages",
                    path);
                string file = Path.Combine(location, dll);
                if (!File.Exists(file))
                {
                    file = Path.Combine(location, "cs", dll);
                }
                if (File.Exists(file))
                {
                    return Assembly.LoadFrom(file);
                }
                return null;
            }
        }

        /// <summary>
        /// Helper to debug diagnostics returned by compilation
        /// </summary>
        /// <param name="emitResult"></param>
        /// <returns>Number or errors and warnings in the result</returns>
        public static bool Check(
            this EmitResult emitResult,
            TextWriter errorWriter,
            out int errorCount,
            out int warnCount)
        {
            emitResult.Diagnostics.Check(errorWriter, out errorCount, out warnCount);
            return emitResult.Success;
        }

        /// <summary>
        /// All stubs needed to compile generated code against Opc.Ua.Core without
        /// referencing the actual assembly.
        /// </summary>
        public const string OpcUaCoreStubs =
            """
            #nullable enable
            using System;
            using System.Threading.Tasks;
            using System.Threading;
            using System.Collections.Generic;
            using System.Reflection;

            [assembly: AssemblyVersionAttribute("4.3.2.1")]
            namespace Opc.Ua
            {
                public static partial class StatusCodes
                {
                    public const uint Good = 0;
                }
                public interface IServiceRequest
                {
                    RequestHeader? RequestHeader { get; set; }
                }
                public interface IServiceResponse
                {
                    ResponseHeader? ResponseHeader { get;}
                }
                public class SecureChannelContext {}
                public interface ITransportChannel
                {
                    ValueTask<IServiceResponse> SendRequestAsync(
                        IServiceRequest request,
                        CancellationToken ct = default);
                    [Obsolete("Use SendRequestAsync instead")]
                    IServiceResponse SendRequest(
                        IServiceRequest request);
                    [Obsolete("Use SendRequestAsync instead")]
                        IAsyncResult BeginSendRequest(
                        IServiceRequest request,
                        AsyncCallback callback,
                        object callbackData);
                    [Obsolete("Use SendRequestAsync instead")]
                    IServiceResponse EndSendRequest(
                        IAsyncResult result);
                }
                public interface IServerBase {}
                public interface IEndpointBase {}
                public interface IServiceHostBase {}
                public enum RequestEncoding { Binary, Xml }
                public class EndpointBase
                {
                    [Obsolete("No WCF support")]
                    protected EndpointBase() {}
                    protected EndpointBase(IServiceHostBase host) {}
                    protected EndpointBase(ServerBase serverBase) {}
                    protected IServerBase? ServerForContext => throw new NotSupportedException();
                    protected ServiceResult? ServerError { get; set; }
                    protected virtual void OnRequestReceived(IServiceRequest request) {}
                    protected virtual void OnResponseSent(IServiceResponse response) {}
                    protected Dictionary<ExpandedNodeId, ServiceDefinition> SupportedServices { get; set; } = new();
                    protected class ServiceDefinition
                    {
                        public ServiceDefinition(Type requestType, InvokeService asyncInvokeMethod) {}
                    }
                    protected delegate ValueTask<IServiceResponse> InvokeService(
                        IServiceRequest request,
                        SecureChannelContext secureChannelContext,
                        CancellationToken cancellationToken = default);
                }
                public class ServerBase : IServerBase
                {
                    public ServerBase(ITelemetryContext telemetry) {}
                    public ServiceResult? ServerError { get; protected set; }
                    protected virtual void ValidateRequest(RequestHeader? requestHeader) {}
                    protected virtual ResponseHeader CreateResponse(
                        RequestHeader requestHeader, uint statusCode)
                        => throw new NotSupportedException();
                }
                public partial class HistoryUpdateDetails
                {
                    public virtual NodeId NodeId { get; set; }
                }
                public interface IClientBase {}
                public class ClientBase : IClientBase
                {
                    public ClientBase(ITransportChannel channel, ITelemetryContext telemetry) { }
                    public ITransportChannel TransportChannel => throw new NotSupportedException();

                    protected static void ValidateResponse(
                        ResponseHeader? header) {}
                    protected virtual void UpdateRequestHeader(
                        IServiceRequest request, bool useDefaults, string serviceName) {}
                    protected virtual void RequestCompleted(
                        IServiceRequest request, IServiceResponse response,
                        string serviceName) {}
                }
                public class FolderState : BaseObjectState
                {
                    public FolderState(NodeState? parent) : base(parent) { }
                }
            }
            """;
    }
}
