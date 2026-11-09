/* ========================================================================
 * Copyright (c) 2005-2026 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using Opc.Ua.Gds.Server.Onboarding;
using Opc.Ua.Tests;

namespace Opc.Ua.Gds.Tests.Onboarding
{
    /// <summary>
    /// Checks bounded acceptance, isolated descriptions, observable failure, and cooperative host shutdown.
    /// </summary>
    [TestFixture]
    [Category("Onboarding")]
    public sealed class DeviceRegistrarPushSchedulerTests
    {
        /// <summary>
        /// Constructor dependencies cannot be replaced by an accepting no-op processor or missing diagnostics.
        /// </summary>
        [Test]
        public void ConstructorRejectsMissingDependencies()
        {
            Assert.That(() => new DeviceRegistrarPushScheduler(null!, NUnitTelemetryContext.Create()),
                Throws.ArgumentNullException);
            Assert.That(() => new DeviceRegistrarPushScheduler(new Processor(), null!),
                Throws.ArgumentNullException);
        }

        /// <summary>
        /// Capacity is explicit and bounded before any worker is started.
        /// </summary>
        [TestCase(0)]
        [TestCase(-1)]
        [TestCase(1025)]
        public void ConstructorRejectsInvalidCapacity(int capacity)
        {
            Assert.That(() => new DeviceRegistrarPushScheduler(
                new Processor(), NUnitTelemetryContext.Create(), capacity),
                Throws.TypeOf<ArgumentOutOfRangeException>());
        }

        /// <summary>
        /// Both supported capacity limits construct without allocating a worker.
        /// </summary>
        [TestCase(1)]
        [TestCase(1024)]
        public void ConstructorAcceptsCapacityBoundaries(int capacity)
        {
            using var scheduler = new DeviceRegistrarPushScheduler(
                new Processor(), NUnitTelemetryContext.Create(), capacity);
            Assert.That(scheduler, Is.InstanceOf<IDeviceRegistrarPushScheduler>());
        }

        /// <summary>
        /// Durable startup refuses to retry persisted work unless the processor can reconcile interrupted effects.
        /// </summary>
        [Test]
        public async Task DurableStartupRequiresRecoveryProcessor()
        {
            using var workStore = new Mock<IDeviceRegistrarPushWorkStore>().Object;
            using var scheduler = new DeviceRegistrarPushScheduler(
                new Processor(), NUnitTelemetryContext.Create(), capacity: 32, workStore: workStore);

            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await scheduler.StartAsync(CancellationToken.None).ConfigureAwait(false));
        }

        /// <summary>
        /// A crashed attempt still occupies pending capacity when another restored item runs first.
        /// </summary>
        [Test]
        public async Task RestartCountsPreviouslyProcessingWorkAgainstPendingCapacity()
        {
            using var fileSystem = new VirtualFileSystem();
            var telemetry = NUnitTelemetryContext.Create();
            const string path = "push-restart-capacity.bin";
            Guid pendingId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            Guid interruptedId = Guid.Parse("00000000-0000-0000-0000-000000000002");
            using (var original = new FileSystemDeviceRegistrarPushWorkStore(path, telemetry, fileSystem))
            {
                await original.EnqueueAsync(interruptedId, Application("interrupted"), 1).ConfigureAwait(false);
                await original.BeginAttemptAsync(interruptedId).ConfigureAwait(false);
                await original.EnqueueAsync(pendingId, Application("pending"), 1).ConfigureAwait(false);
            }

            var entered = Signal();
            var release = Signal();
            var processor = new ScriptedRecoveryProcessor(
                blockedProcessingUri: "urn:pending", processingEntered: entered, processingRelease: release);
            using var store = new FileSystemDeviceRegistrarPushWorkStore(path, telemetry, fileSystem);
            using var scheduler = new DeviceRegistrarPushScheduler(processor, telemetry, 1, store);
            await scheduler.StartAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                await entered.Task.WaitAsync(k_deadline).ConfigureAwait(false);
                ArrayOf<DeviceRegistrarPushWorkItem> items = await store.ReadAsync().ConfigureAwait(false);
                Assert.That(items.ToList().Single(item => item.Id == interruptedId).State,
                    Is.EqualTo(DeviceRegistrarPushWorkState.Interrupted));
                ServiceResultException? full = await Assert.ThrowsAsync<ServiceResultException>(async () =>
                    await scheduler.EnqueueAsync(Application("third")).ConfigureAwait(false));
                Assert.That(full!.StatusCode, Is.EqualTo(StatusCodes.BadTooManyOperations));
                Assert.That(processor.ProcessedApplicationUris, Is.EqualTo(new[] { "urn:pending" }));
            }
            finally
            {
                await scheduler.StopAsync(CancellationToken.None).WaitAsync(k_deadline).ConfigureAwait(false);
                release.TrySetResult(true);
            }
        }

        /// <summary>
        /// A stopped or not-yet-started queue cannot return successful acceptance.
        /// </summary>
        [Test]
        public async Task AcceptanceRequiresRunningWorkerAndRestartIsRejected()
        {
            using var scheduler = new DeviceRegistrarPushScheduler(new Processor(), NUnitTelemetryContext.Create());
            ServiceResultException? before = await Assert.ThrowsAsync<ServiceResultException>(async () =>
                await scheduler.EnqueueAsync(Application()).ConfigureAwait(false));
            Assert.That(before!.StatusCode, Is.EqualTo(StatusCodes.BadServerHalted));

            await scheduler.StartAsync(CancellationToken.None).ConfigureAwait(false);
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await scheduler.StartAsync(CancellationToken.None).ConfigureAwait(false));
            await scheduler.StopAsync(CancellationToken.None).WaitAsync(k_deadline).ConfigureAwait(false);

            ServiceResultException? after = await Assert.ThrowsAsync<ServiceResultException>(async () =>
                await scheduler.EnqueueAsync(Application()).ConfigureAwait(false));
            Assert.That(after!.StatusCode, Is.EqualTo(StatusCodes.BadServerHalted));
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await scheduler.StartAsync(CancellationToken.None).ConfigureAwait(false));
        }

        /// <summary>
        /// Startup cancellation leaves the queue unstarted rather than consuming its one permitted start.
        /// </summary>
        [Test]
        public async Task CanceledStartDoesNotOpenAcceptanceOrConsumeStartup()
        {
            using var scheduler = new DeviceRegistrarPushScheduler(new Processor(), NUnitTelemetryContext.Create());
            using var cancellation = new CancellationTokenSource();
            await cancellation.CancelAsync().ConfigureAwait(false);
            await Assert.ThrowsAsync<OperationCanceledException>(async () =>
                await scheduler.StartAsync(cancellation.Token).ConfigureAwait(false));
            ServiceResultException? halted = await Assert.ThrowsAsync<ServiceResultException>(async () =>
                await scheduler.EnqueueAsync(Application()).ConfigureAwait(false));
            Assert.That(halted!.StatusCode, Is.EqualTo(StatusCodes.BadServerHalted));

            await scheduler.StartAsync(CancellationToken.None).ConfigureAwait(false);
            await scheduler.StopAsync(CancellationToken.None).WaitAsync(k_deadline).ConfigureAwait(false);
        }

        /// <summary>
        /// A full queue rejects immediately while accepted work retains independent nested values.
        /// </summary>
        [Test]
        public async Task QueueBoundsPendingWorkAndProcessesDetachedDescriptionsSerially()
        {
            var entered = Signal();
            var release = Signal();
            var completed = Signal();
            var received = new ConcurrentQueue<ApplicationDescription>();
            int running = 0;
            var processor = new Processor
            {
                Handler = async (application, ct) =>
                {
                    Assert.That(Interlocked.Increment(ref running), Is.EqualTo(1));
                    try
                    {
                        received.Enqueue(application);
                        if (received.Count == 1)
                        {
                            entered.TrySetResult(true);
                            await release.Task.WaitAsync(ct).ConfigureAwait(false);
                        }
                        else
                        {
                            completed.TrySetResult(true);
                        }
                    }
                    finally
                    {
                        Interlocked.Decrement(ref running);
                    }
                }
            };
            using var scheduler = new DeviceRegistrarPushScheduler(processor, NUnitTelemetryContext.Create(), 1);
            await scheduler.StartAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                await scheduler.EnqueueAsync(Application("first")).ConfigureAwait(false);
                await entered.Task.WaitAsync(k_deadline).ConfigureAwait(false);
                ApplicationDescription queued = Application("second");
                string[] urls = ["opc.tcp://second:4840"];
                queued.DiscoveryUrls = urls;
                await scheduler.EnqueueAsync(queued).ConfigureAwait(false);
                queued.ApplicationUri = "urn:changed";
                urls[0] = "opc.tcp://changed:4840";

                ServiceResultException? full = await Assert.ThrowsAsync<ServiceResultException>(async () =>
                    await scheduler.EnqueueAsync(Application("third")).ConfigureAwait(false));
                Assert.That(full!.StatusCode, Is.EqualTo(StatusCodes.BadTooManyOperations));
                Assert.That(received, Has.Count.EqualTo(1));
                release.TrySetResult(true);
                await completed.Task.WaitAsync(k_deadline).ConfigureAwait(false);
                ApplicationDescription[] calls = received.ToArray();
                Assert.That(calls.Select(call => call.ApplicationUri), Is.EqualTo(s_expectedAcceptedApplicationUris));
                Assert.That(calls[1].DiscoveryUrls[0], Is.EqualTo("opc.tcp://second:4840"));
                Assert.That(calls[1], Is.Not.SameAs(queued));
            }
            finally
            {
                release.TrySetResult(true);
                await scheduler.StopAsync(CancellationToken.None).WaitAsync(k_deadline).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// A failed provider invocation is logged once; processing continues without retrying its remote effects.
        /// </summary>
        [TestCase("service")]
        [TestCase("cancellation")]
        public async Task ProcessorFailureIsObservedWithoutRetryAndNextRegistrationRuns(string scenario)
        {
            using var logs = new WorkerLogs();
            var telemetry = new Mock<ITelemetryContext>(MockBehavior.Strict);
            telemetry.SetupGet(value => value.LoggerFactory).Returns(logs);
            var completed = Signal();
            var calls = new ConcurrentQueue<string?>();
            Exception failure = scenario == "cancellation"
                ? new OperationCanceledException()
                : new ServiceResultException(StatusCodes.BadSecurityChecksFailed);
            var processor = new Processor
            {
                Handler = (application, _) =>
                {
                    calls.Enqueue(application.ApplicationUri);
                    if (application.ApplicationUri == "urn:rejected")
                    {
                        throw failure;
                    }
                    completed.TrySetResult(true);
                    return default;
                }
            };
            using var scheduler = new DeviceRegistrarPushScheduler(processor, telemetry.Object);
            await scheduler.StartAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                await scheduler.EnqueueAsync(Application("rejected")).ConfigureAwait(false);
                await scheduler.EnqueueAsync(Application("accepted")).ConfigureAwait(false);
                await completed.Task.WaitAsync(k_deadline).ConfigureAwait(false);
            }
            finally
            {
                await scheduler.StopAsync(CancellationToken.None).WaitAsync(k_deadline).ConfigureAwait(false);
            }
            Assert.That(calls.ToArray(), Is.EqualTo(s_expectedProcessedApplicationUris));
            var failures = logs.Events.Where(entry => entry.Event.Id == 101).ToArray();
            Assert.That(failures, Has.Length.EqualTo(1));
            Assert.That(failures[0].Level, Is.EqualTo(LogLevel.Error));
            Assert.That(failures[0].Error, Is.SameAs(failure));
        }

        /// <summary>
        /// Shutdown cancels the running processor, never dispatches queued work, and reports discarded acceptance.
        /// </summary>
        [Test]
        public async Task ShutdownCancelsRunningWorkAndReportsUnprocessedRegistrations()
        {
            using var logs = new WorkerLogs();
            var telemetry = new Mock<ITelemetryContext>(MockBehavior.Strict);
            telemetry.SetupGet(value => value.LoggerFactory).Returns(logs);
            var entered = Signal();
            int calls = 0;
            CancellationToken processingToken = default;
            var processor = new Processor
            {
                Handler = async (_, ct) =>
                {
                    Interlocked.Increment(ref calls);
                    processingToken = ct;
                    entered.TrySetResult(true);
                    await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
                }
            };
            using var scheduler = new DeviceRegistrarPushScheduler(processor, telemetry.Object);
            await scheduler.StartAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                await scheduler.EnqueueAsync(Application("running")).ConfigureAwait(false);
                await entered.Task.WaitAsync(k_deadline).ConfigureAwait(false);
                await scheduler.EnqueueAsync(Application("queued")).ConfigureAwait(false);
            }
            finally
            {
                await scheduler.StopAsync(CancellationToken.None).WaitAsync(k_deadline).ConfigureAwait(false);
            }
            Assert.That(processingToken.IsCancellationRequested, Is.True);
            Assert.That(calls, Is.EqualTo(1));
            Assert.That(logs.Events.Count(entry => entry.Event.Id == 102), Is.EqualTo(1));
            Assert.That(logs.Events.Count(entry => entry.Event.Id == 103), Is.EqualTo(1));
            Assert.That(logs.Events.Single(entry => entry.Event.Id == 103).Message,
                Does.Contain("1 queued registrations"));
        }

        /// <summary>
        /// Cancellation rejects unaccepted work but does not revoke a registration that was already queued.
        /// </summary>
        [Test]
        public async Task CallerCancellationOnlyGovernsQueueAcceptance()
        {
            var entered = Signal();
            var release = Signal();
            var completed = Signal();
            int calls = 0;
            var processor = new Processor
            {
                Handler = async (_, ct) =>
                {
                    if (Interlocked.Increment(ref calls) == 1)
                    {
                        entered.TrySetResult(true);
                        await release.Task.WaitAsync(ct).ConfigureAwait(false);
                    }
                    else
                    {
                        Assert.That(ct.IsCancellationRequested, Is.False);
                        completed.TrySetResult(true);
                    }
                }
            };
            using var scheduler = new DeviceRegistrarPushScheduler(processor, NUnitTelemetryContext.Create());
            using var cancellation = new CancellationTokenSource();
            await scheduler.StartAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                await scheduler.EnqueueAsync(Application("running")).ConfigureAwait(false);
                await entered.Task.WaitAsync(k_deadline).ConfigureAwait(false);
                await scheduler.EnqueueAsync(Application("queued"), cancellation.Token).ConfigureAwait(false);
                await cancellation.CancelAsync().ConfigureAwait(false);
                await Assert.ThrowsAsync<OperationCanceledException>(async () =>
                    await scheduler.EnqueueAsync(Application("canceled"), cancellation.Token).ConfigureAwait(false));
                release.TrySetResult(true);
                await completed.Task.WaitAsync(k_deadline).ConfigureAwait(false);
            }
            finally
            {
                release.TrySetResult(true);
                await scheduler.StopAsync(CancellationToken.None).WaitAsync(k_deadline).ConfigureAwait(false);
            }
            Assert.That(calls, Is.EqualTo(2));
        }

        /// <summary>
        /// Invalid discovery descriptions never reach the processor.
        /// </summary>
        [TestCase("missing-uri")]
        [TestCase("missing-endpoints")]
        [TestCase("relative-endpoint")]
        [TestCase("client")]
        public async Task InvalidRegistrationIsRejectedBeforeDispatch(string scenario)
        {
            int calls = 0;
            var processor = new Processor
            {
                Handler = (_, _) =>
                {
                    calls++;
                    return default;
                }
            };
            using var scheduler = new DeviceRegistrarPushScheduler(processor, NUnitTelemetryContext.Create());
            ApplicationDescription application = Application();
            switch (scenario)
            {
                case "missing-uri":
                    application.ApplicationUri = string.Empty;
                    break;
                case "missing-endpoints":
                    application.DiscoveryUrls = [];
                    break;
                case "relative-endpoint":
                    application.DiscoveryUrls = ["relative"];
                    break;
                case "client":
                    application.ApplicationType = ApplicationType.Client;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(scenario));
            }
            await scheduler.StartAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                ServiceResultException? error = await Assert.ThrowsAsync<ServiceResultException>(async () =>
                    await scheduler.EnqueueAsync(application).ConfigureAwait(false));
                Assert.That(error!.StatusCode, Is.EqualTo(StatusCodes.BadInvalidArgument));
            }
            finally
            {
                await scheduler.StopAsync(CancellationToken.None).WaitAsync(k_deadline).ConfigureAwait(false);
            }
            Assert.That(calls, Is.Zero);
        }

        /// <summary>
        /// DI uses the same queue for runtime acceptance and hosted lifecycle without starting during resolution.
        /// </summary>
        [Test]
        public void FluentRegistrationSharesHostedWorkerAndRejectsConflictingSchedulers()
        {
            var services = new ServiceCollection();
            services.AddSingleton<ITelemetryContext>(NUnitTelemetryContext.Create());
            Assert.That(services.AddDeviceRegistrarPushScheduler<Processor>(1), Is.SameAs(services));
            using ServiceProvider provider = services.BuildServiceProvider();
            var scheduler = provider.GetRequiredService<DeviceRegistrarPushScheduler>();
            Assert.That(provider.GetRequiredService<IDeviceRegistrarPushScheduler>(), Is.SameAs(scheduler));
            Assert.That(provider.GetServices<IHostedService>().Single(), Is.SameAs(scheduler));
            Assert.That(provider.GetRequiredService<IDeviceRegistrarPushProcessor>(), Is.TypeOf<Processor>());
            Assert.That(() => services.AddDeviceRegistrarPushScheduler<Processor>(),
                Throws.InvalidOperationException);
        }

        /// <summary>
        /// Invalid DI inputs do not add partially configured services.
        /// </summary>
        [Test]
        public void FluentRegistrationRejectsMissingServicesAndInvalidCapacity()
        {
            Assert.That(() => OpcUaDeviceRegistrarBuilderExtensions
                .AddDeviceRegistrarPushScheduler<Processor>(null!), Throws.ArgumentNullException);
            var services = new ServiceCollection();
            Assert.That(() => services.AddDeviceRegistrarPushScheduler<Processor>(0),
                Throws.TypeOf<ArgumentOutOfRangeException>());
            Assert.That(() => services.AddDeviceRegistrarPushScheduler<Processor>(1025),
                Throws.TypeOf<ArgumentOutOfRangeException>());
            Assert.That(services, Is.Empty);
        }

        /// <summary>
        /// Provider conflicts reject registration before any descriptor is added or an existing provider is replaced.
        /// </summary>
        [TestCase("scheduler")]
        [TestCase("processor")]
        [TestCase("worker")]
        public void FluentRegistrationPreservesExistingProvidersOnConflict(string scenario)
        {
            var services = new ServiceCollection();
            using var worker = new DeviceRegistrarPushScheduler(new Processor(), NUnitTelemetryContext.Create());
            switch (scenario)
            {
                case "scheduler":
                    services.AddSingleton(new Mock<IDeviceRegistrarPushScheduler>().Object);
                    break;
                case "processor":
                    services.AddSingleton<IDeviceRegistrarPushProcessor>(new Processor());
                    break;
                case "worker":
                    services.AddSingleton(worker);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(scenario));
            }
            ServiceDescriptor original = services.Single();
            Assert.That(() => services.AddDeviceRegistrarPushScheduler<Processor>(), Throws.InvalidOperationException);
            Assert.That(services, Has.Count.EqualTo(1));
            Assert.That(services.Single(), Is.SameAs(original));
        }

        /// <summary>
        /// Durable acceptance survives shutdown and fresh store/scheduler instances reconcile only interrupted work.
        /// </summary>
        [Test]
        public async Task DurableStoreRestartsAndRecoversInterruptedAndPendingWork()
        {
            string checkpointDirectory = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "Opc.Ua.Gds.Tests",
                Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(checkpointDirectory);
            string checkpointPath = System.IO.Path.Combine(checkpointDirectory, "push-work.bin");

            var firstEntered = Signal();
            var firstRelease = Signal();
            var reconciliationEntered = Signal();
            var reconciliationRelease = Signal();
            using var logs = new WorkerLogs();
            var telemetry = new Mock<ITelemetryContext>(MockBehavior.Strict);
            telemetry.SetupGet(value => value.LoggerFactory).Returns(logs);

            FileSystemDeviceRegistrarPushWorkStore? store1 = null;
            FileSystemDeviceRegistrarPushWorkStore? store2 = null;
            FileSystemDeviceRegistrarPushWorkStore? store3 = null;
            DeviceRegistrarPushScheduler? scheduler1 = null;
            DeviceRegistrarPushScheduler? scheduler2 = null;
            var processor1 = new ScriptedRecoveryProcessor(
                blockedProcessingUri: "urn:first",
                processingEntered: firstEntered,
                processingRelease: firstRelease);
            var processor2 = new ScriptedRecoveryProcessor(
                blockedReconciliationUri: "urn:first",
                reconciliationEntered: reconciliationEntered,
                reconciliationRelease: reconciliationRelease);
            bool scheduler1Started = false;
            bool scheduler1Stopped = false;
            bool scheduler2Started = false;
            bool scheduler2Stopped = false;

            try
            {
                store1 = new FileSystemDeviceRegistrarPushWorkStore(checkpointPath, telemetry.Object);
                scheduler1 = new DeviceRegistrarPushScheduler(
                    processor1, telemetry.Object, capacity: 1, workStore: store1);
                await scheduler1.StartAsync(CancellationToken.None).ConfigureAwait(false);
                scheduler1Started = true;

                await scheduler1.EnqueueAsync(Application("first")).ConfigureAwait(false);
                await firstEntered.Task.WaitAsync(k_deadline).ConfigureAwait(false);
                await scheduler1.EnqueueAsync(Application("second")).ConfigureAwait(false);
                ServiceResultException? full = await Assert.ThrowsAsync<ServiceResultException>(async () =>
                    await scheduler1.EnqueueAsync(Application("third")).ConfigureAwait(false));
                Assert.That(full!.StatusCode, Is.EqualTo(StatusCodes.BadTooManyOperations));

                DeviceRegistrarPushWorkItem[] accepted = (await store1.ReadAsync()
                    .ConfigureAwait(false)).Span.ToArray();
                Assert.That(accepted, Has.Length.EqualTo(2));
                DeviceRegistrarPushWorkItem firstAccepted =
                    accepted.Single(item => item.Application.ApplicationUri == "urn:first");
                DeviceRegistrarPushWorkItem secondAccepted =
                    accepted.Single(item => item.Application.ApplicationUri == "urn:second");
                Assert.Multiple(() =>
                {
                    Assert.That(firstAccepted.Id, Is.Not.EqualTo(Guid.Empty));
                    Assert.That(secondAccepted.Id, Is.Not.EqualTo(Guid.Empty));
                    Assert.That(firstAccepted.Id, Is.Not.EqualTo(secondAccepted.Id));
                    Assert.That(firstAccepted.State, Is.EqualTo(DeviceRegistrarPushWorkState.Processing));
                    Assert.That(secondAccepted.State, Is.EqualTo(DeviceRegistrarPushWorkState.Pending));
                    AssertApplicationDescription(firstAccepted.Application, "urn:first", "opc.tcp://first:4840");
                    AssertApplicationDescription(secondAccepted.Application, "urn:second", "opc.tcp://second:4840");
                });

                Guid firstId = firstAccepted.Id;
                Guid secondId = secondAccepted.Id;
                await scheduler1.StopAsync(CancellationToken.None).WaitAsync(k_deadline).ConfigureAwait(false);
                scheduler1Stopped = true;

                DeviceRegistrarPushWorkItem[] interrupted = (await store1.ReadAsync()
                    .ConfigureAwait(false)).Span.ToArray();
                DeviceRegistrarPushWorkItem firstInterrupted =
                    interrupted.Single(item => item.Application.ApplicationUri == "urn:first");
                DeviceRegistrarPushWorkItem secondPending =
                    interrupted.Single(item => item.Application.ApplicationUri == "urn:second");
                Assert.Multiple(() =>
                {
                    Assert.That(processor1.ProcessingCancellationObserved, Is.True);
                    Assert.That(processor1.ProcessedApplicationUris, Is.EqualTo(new[] { "urn:first" }));
                    Assert.That(interrupted, Has.Length.EqualTo(2));
                    Assert.That(firstInterrupted.Id, Is.EqualTo(firstId));
                    Assert.That(secondPending.Id, Is.EqualTo(secondId));
                    Assert.That(firstInterrupted.State, Is.EqualTo(DeviceRegistrarPushWorkState.Interrupted));
                    Assert.That(secondPending.State, Is.EqualTo(DeviceRegistrarPushWorkState.Pending));
                    AssertApplicationDescription(firstInterrupted.Application, "urn:first", "opc.tcp://first:4840");
                    AssertApplicationDescription(secondPending.Application, "urn:second", "opc.tcp://second:4840");
                });

                scheduler1.Dispose();
                scheduler1 = null;
                store1.Dispose();
                store1 = null;

                store2 = new FileSystemDeviceRegistrarPushWorkStore(checkpointPath, telemetry.Object);
                DeviceRegistrarPushWorkItem[] restoredBeforeStart = (await store2.ReadAsync()
                    .ConfigureAwait(false)).Span.ToArray();
                DeviceRegistrarPushWorkItem restoredFirst =
                    restoredBeforeStart.Single(item => item.Application.ApplicationUri == "urn:first");
                DeviceRegistrarPushWorkItem restoredSecond =
                    restoredBeforeStart.Single(item => item.Application.ApplicationUri == "urn:second");
                Assert.Multiple(() =>
                {
                    Assert.That(restoredBeforeStart, Has.Length.EqualTo(2));
                    Assert.That(restoredFirst.Id, Is.EqualTo(firstId));
                    Assert.That(restoredSecond.Id, Is.EqualTo(secondId));
                    Assert.That(restoredFirst.State, Is.EqualTo(DeviceRegistrarPushWorkState.Interrupted));
                    Assert.That(restoredSecond.State, Is.EqualTo(DeviceRegistrarPushWorkState.Pending));
                    AssertApplicationDescription(restoredFirst.Application, "urn:first", "opc.tcp://first:4840");
                    AssertApplicationDescription(restoredSecond.Application, "urn:second", "opc.tcp://second:4840");
                });

                scheduler2 = new DeviceRegistrarPushScheduler(
                    processor2, telemetry.Object, capacity: 1, workStore: store2);
                await scheduler2.StartAsync(CancellationToken.None).ConfigureAwait(false);
                scheduler2Started = true;
                await reconciliationEntered.Task.WaitAsync(k_deadline).ConfigureAwait(false);

                Assert.Multiple(() =>
                {
                    Assert.That(processor2.ProcessedApplicationUris, Does.Not.Contain("urn:first"));
                    Assert.That(processor2.ReconciledApplicationUris, Is.EqualTo(new[] { "urn:first" }));
                    Assert.That(processor2.EventsFor("urn:first"),
                        Is.EqualTo(new[] { ("reconcile-enter", "urn:first") }));
                });

                reconciliationRelease.TrySetResult(true);
                await logs.WaitForCompletionCountAsync(2).ConfigureAwait(false);
                Assert.Multiple(() =>
                {
                    Assert.That(processor2.ProcessedApplicationUris.Count(uri => uri == "urn:first"), Is.EqualTo(1));
                    Assert.That(processor2.ProcessedApplicationUris.Count(uri => uri == "urn:second"), Is.EqualTo(1));
                    Assert.That(processor2.ReconciledApplicationUris, Is.EqualTo(new[] { "urn:first" }));
                    Assert.That(processor2.EventsFor("urn:first"),
                        Is.EqualTo(new[] {
                            ("reconcile-enter", "urn:first"),
                            ("reconcile-complete", "urn:first"),
                            ("process", "urn:first")
                        }));
                    Assert.That(processor2.EventsFor("urn:second"),
                        Is.EqualTo(new[] { ("process", "urn:second") }));
                    Assert.That(logs.Events.Count(entry => entry.Event.Id == 100), Is.EqualTo(2));
                });

                await scheduler2.StopAsync(CancellationToken.None).WaitAsync(k_deadline).ConfigureAwait(false);
                scheduler2Stopped = true;
                scheduler2.Dispose();
                scheduler2 = null;
                store2.Dispose();
                store2 = null;

                store3 = new FileSystemDeviceRegistrarPushWorkStore(checkpointPath, telemetry.Object);
                Assert.That((await store3.ReadAsync().ConfigureAwait(false)).Count, Is.Zero);
            }
            finally
            {
                firstRelease.TrySetResult(true);
                reconciliationRelease.TrySetResult(true);

                if (scheduler1 is not null)
                {
                    try
                    {
                        if (scheduler1Started && !scheduler1Stopped)
                        {
                            await scheduler1.StopAsync(CancellationToken.None)
                                .WaitAsync(k_deadline).ConfigureAwait(false);
                        }
                    }
                    catch (Exception)
                    {
                        // Preserve the original test failure while still releasing owned resources.
                    }
                    scheduler1.Dispose();
                }
                if (scheduler2 is not null)
                {
                    try
                    {
                        if (scheduler2Started && !scheduler2Stopped)
                        {
                            await scheduler2.StopAsync(CancellationToken.None)
                                .WaitAsync(k_deadline).ConfigureAwait(false);
                        }
                    }
                    catch (Exception)
                    {
                        // Preserve the original test failure while still releasing owned resources.
                    }
                    scheduler2.Dispose();
                }
                store1?.Dispose();
                store2?.Dispose();
                store3?.Dispose();
                if (System.IO.Directory.Exists(checkpointDirectory))
                {
                    System.IO.Directory.Delete(checkpointDirectory, recursive: true);
                }
            }
        }

        /// <summary>
        /// Queue acceptance detaches caller-owned LocalizedText arrays and deferred formatting arguments.
        /// </summary>
        [Test]
        public async Task EnqueueAsyncDetachesLocalizedNamesFromCallerMutation()
        {
            var firstEntered = Signal();
            var releaseFirst = Signal();
            var targetProcessed = Signal();
            var received = new ConcurrentQueue<ApplicationDescription>();
            int processCount = 0;
            var processor = new Processor
            {
                Handler = async (application, cancellationToken) =>
                {
                    received.Enqueue(application);
                    if (Interlocked.Increment(ref processCount) == 1)
                    {
                        firstEntered.TrySetResult(true);
                        await releaseFirst.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        targetProcessed.TrySetResult(true);
                    }
                }
            };
            using var scheduler = new DeviceRegistrarPushScheduler(processor, NUnitTelemetryContext.Create());
            await scheduler.StartAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                await scheduler.EnqueueAsync(Application("blocker")).ConfigureAwait(false);
                await firstEntered.Task.WaitAsync(k_deadline).ConfigureAwait(false);

                object[] formattingArguments = ["Original"];
                var originalName = new LocalizedText(
                    new TranslationInfo("device-name", "en-US", "Device {0}", formattingArguments));
                LocalizedText[] originalNames = [originalName];
                ApplicationDescription queued = Application("localized");
                queued.ApplicationNames = originalNames.ToArrayOf();

                await scheduler.EnqueueAsync(queued).ConfigureAwait(false);
                formattingArguments[0] = "Changed";
                originalNames[0] = new LocalizedText("fr-FR", "Caller replacement");
                Assert.Multiple(() =>
                {
                    Assert.That(queued.ApplicationNames[0].Text, Is.EqualTo("Caller replacement"));
                    Assert.That(originalName.Text, Is.EqualTo("Device Changed"));
                });

                releaseFirst.TrySetResult(true);
                await targetProcessed.Task.WaitAsync(k_deadline).ConfigureAwait(false);
                ApplicationDescription processed = received.Single(
                    application => application.ApplicationUri == "urn:localized");
                LocalizedText processedName = processed.ApplicationNames[0];
                Assert.Multiple(() =>
                {
                    Assert.That(received, Has.Count.EqualTo(2));
                    Assert.That(processed.ApplicationUri, Is.EqualTo("urn:localized"));
                    Assert.That(processed.ApplicationNames.Count, Is.EqualTo(1));
                    Assert.That(processedName.Locale, Is.EqualTo("en-US"));
                    Assert.That(processedName.Text, Is.EqualTo("Device Original"));
                    Assert.That(processedName.TranslationInfo.Args, Is.EqualTo(new object[] { "Original" }));
                });
            }
            finally
            {
                releaseFirst.TrySetResult(true);
                await scheduler.StopAsync(CancellationToken.None).WaitAsync(k_deadline).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Queued descriptions retain the post-setter application-name value.
        /// </summary>
        [TestCase("null-array")]
        [TestCase("empty-array")]
        [TestCase("null-element")]
        public async Task EnqueueAsyncPreservesApplicationNamesAfterSetterNormalization(string scenario)
        {
            var entered = Signal();
            var release = Signal();
            var received = new TaskCompletionSource<ApplicationDescription>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var processor = new Processor
            {
                Handler = async (application, cancellationToken) =>
                {
                    if (application.ApplicationUri == "urn:blocker")
                    {
                        entered.TrySetResult(true);
                        await release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        received.TrySetResult(application);
                    }
                }
            };
            using var scheduler = new DeviceRegistrarPushScheduler(processor, NUnitTelemetryContext.Create(), 1);
            await scheduler.StartAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                await scheduler.EnqueueAsync(Application("blocker")).ConfigureAwait(false);
                await entered.Task.WaitAsync(k_deadline).ConfigureAwait(false);
                ApplicationDescription queued = Application("names");
                queued.ApplicationNames = NamesForSnapshotScenario(scenario);
                ArrayOf<LocalizedText> expectedNames = queued.ApplicationNames;
                AssertApplicationNamesState(queued.ApplicationNames, expectedNames);
                await scheduler.EnqueueAsync(queued).ConfigureAwait(false);

                // The caller can replace the field after acceptance without changing the queued snapshot.
                queued.ApplicationNames = [new LocalizedText("en-US", "Caller replacement")];
                release.TrySetResult(true);
                ApplicationDescription processed = await received.Task
                    .WaitAsync(k_deadline).ConfigureAwait(false);
                Assert.That(processed.ApplicationUri, Is.EqualTo("urn:names"));
                AssertApplicationNamesState(processed.ApplicationNames, expectedNames);
                Assert.That(queued.ApplicationNames[0].Text, Is.EqualTo("Caller replacement"));
            }
            finally
            {
                release.TrySetResult(true);
                await scheduler.StopAsync(CancellationToken.None).WaitAsync(k_deadline).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// The real store snapshots the post-setter application-name value.
        /// </summary>
        [TestCase("null-array")]
        [TestCase("empty-array")]
        [TestCase("null-element")]
        public async Task DurableStorePreservesApplicationNamesAfterSetterNormalization(string scenario)
        {
            string directory = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), "Opc.Ua.Gds.Tests", Guid.NewGuid().ToString("N"));
            string path = System.IO.Path.Combine(directory, "push-work.bin");
            var telemetry = NUnitTelemetryContext.Create();
            Guid id = Guid.NewGuid();
            try
            {
                System.IO.Directory.CreateDirectory(directory);
                using (var store = new FileSystemDeviceRegistrarPushWorkStore(path, telemetry))
                {
                    ApplicationDescription application = Application("names");
                    application.ApplicationNames = NamesForSnapshotScenario(scenario);
                    ArrayOf<LocalizedText> expectedNames = application.ApplicationNames;
                    AssertApplicationNamesState(application.ApplicationNames, expectedNames);
                    await store.EnqueueAsync(id, application, 1).ConfigureAwait(false);
                    application.ApplicationNames = [new LocalizedText("en-US", "Caller replacement")];

                    ArrayOf<DeviceRegistrarPushWorkItem> items = await store.ReadAsync().ConfigureAwait(false);
                    Assert.That(items.Count, Is.EqualTo(1));
                    Assert.That(items[0].Id, Is.EqualTo(id));
                    Assert.That(items[0].State, Is.EqualTo(DeviceRegistrarPushWorkState.Pending));
                    Assert.That(items[0].Application.ApplicationUri, Is.EqualTo("urn:names"));
                    AssertApplicationNamesState(items[0].Application.ApplicationNames, expectedNames);

                    // Also detach returned descriptions from the durable record.
                    items[0].Application.ApplicationNames = [new LocalizedText("Returned replacement")];
                }

                using (var reopened = new FileSystemDeviceRegistrarPushWorkStore(path, telemetry))
                {
                    ArrayOf<DeviceRegistrarPushWorkItem> items = await reopened.ReadAsync().ConfigureAwait(false);
                    Assert.That(items.Count, Is.EqualTo(1));
                    Assert.That(items[0].Id, Is.EqualTo(id));
                    Assert.That(items[0].Application.ApplicationUri, Is.EqualTo("urn:names"));
                    AssertApplicationNamesState(items[0].Application.ApplicationNames, expectedNames);
                    await reopened.CompleteAsync(id).ConfigureAwait(false);
                    Assert.That((await reopened.ReadAsync().ConfigureAwait(false)).Count, Is.Zero);
                }
            }
            finally
            {
                if (System.IO.Directory.Exists(directory))
                {
                    System.IO.Directory.Delete(directory, recursive: true);
                }
            }
        }

        /// <summary>
        /// Queue snapshots do not invoke a provider-owned description's virtual clone or retain its fields.
        /// </summary>
        [Test]
        public async Task EnqueueAsyncDetachesSelfCloningApplicationDescription()
        {
            var firstEntered = Signal();
            var releaseFirst = Signal();
            var targetProcessed = Signal();
            var received = new ConcurrentQueue<ApplicationDescription>();
            int processCount = 0;
            var processor = new Processor
            {
                Handler = async (application, cancellationToken) =>
                {
                    received.Enqueue(application);
                    if (Interlocked.Increment(ref processCount) == 1)
                    {
                        firstEntered.TrySetResult(true);
                        await releaseFirst.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        targetProcessed.TrySetResult(true);
                    }
                }
            };
            using var scheduler = new DeviceRegistrarPushScheduler(processor, NUnitTelemetryContext.Create());
            await scheduler.StartAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                await scheduler.EnqueueAsync(Application("blocker")).ConfigureAwait(false);
                await firstEntered.Task.WaitAsync(k_deadline).ConfigureAwait(false);

                string[] discoveryUrls = ["opc.tcp://original:4840"];
                LocalizedText[] applicationNames = [new LocalizedText("en-US", "Original name")];
                var original = new SelfCloningApplicationDescription
                {
                    ApplicationName = new LocalizedText("en-US", "Original application"),
                    ApplicationUri = "urn:original",
                    ApplicationType = ApplicationType.Server,
                    ProductUri = "urn:product:original",
                    GatewayServerUri = "urn:gateway:original",
                    DiscoveryProfileUri = "urn:profile:original",
                    DiscoveryUrls = discoveryUrls.ToArrayOf(),
                    ApplicationNames = applicationNames.ToArrayOf()
                };

                await scheduler.EnqueueAsync(original).ConfigureAwait(false);
                Assert.Multiple(() =>
                {
                    Assert.That(original.GetType(), Is.EqualTo(typeof(SelfCloningApplicationDescription)));
                    Assert.That(original.ApplicationUri, Is.EqualTo("urn:original"));
                    Assert.That(original.ProductUri, Is.EqualTo("urn:product:original"));
                    Assert.That(discoveryUrls, Is.EqualTo(new[] { "opc.tcp://original:4840" }));
                    Assert.That(applicationNames[0].Text, Is.EqualTo("Original name"));
                });

                original.ApplicationName = new LocalizedText("fr-FR", "Changed");
                original.ApplicationUri = "urn:changed";
                original.ApplicationType = ApplicationType.Client;
                original.ProductUri = "urn:product:changed";
                original.GatewayServerUri = "urn:gateway:changed";
                original.DiscoveryProfileUri = "urn:profile:changed";
                discoveryUrls[0] = "opc.tcp://changed:4840";
                applicationNames[0] = new LocalizedText("fr-FR", "Changed name");

                releaseFirst.TrySetResult(true);
                await targetProcessed.Task.WaitAsync(k_deadline).ConfigureAwait(false);
                ApplicationDescription processed = received.Single(
                    application => application.ApplicationUri == "urn:original");
                Assert.Multiple(() =>
                {
                    Assert.That(processed.GetType(), Is.EqualTo(typeof(ApplicationDescription)));
                    Assert.That(processed.ApplicationName.Locale, Is.EqualTo("en-US"));
                    Assert.That(processed.ApplicationName.Text, Is.EqualTo("Original application"));
                    Assert.That(processed.ApplicationUri, Is.EqualTo("urn:original"));
                    Assert.That(processed.ApplicationType, Is.EqualTo(ApplicationType.Server));
                    Assert.That(processed.ProductUri, Is.EqualTo("urn:product:original"));
                    Assert.That(processed.GatewayServerUri, Is.EqualTo("urn:gateway:original"));
                    Assert.That(processed.DiscoveryProfileUri, Is.EqualTo("urn:profile:original"));
                    Assert.That(
                        processed.DiscoveryUrls.Span.ToArray(),
                        Is.EqualTo(new[] { "opc.tcp://original:4840" }));
                    Assert.That(processed.ApplicationNames[0].Text, Is.EqualTo("Original name"));
                });
            }
            finally
            {
                releaseFirst.TrySetResult(true);
                await scheduler.StopAsync(CancellationToken.None).WaitAsync(k_deadline).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Durable acceptance snapshots provider-owned descriptions before persisting their fields and arrays.
        /// </summary>
        [Test]
        public async Task DurableStoreDetachesSelfCloningApplicationDescription()
        {
            string directory = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), "Opc.Ua.Gds.Tests", Guid.NewGuid().ToString("N"));
            string path = System.IO.Path.Combine(directory, "push-work.bin");
            Guid id = Guid.NewGuid();
            try
            {
                System.IO.Directory.CreateDirectory(directory);
                using var store = new FileSystemDeviceRegistrarPushWorkStore(path, NUnitTelemetryContext.Create());
                string[] discoveryUrls = ["opc.tcp://original:4840"];
                LocalizedText[] applicationNames = [new LocalizedText("en-US", "Original name")];
                var original = new SelfCloningApplicationDescription
                {
                    ApplicationName = new LocalizedText("en-US", "Original application"),
                    ApplicationUri = "urn:original",
                    ApplicationType = ApplicationType.Server,
                    ProductUri = "urn:product:original",
                    GatewayServerUri = "urn:gateway:original",
                    DiscoveryProfileUri = "urn:profile:original",
                    DiscoveryUrls = discoveryUrls.ToArrayOf(),
                    ApplicationNames = applicationNames.ToArrayOf()
                };

                await store.EnqueueAsync(id, original, 1).ConfigureAwait(false);
                Assert.That(original.ApplicationUri, Is.EqualTo("urn:original"));
                original.ApplicationUri = "urn:changed";
                discoveryUrls[0] = "opc.tcp://changed:4840";
                applicationNames[0] = new LocalizedText("fr-FR", "Changed name");

                ArrayOf<DeviceRegistrarPushWorkItem> items = await store.ReadAsync().ConfigureAwait(false);
                Assert.That(items.Count, Is.EqualTo(1));
                ApplicationDescription persisted = items[0].Application;
                Assert.Multiple(() =>
                {
                    Assert.That(persisted.GetType(), Is.EqualTo(typeof(ApplicationDescription)));
                    Assert.That(persisted.ApplicationUri, Is.EqualTo("urn:original"));
                    Assert.That(persisted.ApplicationType, Is.EqualTo(ApplicationType.Server));
                    Assert.That(persisted.ApplicationName.Text, Is.EqualTo("Original application"));
                    Assert.That(persisted.ProductUri, Is.EqualTo("urn:product:original"));
                    Assert.That(persisted.GatewayServerUri, Is.EqualTo("urn:gateway:original"));
                    Assert.That(persisted.DiscoveryProfileUri, Is.EqualTo("urn:profile:original"));
                    Assert.That(
                        persisted.DiscoveryUrls.Span.ToArray(),
                        Is.EqualTo(new[] { "opc.tcp://original:4840" }));
                    Assert.That(persisted.ApplicationNames[0].Text, Is.EqualTo("Original name"));
                });
            }
            finally
            {
                if (System.IO.Directory.Exists(directory))
                {
                    System.IO.Directory.Delete(directory, recursive: true);
                }
            }
        }

        private static ArrayOf<LocalizedText> NamesForSnapshotScenario(string scenario)
        {
            return scenario switch
            {
                "null-array" => ArrayOf.Null<LocalizedText>(),
                "empty-array" => ArrayOf.Empty<LocalizedText>(),
                "null-element" => new LocalizedText[] { default }.ToArrayOf(),
                _ => throw new ArgumentOutOfRangeException(nameof(scenario))
            };
        }

        private static void AssertApplicationNamesState(
            ArrayOf<LocalizedText> names,
            ArrayOf<LocalizedText> expectedNames)
        {
            Assert.That(names.IsNull, Is.EqualTo(expectedNames.IsNull));
            Assert.That(names.Count, Is.EqualTo(expectedNames.Count));
            if (expectedNames.Count > 0)
            {
                Assert.Multiple(() =>
                {
                    Assert.That(names[0], Is.EqualTo(expectedNames[0]));
                    Assert.That(names[0].IsNull, Is.EqualTo(expectedNames[0].IsNull));
                    Assert.That(names[0].Text, Is.EqualTo(expectedNames[0].Text));
                    Assert.That(names[0].Locale, Is.EqualTo(expectedNames[0].Locale));
                });
            }
        }

        /// <summary>
        /// Creates a syntactically valid description without relying on DNS or a live server.
        /// </summary>
        private static ApplicationDescription Application(string name = "device")
        {
            return new ApplicationDescription
            {
                ApplicationUri = "urn:" + name,
                ApplicationType = ApplicationType.Server,
                DiscoveryUrls = ["opc.tcp://" + name + ":4840"]
            };
        }

        /// <summary>
        /// Creates a deterministic handshake without running continuations inside queue operations.
        /// </summary>
        private static TaskCompletionSource<bool> Signal()
        {
            return new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        /// <summary>
        /// Pins the immutable description fields retained across a durable restart.
        /// </summary>
        private static void AssertApplicationDescription(
            ApplicationDescription application,
            string expectedUri,
            string expectedDiscoveryUrl)
        {
            Assert.That(application.ApplicationUri, Is.EqualTo(expectedUri));
            Assert.That(application.ApplicationType, Is.EqualTo(ApplicationType.Server));
            Assert.That(application.DiscoveryUrls.Span.ToArray(), Is.EqualTo(new[] { expectedDiscoveryUrl }));
        }

        /// <summary>
        /// Runs scripted processing and recovery while exposing deterministic ordering evidence.
        /// </summary>
        private sealed class ScriptedRecoveryProcessor :
            IDeviceRegistrarPushProcessor,
            IDeviceRegistrarPushRecoveryProcessor
        {
            private readonly string? m_blockedProcessingUri;
            private readonly TaskCompletionSource<bool>? m_processingEntered;
            private readonly TaskCompletionSource<bool>? m_processingRelease;
            private readonly string? m_blockedReconciliationUri;
            private readonly TaskCompletionSource<bool>? m_reconciliationEntered;
            private readonly TaskCompletionSource<bool>? m_reconciliationRelease;
            private readonly ConcurrentQueue<string> m_processedApplicationUris = new();
            private readonly ConcurrentQueue<string> m_reconciledApplicationUris = new();
            private readonly ConcurrentQueue<(string Event, string ApplicationUri)> m_events = new();
            private int m_processingCancellationObserved;

            public ScriptedRecoveryProcessor(
                string? blockedProcessingUri = null,
                TaskCompletionSource<bool>? processingEntered = null,
                TaskCompletionSource<bool>? processingRelease = null,
                string? blockedReconciliationUri = null,
                TaskCompletionSource<bool>? reconciliationEntered = null,
                TaskCompletionSource<bool>? reconciliationRelease = null)
            {
                m_blockedProcessingUri = blockedProcessingUri;
                m_processingEntered = processingEntered;
                m_processingRelease = processingRelease;
                m_blockedReconciliationUri = blockedReconciliationUri;
                m_reconciliationEntered = reconciliationEntered;
                m_reconciliationRelease = reconciliationRelease;
            }

            public bool ProcessingCancellationObserved
                => Volatile.Read(ref m_processingCancellationObserved) != 0;

            public string[] ProcessedApplicationUris
                => m_processedApplicationUris.ToArray();

            public string[] ReconciledApplicationUris
                => m_reconciledApplicationUris.ToArray();

            public (string Event, string ApplicationUri)[] EventsFor(string applicationUri)
            {
                return m_events.Where(item => item.ApplicationUri == applicationUri).ToArray();
            }

            public async ValueTask ProcessAsync(
                ApplicationDescription application,
                CancellationToken cancellationToken = default)
            {
                string applicationUri = application.ApplicationUri!;
                m_processedApplicationUris.Enqueue(applicationUri);
                m_events.Enqueue(("process", applicationUri));
                if (applicationUri == m_blockedProcessingUri)
                {
                    m_processingEntered!.TrySetResult(true);
                    try
                    {
                        await m_processingRelease!.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        Interlocked.Exchange(ref m_processingCancellationObserved, 1);
                        throw;
                    }
                }
            }

            public async ValueTask ReconcileInterruptedAsync(
                ApplicationDescription application,
                CancellationToken cancellationToken = default)
            {
                string applicationUri = application.ApplicationUri!;
                m_reconciledApplicationUris.Enqueue(applicationUri);
                m_events.Enqueue(("reconcile-enter", applicationUri));
                if (applicationUri == m_blockedReconciliationUri)
                {
                    m_reconciliationEntered!.TrySetResult(true);
                    await m_reconciliationRelease!.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                }
                m_events.Enqueue(("reconcile-complete", applicationUri));
            }
        }

        /// <summary>
        /// Supplies a scripted processor without constructing network clients.
        /// </summary>
        private sealed class Processor : IDeviceRegistrarPushProcessor
        {
            /// <summary>
            /// Gets or sets the script for one attempt.
            /// </summary>
            public Func<ApplicationDescription, CancellationToken, ValueTask> Handler { get; set; }
                = static (_, _) => default;

            /// <inheritdoc/>
            public ValueTask ProcessAsync(ApplicationDescription application, CancellationToken cancellationToken)
            {
                return Handler(application, cancellationToken);
            }
        }

        /// <summary>
        /// Records the worker's source-generated diagnostics without writing to external logs.
        /// </summary>
        private sealed class WorkerLogs : ILoggerFactory, ILogger
        {
            private readonly TaskCompletionSource<bool>[] m_completionSignals = [Signal(), Signal()];
            private int m_completionCount;

            /// <summary>
            /// Gets completed log calls in publication order.
            /// </summary>
            public ConcurrentQueue<(LogLevel Level, EventId Event, Exception? Error, string Message)> Events { get; }
                = new();

            /// <summary>
            /// Waits for the requested number of durable scheduler completion events.
            /// </summary>
            public Task WaitForCompletionCountAsync(int count)
            {
                if (count < 1 || count > m_completionSignals.Length)
                {
                    throw new ArgumentOutOfRangeException(nameof(count));
                }
                return m_completionSignals[count - 1].Task.WaitAsync(k_deadline);
            }

            /// <inheritdoc/>
            public ILogger CreateLogger(string categoryName)
            {
                return this;
            }

            /// <inheritdoc/>
            public void AddProvider(ILoggerProvider provider)
            {
                throw new NotSupportedException();
            }

            /// <inheritdoc/>
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            {
                return null;
            }

            /// <inheritdoc/>
            public bool IsEnabled(LogLevel logLevel)
            {
                return true;
            }

            /// <inheritdoc/>
            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                Events.Enqueue((logLevel, eventId, exception, formatter(state, exception)));
                if (eventId.Id == 100)
                {
                    int count = Interlocked.Increment(ref m_completionCount);
                    if (count <= m_completionSignals.Length)
                    {
                        m_completionSignals[count - 1].TrySetResult(true);
                    }
                }
            }

            /// <inheritdoc/>
            public void Dispose()
            {
            }
        }

        /// <summary>A failure guard only; test ordering is controlled by explicit signals, not delays.</summary>
        private static readonly TimeSpan k_deadline = TimeSpan.FromSeconds(10);
        /// <summary>
        /// The registrar URIs accepted and processed by the queue-capacity test.
        /// </summary>
        private static readonly string[] s_expectedAcceptedApplicationUris = ["urn:first", "urn:second"];
        /// <summary>
        /// The registrar URIs processed when the first handler invocation fails.
        /// </summary>
        private static readonly string[] s_expectedProcessedApplicationUris = ["urn:rejected", "urn:accepted"];
    }
}
