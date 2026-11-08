/* ========================================================================
 * Copyright (c) 2005-2026 The OPC Foundation, Inc. All rights reserved.
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
using System.Threading.Tasks;
using Moq;
using NUnit.Framework;
using Opc.Ua.AutoID.Client;
using Opc.Ua.Client;
using Opc.Ua.Client.Subscriptions;
using Opc.Ua.Client.Subscriptions.MonitoredItems;
using Opc.Ua.Client.Subscriptions.Streaming;
using Opc.Ua.Tests;

namespace Opc.Ua.AutoID.Tests
{
    /// <summary>
    /// Exercises client error and boundary paths with controlled service responses.
    /// </summary>
    [TestFixture]
    [Category("AutoID")]
    public sealed class AutoIdClientBranchTests
    {
        [Test]
        public void ObserveScanActiveRejectsANullSubscription()
        {
            var harness = CreateClient();

            Assert.Throws<ArgumentNullException>(() => harness.Client.ObserveScanActiveAsync(null!, Reader));
        }

        [Test]
        public async Task ObserveScanActiveReportsAnAbsentControlBeforeSubscribingAsync()
        {
            (Mock<ISession> session, AutoIdClient client, ushort namespaceIndex) = CreateClient();
            SetupBrowse(session, _ => []);
            var streaming = new Mock<IStreamingSubscription>(MockBehavior.Strict);
            await using IAsyncEnumerator<AutoIdScanActiveReadResult> changes = client
                .ObserveScanActiveAsync(streaming.Object, ReaderFor(namespaceIndex))
                .GetAsyncEnumerator();

            ServiceResultException error = (await Assert.ThrowsAsync<ServiceResultException>(
                async () => await changes.MoveNextAsync().ConfigureAwait(false)))!;

            Assert.That(error.StatusCode, Is.EqualTo((StatusCode)StatusCodes.BadNotFound));
            streaming.VerifyNoOtherCalls();
        }

        [Test]
        public async Task ObserveScanActiveCompletesWhenTheSubscriptionEndsAsync()
        {
            (Mock<ISession> session, AutoIdClient client, ushort namespaceIndex) = CreateClient();
            SetupBrowse(session, _ => [Child(BrowseNames.ScanActive, NodeClass.Variable, namespaceIndex)]);
            var streaming = new Mock<IStreamingSubscription>(MockBehavior.Strict);
            streaming.Setup(value => value.SubscribeDataChangesAsync(
                    It.IsAny<NodeId>(),
                    It.IsAny<MonitoredItemOptions?>(),
                    It.IsAny<CancellationToken>()))
                .Returns(EmptyChanges());

            await using IAsyncEnumerator<AutoIdScanActiveReadResult> changes = client
                .ObserveScanActiveAsync(streaming.Object, ReaderFor(namespaceIndex))
                .GetAsyncEnumerator();

            Assert.That(await changes.MoveNextAsync().ConfigureAwait(false), Is.False);
            streaming.Verify(value => value.SubscribeDataChangesAsync(
                It.IsAny<NodeId>(),
                It.IsAny<MonitoredItemOptions?>(),
                It.IsAny<CancellationToken>()), Times.Once);
        }

        [Test]
        public async Task ReadScanActiveReturnsNotFoundWhenTheAutoIdNamespaceIsAbsentAsync()
        {
            var harness = CreateClient(includeAutoIdNamespace: false);

            AutoIdScanActiveReadResult result = await harness.Client.ReadScanActiveAsync(Reader).ConfigureAwait(false);

            Assert.That(result.Status, Is.EqualTo((StatusCode)StatusCodes.BadNotFound));
            harness.Session.Verify(value => value.BrowseAsync(
                It.IsAny<RequestHeader?>(),
                It.IsAny<ViewDescription?>(),
                It.IsAny<uint>(),
                It.IsAny<ArrayOf<BrowseDescription>>(),
                It.IsAny<CancellationToken>()), Times.Never);
        }

        [Test]
        public async Task ReadScanParametersReportsMissingNestedNodesWithoutReadingAsync()
        {
            (Mock<ISession> session, AutoIdClient client, ushort namespaceIndex) = CreateClient();
            NodeId runtimeParametersId = new("runtime", namespaceIndex);
            SetupBrowse(session, parent => parent.Equals(ReaderFor(namespaceIndex).NodeId)
                ? [Child(BrowseNames.RuntimeParameters, NodeClass.Object, namespaceIndex, runtimeParametersId)]
                : []);

            AutoIdScanParameterReadResult result = await client
                .ReadScanParametersAsync(ReaderFor(namespaceIndex))
                .ConfigureAwait(false);

            Assert.Multiple(() =>
            {
                Assert.That(result.Status.Duration, Is.EqualTo((StatusCode)StatusCodes.BadNotFound));
                Assert.That(result.Status.Cycles, Is.EqualTo((StatusCode)StatusCodes.BadNotFound));
                Assert.That(result.Status.DataAvailable, Is.EqualTo((StatusCode)StatusCodes.BadNotFound));
                Assert.That(result.Status.CodeType, Is.EqualTo((StatusCode)StatusCodes.BadNotFound));
                Assert.That(result.Status.CodeTypes, Is.EqualTo((StatusCode)StatusCodes.BadNotFound));
                Assert.That(result.CodeTypeNamesStatus, Is.EqualTo((StatusCode)StatusCodes.BadNotFound));
            });
            session.Verify(value => value.ReadAsync(
                It.IsAny<RequestHeader?>(),
                It.IsAny<double>(),
                It.IsAny<TimestampsToReturn>(),
                It.IsAny<ArrayOf<ReadValueId>>(),
                It.IsAny<CancellationToken>()), Times.Never);
        }

        [Test]
        public async Task ReadScanActiveRejectsDuplicateBrowseNamesAsync()
        {
            (Mock<ISession> session, AutoIdClient client, ushort namespaceIndex) = CreateClient();
            SetupBrowse(session, _ =>
            [
                Child(BrowseNames.ScanActive, NodeClass.Variable, namespaceIndex, new NodeId("first", namespaceIndex)),
                Child(BrowseNames.ScanActive, NodeClass.Variable, namespaceIndex, new NodeId("second", namespaceIndex))
            ]);

            ServiceResultException error = (await Assert.ThrowsAsync<ServiceResultException>(
                async () => await client.ReadScanActiveAsync(ReaderFor(namespaceIndex)).ConfigureAwait(false)))!;

            Assert.That(error.StatusCode, Is.EqualTo((StatusCode)StatusCodes.BadBrowseNameDuplicated));
        }

        [TestCase("not-bool", false)]
        [TestCase("true", true)]
        public async Task ReadScanActivePreservesBadStatusesAndRejectsWrongValueTypesAsync(
            string value,
            bool accessDenied)
        {
            StatusCode valueStatus = accessDenied ? StatusCodes.BadUserAccessDenied : StatusCodes.Good;
            StatusCode expectedStatus = accessDenied ? StatusCodes.BadUserAccessDenied : StatusCodes.BadTypeMismatch;
            (Mock<ISession> session, AutoIdClient client, ushort namespaceIndex) = CreateClient();
            NodeId scanActiveId = new("scan-active", namespaceIndex);
            SetupBrowse(session, _ =>
                [Child(BrowseNames.ScanActive, NodeClass.Variable, namespaceIndex, scanActiveId)]);
            SetupRead(session, _ =>
            [
                new DataValue(Variant.From(value), valueStatus)
            ]);

            AutoIdScanActiveReadResult result = await client.ReadScanActiveAsync(ReaderFor(namespaceIndex))
                .ConfigureAwait(false);

            Assert.Multiple(() =>
            {
                Assert.That(result.Status, Is.EqualTo(expectedStatus));
                Assert.That(result.IsActive, Is.False);
            });
        }

        [Test]
        public async Task ReadScanActiveRejectsAResultCountMismatchAsync()
        {
            (Mock<ISession> session, AutoIdClient client, ushort namespaceIndex) = CreateClient();
            SetupBrowse(session, _ => [Child(BrowseNames.ScanActive, NodeClass.Variable, namespaceIndex)]);
            SetupRead(session, _ => []);

            ServiceResultException error = (await Assert.ThrowsAsync<ServiceResultException>(
                async () => await client.ReadScanActiveAsync(ReaderFor(namespaceIndex)).ConfigureAwait(false)))!;

            Assert.That(error.StatusCode, Is.EqualTo((StatusCode)StatusCodes.BadUnexpectedError));
        }

        [Test]
        public async Task ReadDeviceRejectsAMissingRequiredVariableAsync()
        {
            (Mock<ISession> session, AutoIdClient client, ushort namespaceIndex) = CreateClient();
            SetupBrowse(session, _ => [Child(BrowseNames.DeviceStatus, NodeClass.Variable, namespaceIndex)]);
            SetupRead(session, _ => [new DataValue(Variant.From((int)DeviceStatusEnumeration.Idle))]);

            ServiceResultException error = (await Assert.ThrowsAsync<ServiceResultException>(
                async () => await client.ReadDeviceAsync(
                    ReaderFor(namespaceIndex), AutoIdReadOptions.StatusOnly).ConfigureAwait(false)))!;

            Assert.That(error.StatusCode, Is.EqualTo((StatusCode)StatusCodes.BadNotFound));
        }

        [Test]
        public async Task ReadDevicePreservesBadStatusForARequiredVariableAsync()
        {
            (Mock<ISession> session, AutoIdClient client, ushort namespaceIndex) = CreateClient();
            SetupBrowse(session, _ =>
            [
                Child(BrowseNames.DeviceName, NodeClass.Variable, namespaceIndex),
                Child(BrowseNames.DeviceStatus, NodeClass.Variable, namespaceIndex)
            ]);
            SetupRead(session, _ =>
            [
                DataValue.FromStatusCode(StatusCodes.BadUserAccessDenied),
                new DataValue(Variant.From((int)DeviceStatusEnumeration.Idle))
            ]);

            ServiceResultException error = (await Assert.ThrowsAsync<ServiceResultException>(
                async () => await client.ReadDeviceAsync(
                    ReaderFor(namespaceIndex), AutoIdReadOptions.StatusOnly).ConfigureAwait(false)))!;

            Assert.That(error.StatusCode, Is.EqualTo((StatusCode)StatusCodes.BadUserAccessDenied));
        }

        [Test]
        public async Task ReadLastScanReturnsBadDataWithoutRejectingTheAcquisitionAsync()
        {
            (Mock<ISession> session, AutoIdClient client, ushort namespaceIndex) = CreateClient();
            NodeId lastDataId = new("last-data", namespaceIndex);
            NodeId lastTimestampId = new("last-timestamp", namespaceIndex);
            SetupBrowse(session, _ =>
            [
                Child(BrowseNames.DeviceName, NodeClass.Variable, namespaceIndex),
                Child(BrowseNames.DeviceStatus, NodeClass.Variable, namespaceIndex),
                Child(BrowseNames.LastScanData, NodeClass.Variable, namespaceIndex, lastDataId),
                Child(BrowseNames.LastScanTimestamp, NodeClass.Variable, namespaceIndex, lastTimestampId)
            ]);
            int readCount = 0;
            DateTimeUtc timestamp = new(new DateTime(2026, 11, 6, 12, 0, 0, DateTimeKind.Utc));
            SetupRead(session, _ =>
            {
                if (Interlocked.Increment(ref readCount) == 1)
                {
                    return
                    [
                        new DataValue(Variant.From("Reader")),
                        new DataValue(Variant.From((int)DeviceStatusEnumeration.Idle))
                    ];
                }
                return
                [
                    DataValue.FromStatusCode(StatusCodes.BadUserAccessDenied),
                    new DataValue(Variant.From(timestamp))
                ];
            });

            AutoIdDeviceSnapshot result = await client.ReadLastScanAsync(ReaderFor(namespaceIndex))
                .ConfigureAwait(false);

            Assert.Multiple(() =>
            {
                Assert.That(result.LastScanStatus, Is.EqualTo((StatusCode)StatusCodes.BadUserAccessDenied));
                Assert.That(result.LastScanData.IsNull, Is.True);
                Assert.That(result.LastScanTimestamp, Is.EqualTo(timestamp));
                Assert.That(readCount, Is.EqualTo(2));
            });
        }

        private static (Mock<ISession> Session, AutoIdClient Client, ushort NamespaceIndex) CreateClient(
            bool includeAutoIdNamespace = true)
        {
            ITelemetryContext telemetry = NUnitTelemetryContext.Create();
            ServiceMessageContext messageContext = ServiceMessageContext.Create(telemetry);
            ushort namespaceIndex = includeAutoIdNamespace
                ? checked((ushort)messageContext.NamespaceUris.GetIndexOrAppend(AutoIdModel.NamespaceUri))
                : (ushort)1;
            var session = new Mock<ISession>(MockBehavior.Strict);
            session.SetupGet(value => value.MessageContext).Returns(messageContext);
            session.SetupGet(value => value.NamespaceUris).Returns(messageContext.NamespaceUris);
            session.SetupGet(value => value.OperationLimits).Returns(new OperationLimits());
            session.SetupGet(value => value.ServerCapabilities).Returns(new ServerCapabilities());
            session.SetupGet(value => value.ContinuationPointPolicy).Returns(ContinuationPointPolicy.Default);
            return (session, new AutoIdClient(session.Object, telemetry), namespaceIndex);
        }

        private static AutoIdReaderEntry ReaderFor(int namespaceIndex)
        {
            ushort index = namespaceIndex < 0 ? (ushort)1 : checked((ushort)namespaceIndex);
            return new AutoIdReaderEntry(
                new NodeId("reader", index),
                new QualifiedName("Reader", index),
                "Reader",
                new NodeId("reader-type", index),
                AutoIdReaderKind.Rfid);
        }

        private static ReferenceDescription Child(
            string name,
            NodeClass nodeClass,
            int namespaceIndex,
            NodeId nodeId = default)
        {
            ushort index = checked((ushort)namespaceIndex);
            NodeId id = nodeId.IsNull ? new NodeId(name, index) : nodeId;
            return new ReferenceDescription
            {
                BrowseName = new QualifiedName(name, index),
                DisplayName = new LocalizedText(name),
                NodeClass = nodeClass,
                NodeId = id
            };
        }

        private static void SetupBrowse(
            Mock<ISession> session,
            Func<NodeId, ReferenceDescription[]> getChildren)
        {
            session.Setup(value => value.BrowseAsync(
                    It.IsAny<RequestHeader?>(),
                    It.IsAny<ViewDescription?>(),
                    It.IsAny<uint>(),
                    It.IsAny<ArrayOf<BrowseDescription>>(),
                    It.IsAny<CancellationToken>()))
                .Returns((RequestHeader? _,
                    ViewDescription? _,
                    uint _,
                    ArrayOf<BrowseDescription> requests,
                    CancellationToken _) =>
                {
                    Assert.That(requests, Has.Count.EqualTo(1));
                    BrowseResult result = new()
                    {
                        StatusCode = StatusCodes.Good,
                        References = getChildren(requests[0].NodeId)
                    };
                    return new ValueTask<BrowseResponse>(new BrowseResponse
                    {
                        ResponseHeader = new ResponseHeader(),
                        Results = [result]
                    });
                });
        }

        private static void SetupRead(
            Mock<ISession> session,
            Func<ArrayOf<ReadValueId>, DataValue[]> getResults)
        {
            session.Setup(value => value.ReadAsync(
                    It.IsAny<RequestHeader?>(),
                    It.IsAny<double>(),
                    It.IsAny<TimestampsToReturn>(),
                    It.IsAny<ArrayOf<ReadValueId>>(),
                    It.IsAny<CancellationToken>()))
                .Returns((RequestHeader? _,
                    double _,
                    TimestampsToReturn _,
                    ArrayOf<ReadValueId> nodes,
                    CancellationToken _) =>
                {
                    DataValue[] results = getResults(nodes);
                    return new ValueTask<ReadResponse>(new ReadResponse
                    {
                        ResponseHeader = new ResponseHeader(),
                        Results = results.ToArrayOf()
                    });
                });
        }

        private static async IAsyncEnumerable<DataValueChange> EmptyChanges()
        {
            await Task.CompletedTask.ConfigureAwait(false);
            yield break;
        }

        private static readonly AutoIdReaderEntry Reader = new(
            new NodeId("reader", 1),
            new QualifiedName("Reader", 1),
            "Reader",
            new NodeId("reader-type", 1),
            AutoIdReaderKind.Rfid);
    }
}
