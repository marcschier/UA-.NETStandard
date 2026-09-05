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

namespace Opc.Ua.Server.Historian
{
    /// <summary>
    /// Continuation-point state persisted by the dispatcher between
    /// HistoryRead pages.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The dispatcher serialises one instance per outstanding paginated
    /// read into the session's continuation-point dictionary
    /// (<see cref="ISessionContinuationPoints.SaveHistory"/>).
    /// On the next page request the dispatcher restores the state
    /// (which removes it from the session's storage), calls the same
    /// provider with the saved <see cref="ResumeToken"/>, and either
    /// retires the continuation (final page → <see cref="Dispose"/>) or
    /// re-saves it with the new resume token under a fresh <see cref="Id"/>.
    /// This makes every issued continuation point single-use.
    /// </para>
    /// <para>
    /// State held here must stay small — it is stored verbatim in the
    /// session for as long as the client keeps the continuation point
    /// active. The session pool already invokes <see cref="Dispose"/>
    /// when an entry is evicted (max-cp eviction or session close), so
    /// future provider implementations that need to release backend
    /// resources from a saved cursor can do so by extending
    /// <see cref="ResumeToken"/> with a payload type that hooks into
    /// disposal — the framework guarantees the call.
    /// </para>
    /// </remarks>
    internal sealed class HistorianContinuationState : IHistoryContinuationPoint
    {
        public required Guid Id { get; set; }

        public required IHistorianProvider Provider { get; init; }

        public required HistorianReadKind Kind { get; init; }

        public required NodeId NodeId { get; init; }

        public required HistorianResumeToken ResumeToken { get; set; }

        public HistorianRawReadRequest? RawRequest { get; init; }

        public HistorianModifiedReadRequest? ModifiedRequest { get; init; }

        public HistorianProcessedReadRequest? ProcessedRequest { get; init; }

        public HistorianAtTimeReadRequest? AtTimeRequest { get; init; }

        public HistorianAnnotationReadRequest? AnnotationRequest { get; init; }

        public HistorianEventReadRequest? EventRequest { get; init; }

        public TimestampsToReturn TimestampsToReturn { get; init; }

        public NumericRange IndexRange { get; init; }

        public QualifiedName DataEncoding { get; init; } = QualifiedName.Null;

        public bool UsesLegacyAnnotationNodeId { get; init; }

        /// <summary>
        /// Buffered output values for paginated processed reads using
        /// the framework streaming fallback. The first call computes
        /// every aggregate value, returns the first page, and stores
        /// the remainder here for subsequent calls to drain. Null for
        /// every other read kind. Successor and restoration states share
        /// this immutable payload and advance only their own offset.
        /// </summary>
        public HistorianBufferedProcessedPayload? BufferedProcessedOutputs { get; set; }

        /// <summary>
        /// Cursor into <see cref="BufferedProcessedOutputs"/>.
        /// </summary>
        public int BufferedProcessedOffset { get; set; }

        public HistorianContinuationState CreateSuccessor(
            HistorianResumeToken resumeToken,
            int? bufferedProcessedOffset = null)
        {
            return Clone(
                Guid.NewGuid(),
                resumeToken,
                bufferedProcessedOffset ?? BufferedProcessedOffset,
                NodeId,
                UsesLegacyAnnotationNodeId);
        }

        public HistorianContinuationState CreateRestorationCopy()
        {
            return Clone(
                Id,
                ResumeToken,
                BufferedProcessedOffset,
                NodeId,
                UsesLegacyAnnotationNodeId);
        }

        public HistorianContinuationState CreateNormalizedAnnotationState(
            NodeId nodeId)
        {
            if (nodeId.IsNull)
            {
                throw new ArgumentException(
                    "The annotation property NodeId must not be null.",
                    nameof(nodeId));
            }
            if (Kind != HistorianReadKind.Annotations ||
                !UsesLegacyAnnotationNodeId)
            {
                throw new InvalidOperationException(
                    "Only legacy annotation continuation state can be normalized.");
            }
            return Clone(
                Id,
                ResumeToken,
                BufferedProcessedOffset,
                nodeId,
                usesLegacyAnnotationNodeId: false);
        }

        public void Dispose()
        {
            // Reserved hook so the session's continuation-point pool can
            // release provider resources when an entry is evicted. Today
            // the InMemoryHistorianProvider holds no resources in a resume
            // token; provider implementations that do (e.g. database
            // cursors) should attach disposal logic here in a future
            // extension.
            BufferedProcessedOutputs = null;
        }

        private HistorianContinuationState Clone(
            Guid id,
            HistorianResumeToken resumeToken,
            int bufferedProcessedOffset,
            NodeId nodeId,
            bool usesLegacyAnnotationNodeId)
        {
            return new HistorianContinuationState
            {
                Id = id,
                Provider = Provider,
                Kind = Kind,
                NodeId = nodeId,
                ResumeToken = resumeToken,
                RawRequest = RawRequest is null ? null : RawRequest with { },
                ModifiedRequest = ModifiedRequest is null
                    ? null
                    : ModifiedRequest with { },
                ProcessedRequest = ProcessedRequest is null
                    ? null
                    : ProcessedRequest with
                    {
                        Configuration = CoreUtils.Clone(
                            ProcessedRequest.Configuration) ??
                            throw new InvalidOperationException(
                                "The processed request configuration could not be cloned.")
                    },
                AtTimeRequest = AtTimeRequest is null
                    ? null
                    : AtTimeRequest with { },
                AnnotationRequest = AnnotationRequest is null
                    ? null
                    : AnnotationRequest with { },
                EventRequest = EventRequest is null
                    ? null
                    : EventRequest with
                    {
                        Filter = CoreUtils.Clone(EventRequest.Filter) ??
                            throw new InvalidOperationException(
                                "The event request filter could not be cloned.")
                    },
                TimestampsToReturn = TimestampsToReturn,
                IndexRange = IndexRange,
                DataEncoding = DataEncoding,
                UsesLegacyAnnotationNodeId =
                    usesLegacyAnnotationNodeId,
                BufferedProcessedOutputs = BufferedProcessedOutputs,
                BufferedProcessedOffset = bufferedProcessedOffset
            };
        }
    }

    /// <summary>
    /// Immutable buffered output shared by processed continuation states.
    /// </summary>
    internal sealed class HistorianBufferedProcessedPayload
    {
        public HistorianBufferedProcessedPayload(
            ArrayOf<DataValue> values)
        {
            Values = values;
        }

        public int Count => Values.Count;

        public DataValue this[int index] => Values[index];

        private ArrayOf<DataValue> Values { get; }
    }

    /// <summary>
    /// Kind of paginated read in flight.
    /// </summary>
    internal enum HistorianReadKind
    {
        Raw,
        Modified,
        Processed,
        AtTime,
        Annotations,
        Events
    }
}
