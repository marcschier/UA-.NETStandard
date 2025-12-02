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

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Context
    /// </summary>
    internal interface ITemplateContext
    {
        /// <summary>
        /// The index of the current target within the list being processed.
        /// </summary>
        int Index { get; }

        /// <summary>
        /// Get template writer
        /// </summary>
        TemplateWriter Out { get; }

        /// <summary>
        /// The current iteration variable that is the target of the template.
        /// </summary>
        object Target { get; }

        /// <summary>
        /// The interpolated template string passed to AddReplacement method.
        /// </summary>
        TemplateString TemplateString { get; }

        /// <summary>
        /// The token that is to be replaced by the current template evaluation.
        /// </summary>
        string Token { get; }
    }

    /// <summary>
    /// Contains the current context to use for serialization.
    /// </summary>
    internal sealed class TemplateContext : ITemplateContext
    {
        /// <summary>
        /// The interpolated template string passed to AddReplacement method.
        /// </summary>
        public TemplateString TemplateString { get; set; }

        /// <summary>
        /// Get template writer
        /// </summary>
        public TemplateWriter Out { get; set; }

        /// <summary>
        /// The token that is to be replaced by the current template evaluation.
        /// </summary>
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// The current iteration variable that is the target of the template.
        /// </summary>
        public object Target { get; set; }

        /// <summary>
        /// The index of the current target within the list being processed.
        /// </summary>
        public int Index { get; set; } = -1;
    }
}
