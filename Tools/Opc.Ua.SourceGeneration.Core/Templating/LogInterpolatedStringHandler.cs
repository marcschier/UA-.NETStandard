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
using System.Runtime.CompilerServices;
using System.Text;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Test
    /// </summary>
    public static class Log
    {
        /// <summary>
        /// Log
        /// </summary>
        /// <param name="builder"></param>
        public static void Message(LogInterpolatedStringHandler builder)
        {
            Console.WriteLine(builder.GetFormattedText());
        }
    }

    /// <summary>
    /// Handler
    /// </summary>
    [InterpolatedStringHandler]
#pragma warning disable CA1815 // Override equals and operator equals on value types
    public readonly struct LogInterpolatedStringHandler
#pragma warning restore CA1815 // Override equals and operator equals on value types
    {
        /// <summary>
        /// Storage for the built-up string
        /// </summary>
        private readonly StringBuilder m_builder;

        /// <inheritdoc/>
        public LogInterpolatedStringHandler(int literalLength, int formattedCount)
        {
            m_builder = new StringBuilder(literalLength);
            Console.WriteLine($"\tliteral length: {literalLength}, formattedCount: {formattedCount}");
        }

        /// <inheritdoc/>
        public readonly void AppendLiteral(string s)
        {
            Console.WriteLine($"\tAppendLiteral called: {{{s}}}");

            m_builder.Append(s);
            Console.WriteLine("\tAppended the literal string");
        }

        /// <inheritdoc/>
        public readonly void AppendFormatted<T>(T t)
        {
            Console.WriteLine($"\tAppendFormatted called: {{{t}}} is of type {typeof(T)}");

            m_builder.Append(t?.ToString());
            Console.WriteLine("\tAppended the formatted object");
        }

        /// <inheritdoc/>
        internal readonly string GetFormattedText()
        {
            return m_builder.ToString();
        }
    }
}
