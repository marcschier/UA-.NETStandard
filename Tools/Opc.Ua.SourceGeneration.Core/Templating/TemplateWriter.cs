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
using System.Reflection;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Template writer that handles indentation and line break management.
    /// </summary>
    internal sealed class TemplateWriter
    {
        /// <summary>
        /// Create template
        /// </summary>
        public TemplateWriter(TextWriter writer)
        {
            m_writer = writer;
            m_indentCharCount = new Stack<int>();
            m_indentCharCount.Push(0);
        }

        /// <summary>
        /// Returns enough whitespace to indent the current line properly.
        /// </summary>
        public string Indentation => IndentationCharCount > 0 ?
            new string(' ', IndentationCharCount) :
            string.Empty;

        /// <summary>
        /// Indent character count
        /// </summary>
        public int IndentationCharCount
            => m_indentCharCount.Peek();

        /// <summary>
        /// Increases the current indentation level by the
        /// specified number of characters.
        /// </summary>
        /// <param name="charCount">The number of characters
        /// to add to the current indentation level. Must be
        /// zero or greater.</param>
        public void PushIndentChars(int charCount)
        {
            m_indentCharCount.Push(
                IndentationCharCount + charCount);
        }

        /// <summary>
        /// Decreases the current indentation level back
        /// </summary>
        public void PopIndentation()
        {
            if (m_indentCharCount.Count > 1)
            {
                m_indentCharCount.Pop();
            }
        }

        /// <summary>
        /// Writes the text to the stream.
        /// </summary>
        public void Write(char text)
        {
            WriteIndentIfNeeded();
            m_writer.Write(text);
        }

        /// <summary>
        /// Writes the text to the stream.
        /// </summary>
        public void Write(string text)
        {
            WriteIndentIfNeeded();
            m_writer.Write(text);
        }

        /// <summary>
        /// Formats and then writes the text to the stream.
        /// </summary>
        public void Write(string format, object arg1)
        {
            WriteIndentIfNeeded();
            m_writer.Write(format, arg1);
        }

        /// <summary>
        /// Formats and then writes the text to the stream.
        /// </summary>
        public void Write(string format, object arg1, object arg2)
        {
            WriteIndentIfNeeded();
            m_writer.Write(format, arg1, arg2);
        }

        /// <summary>
        /// Formats and then writes the text to the stream.
        /// </summary>
        public void Write(string format, object arg1, object arg2, object arg3)
        {
            WriteIndentIfNeeded();
            m_writer.Write(format, arg1, arg2, arg3);
        }

        /// <summary>
        /// Writes a new line and then indents the text and writes the text.
        /// </summary>
        public void WriteAfterNewLine(string text)
        {
            WriteNewLine();
            WriteIndentIfNeeded();
            m_writer.Write(text);
        }

        /// <summary>
        /// Writes the text (indented) to the stream followed by a new line.
        /// </summary>
        public void WriteAfterNewLine(string text, params object[] args)
        {
            WriteNewLine();
            WriteIndentIfNeeded();
            m_writer.Write(text, args);
        }

        /// <summary>
        /// Writes the text followed by a new line.
        /// </summary>
        public void WriteLine(string text)
        {
            WriteIndentIfNeeded();
            m_writer.Write(text);
            WriteNewLine();
        }

        /// <summary>
        /// Formats and then writes the text followed by a new line.
        /// </summary>
        public void WriteLine(string text, params object[] args)
        {
            WriteIndentIfNeeded();
            m_writer.Write(text, args);
            WriteNewLine();
        }

        /// <summary>
        /// Begin new line
        /// </summary>
        public bool WriteNewLine(bool ifNotAlreadyWritten = false)
        {
            if (ifNotAlreadyWritten && m_newLine)
            {
                return false;
            }
            m_writer.Write(Environment.NewLine);
            m_newLine = true;
            return true;
        }

        /// <summary>
        /// Write indent if needed. 
        /// </summary>
        private void WriteIndentIfNeeded()
        {
            if (m_newLine)
            {
                m_newLine = false;
                m_writer.Write(Indentation);
            }
        }

        private readonly TextWriter m_writer;
        private readonly Stack<int> m_indentCharCount;
        private bool m_newLine;
    }
}
