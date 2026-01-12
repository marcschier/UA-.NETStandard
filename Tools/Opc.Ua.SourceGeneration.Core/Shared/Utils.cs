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

using System.Xml;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Common utils for all generators
    /// </summary>
    internal static class Utils
    {
        /// <summary>
        /// Ensures the first character is lower case.
        /// </summary>
        public static string ToLowerCamelCase(this string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                return name;
            }

            if (char.IsLower(name[0]))
            {
                return name;
            }

            return CoreUtils.Format("{0}{1}", char.ToLowerInvariant(name[0]), name[1..]);
        }

        /// <summary>
        /// Checks for a null qualified name.
        /// </summary>
        public static bool IsNull(this XmlQualifiedName qname)
        {
            if (qname == null)
            {
                return true;
            }

            if (string.IsNullOrEmpty(qname.Name))
            {
                return true;
            }

            return false;
        }
    }
}
