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

#if NET8_0_OR_GREATER
using System.Collections.Frozen;
#else
using System.Collections.ObjectModel;
using System.Linq;
#endif

namespace Opc.Ua
{
    /// <summary>
    /// A class that defines constants used by UA applications.
    /// </summary>
    public static partial class DataTypes
    {
        /// <summary>
        /// Returns the browse names for all data types.
        /// </summary>
        [Obsolete("Use BrowseNames property instead.")]
        public static string[] GetBrowseNames()
        {
            return [.. BrowseNames];
        }

        /// <summary>
        /// Returns the data type id that describes a value.
        /// </summary>
        public static NodeId GetDataTypeId(object value)
        {
            return TypeInfo.GetDataTypeId(value);
        }

        /// <summary>
        /// Returns the data type id that describes a value.
        /// </summary>
        public static NodeId GetDataTypeId(Type type)
        {
            return TypeInfo.GetDataTypeId(type);
        }

        /// <summary>
        /// Returns the data type id that describes a value.
        /// </summary>
        public static NodeId GetDataTypeId(TypeInfo typeInfo)
        {
            return TypeInfo.GetDataTypeId(typeInfo);
        }

        /// <summary>
        /// Returns the array rank for a value.
        /// </summary>
        public static int GetValueRank(object value)
        {
            return TypeInfo.GetValueRank(value);
        }

        /// <summary>
        /// Returns the array rank for a type.
        /// </summary>
        public static int GetValueRank(Type type)
        {
            return TypeInfo.GetValueRank(type);
        }

        /// <summary>
        /// Returns the BuiltInType type for the DataTypeId.
        /// </summary>
        public static BuiltInType GetBuiltInType(NodeId datatypeId)
        {
            return TypeInfo.GetBuiltInType(datatypeId);
        }

        /// <summary>
        /// Returns the BuiltInType type for the DataTypeId.
        /// </summary>
        public static BuiltInType GetBuiltInType(NodeId datatypeId, ITypeTable typeTree)
        {
            return TypeInfo.GetBuiltInType(datatypeId, typeTree);
        }

        /// <summary>
        /// Returns the system type for the datatype.
        /// </summary>
        public static Type GetSystemType(NodeId datatypeId, IEncodeableFactory factory)
        {
            return TypeInfo.GetSystemType(datatypeId, factory);
        }
    }
}
