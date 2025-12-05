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
using System.Linq;
using System.Runtime.Serialization;

namespace Opc.Ua
{
    /// <summary>
    /// Surrogates for data contract serializer
    /// </summary>
    public sealed class DataContractSurrogates : ISerializationSurrogateProvider
    {
        /// <summary>
        /// A static instance of the surrogate provider.
        /// </summary>
        public static DataContractSurrogates Instance { get; } = new DataContractSurrogates();

        /// <inheritdoc/>
        public object GetDeserializedObject(object obj, Type targetType)
        {
            if (targetType == typeof(NodeId))
            {
                return obj is SerializableNodeId s ? s.NodeId : NodeId.Null;
            }
            if (targetType == typeof(NodeIdCollection))
            {
                return obj is SerializableNodeIdCollection n ? (NodeIdCollection)n : obj;
            }
            if (targetType == typeof(Guid) && obj is Uuid uuid)
            {
                return (Guid)uuid;
            }
            return obj;
        }

        /// <inheritdoc/>
        public object GetObjectToSerialize(object obj, Type targetType)
        {
            if (targetType == typeof(NodeId))
            {
                return new SerializableNodeId(obj is NodeId n ? n : NodeId.Null);
            }
            if (targetType == typeof(NodeIdCollection))
            {
                return obj is NodeIdCollection n ? (SerializableNodeIdCollection)n : obj;
            }
            if (targetType == typeof(Guid))
            {
                return obj is Guid g ? new Uuid(g) : Uuid.Empty;
            }
            return obj;
        }

        /// <inheritdoc/>
        public Type GetSurrogateType(Type type)
        {
            if (type == typeof(NodeId))
            {
                return typeof(SerializableNodeId);
            }
            if (type == typeof(NodeIdCollection))
            {
                return typeof(SerializableNodeIdCollection);
            }
            if (type == typeof(Guid))
            {
                return typeof(Uuid);
            }
            return type;
        }
    }
}
