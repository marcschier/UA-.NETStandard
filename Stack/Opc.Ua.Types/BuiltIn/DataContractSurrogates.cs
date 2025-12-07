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
using System.Collections;
using System.Linq;
using System.Runtime.Serialization;

namespace Opc.Ua
{
    /// <summary>
    /// Surrogates for data contract serializer. Used to swap types that
    /// are not directly supported by the serializer for types that are.
    /// </summary>
    public class DataContractSurrogates : ISerializationSurrogateProvider
    {
        /// <summary>
        /// Known types
        /// </summary>
        public static Type[] KnownTypes =>
        [
            typeof(Guid),
            typeof(GuidCollection),
            typeof(Uuid),
            typeof(UuidCollection),
            typeof(NodeId),
            typeof(NodeIdCollection),
            typeof(SerializableNodeId),
            typeof(SerializableNodeIdCollection),
            typeof(ExpandedNodeId),
            typeof(ExpandedNodeIdCollection),
            typeof(SerializableExpandedNodeId),
            typeof(SerializableExpandedNodeIdCollection)
        ];

        /// <summary>
        /// Create surrogate provider
        /// </summary>
        /// <param name="messageContext"></param>
        public DataContractSurrogates(IServiceMessageContext messageContext)
        {
            MessageContext = messageContext;
        }

        /// <summary>
        /// Access to message context passed to provider.
        /// </summary>
        public IServiceMessageContext MessageContext { get; }

        /// <inheritdoc/>
        public object GetDeserializedObject(object obj, Type targetType)
        {
            if (targetType == typeof(NodeId))
            {
                return obj is SerializableNodeId value ?
                    value.NodeId :
                    obj;
            }
            if (targetType == typeof(NodeIdCollection))
            {
                return obj is SerializableNodeIdCollection value ?
                    (NodeIdCollection)value :
                    obj;
            }
            if (targetType == typeof(ExpandedNodeId))
            {
                return obj is SerializableExpandedNodeId value ?
                    value.ExpandedNodeId :
                    obj;
            }
            if (targetType == typeof(ExpandedNodeIdCollection))
            {
                return obj is SerializableExpandedNodeIdCollection value ?
                    (ExpandedNodeIdCollection)value :
                    obj;
            }
            if (targetType == typeof(Guid))
            {
                return obj is Uuid value ?
                    value.Value :
                    obj;
            }
            if (targetType == typeof(GuidCollection))
            {
                return obj is UuidCollection value ?
                    (GuidCollection)value :
                    obj;
            }
            return obj;
        }

        /// <inheritdoc/>
        public object GetObjectToSerialize(object obj, Type targetType)
        {
            if (targetType == typeof(SerializableNodeId))
            {
                if (obj is SerializableNodeId value)
                {
                    return value;
                }
                targetType = obj?.GetType() ?? targetType;
            }
            if (targetType == typeof(NodeId))
            {
                return new SerializableNodeId(
                    obj is NodeId value ?
                    value :
                    NodeId.Null);
            }
            if (targetType == typeof(SerializableNodeIdCollection))
            {
                if (obj is SerializableNodeIdCollection value)
                {
                    return value;
                }
                targetType = obj?.GetType() ?? targetType;
            }
            if (targetType == typeof(NodeIdCollection))
            {
                return obj is NodeIdCollection value ?
                    new SerializableNodeIdCollection(value) :
                    obj;
            }
            if (targetType == typeof(SerializableExpandedNodeId))
            {
                if (obj is SerializableExpandedNodeId value)
                {
                    return value;
                }
                targetType = obj?.GetType() ?? targetType;
            }
            if (targetType == typeof(ExpandedNodeId))
            {
                return new SerializableExpandedNodeId(
                    obj is ExpandedNodeId value ?
                    value :
                    ExpandedNodeId.Null);
            }
            if (targetType == typeof(SerializableExpandedNodeIdCollection))
            {
                if (obj is SerializableExpandedNodeIdCollection value)
                {
                    return value;
                }
                targetType = obj?.GetType() ?? targetType;
            }
            if (targetType == typeof(ExpandedNodeIdCollection))
            {
                return obj is ExpandedNodeIdCollection value ?
                    new SerializableExpandedNodeIdCollection(value) :
                    obj;
            }
            if (targetType == typeof(Uuid))
            {
                if (obj is Uuid value)
                {
                    return value;
                }
                targetType = obj?.GetType() ?? targetType;
            }
            if (targetType == typeof(Guid))
            {
                return obj is Guid value ? new Uuid(value) : obj;
            }
            if (targetType == typeof(UuidCollection))
            {
                if (obj is UuidCollection value)
                {
                    return value;
                }
                targetType = obj?.GetType() ?? targetType;
            }
            if (targetType == typeof(GuidCollection))
            {
                return obj is GuidCollection value ?
                    new UuidCollection(value) :
                    obj;
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
            if (type == typeof(ExpandedNodeId))
            {
                return typeof(SerializableExpandedNodeId);
            }
            if (type == typeof(ExpandedNodeIdCollection))
            {
                return typeof(SerializableExpandedNodeIdCollection);
            }
            if (type == typeof(Guid))
            {
                return typeof(Uuid);
            }
            if (type == typeof(GuidCollection))
            {
                return typeof(UuidCollection);
            }
            return type;
        }
    }
}
