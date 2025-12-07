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
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;

namespace Opc.Ua
{
    /// <summary>
    /// Denotes a surrogate for a specific type.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public interface ISurrogateFor<out T>
    {
        /// <summary>
        /// Which value is surrogated
        /// </summary>
        public T Value { get; }
    }

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
            .. SurrogateMappings.Keys,
            .. SurrogateMappings.Values
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
            if (typeof(ISurrogateFor<>)
                .MakeGenericType(targetType)
                .IsAssignableFrom(obj.GetType()))
            {
                return obj.GetType()
                    .GetProperty(nameof(ISurrogateFor<>.Value))!
                    .GetValue(obj);
            }
            if (targetType == typeof(NodeId))
            {
                return obj is SerializableNodeId value ?
                    value.Value :
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
                    value.Value :
                    obj;
            }
            if (targetType == typeof(ExpandedNodeIdCollection))
            {
                return obj is SerializableExpandedNodeIdCollection value ?
                    (ExpandedNodeIdCollection)value :
                    obj;
            }
            if (targetType == typeof(StatusCode))
            {
                return obj is SerializableStatusCode value ?
                    value.Value :
                    obj;
            }
            if (targetType == typeof(StatusCodeCollection))
            {
                return obj is SerializableStatusCodeCollection value ?
                    (StatusCodeCollection)value :
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
         //  if (typeof(ISurrogateFor<>)
         //      .MakeGenericType(targetType)
         //      .IsAssignableFrom(obj.GetType()))
         //  {
         //      return obj.GetType()
         //          .GetProperty(nameof(ISurrogateFor<>.Value))!
         //          .GetValue(obj);
         //  }
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
            if (targetType == typeof(SerializableStatusCode))
            {
                if (obj is SerializableStatusCode value)
                {
                    return value;
                }
                targetType = obj?.GetType() ?? targetType;
            }
            if (targetType == typeof(StatusCode))
            {
                return new SerializableStatusCode(
                    obj is StatusCode value ?
                    value :
                    default);
            }
            if (targetType == typeof(SerializableStatusCodeCollection))
            {
                if (obj is SerializableStatusCodeCollection value)
                {
                    return value;
                }
                targetType = obj?.GetType() ?? targetType;
            }
            if (targetType == typeof(StatusCodeCollection))
            {
                return obj is StatusCodeCollection value ?
                    new SerializableStatusCodeCollection(value) :
                    obj;
            }
            return obj;
        }

        /// <inheritdoc/>
        public Type GetSurrogateType(Type type)
        {
            return SurrogateMappings.TryGetValue(type, out Type surrogateType) ?
                surrogateType :
                type;
        }

        /// <summary>
        /// Surrogate mappings
        /// </summary>
        public static readonly Dictionary<Type, Type> SurrogateMappings = new()
        {
            { typeof(NodeId), typeof(SerializableNodeId) },
            { typeof(NodeIdCollection), typeof(SerializableNodeIdCollection) },
            { typeof(ExpandedNodeId), typeof(SerializableExpandedNodeId) },
            { typeof(ExpandedNodeIdCollection), typeof(SerializableExpandedNodeIdCollection) },
            { typeof(Guid), typeof(Uuid) },
            { typeof(GuidCollection), typeof(UuidCollection) },
            { typeof(StatusCode), typeof(SerializableStatusCode) },
            { typeof(StatusCodeCollection), typeof(SerializableStatusCodeCollection) },
            { typeof(QualifiedName), typeof(SerializableQualifiedName) },
            { typeof(QualifiedNameCollection), typeof(SerializableQualifiedNameCollection) },
            { typeof(Variant), typeof(SerializableVariant) },
            { typeof(VariantCollection), typeof(SerializableVariantCollection) },
        };
    }
}
