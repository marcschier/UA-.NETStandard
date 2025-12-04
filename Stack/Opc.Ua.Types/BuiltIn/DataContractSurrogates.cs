/* Copyright (c) 1996-2022 The OPC Foundation. All rights reserved.
   The source code in this file is covered under a dual-license scenario:
     - RCL: for OPC Foundation Corporate Members in good-standing
     - GPL V2: everybody else
   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/
   GNU General Public License as published by the Free Software Foundation;
   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2
   This source code is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

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
