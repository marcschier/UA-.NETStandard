/* Copyright (c) 1996-2020 The OPC Foundation. All rights reserved.
   The source code in this file is covered under a dual-license scenario:
     - RCL: for OPC Foundation members in good-standing
     - GPL V2: everybody else
   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/
   GNU General Public License as published by the Free Software Foundation;
   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2
   This source code is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

namespace Opc.Ua
{
    /// <summary> 
    /// The base class for all object type nodes.
    /// </summary>
    public class BaseObjectTypeState : BaseTypeState
    {

        /// <summary>
        /// Initializes the instance with its defalt attribute values.
        /// </summary>
        public BaseObjectTypeState() : base(NodeClass.ObjectType)
        {
        }

        /// <summary>
        /// Initializes the instance with the default values.
        /// </summary>
        protected override void Initialize(ISystemContext context)
        {
            SuperTypeId = Opc.Ua.NodeId.Create(Opc.Ua.ObjectTypes.BaseObjectType, Opc.Ua.Namespaces.OpcUa, context.NamespaceUris);
            NodeId = Opc.Ua.NodeId.Create(Opc.Ua.ObjectTypes.BaseObjectType, Opc.Ua.Namespaces.OpcUa, context.NamespaceUris);
            BrowseName = Opc.Ua.QualifiedName.Create(Opc.Ua.BrowseNames.BaseObjectType, Opc.Ua.Namespaces.OpcUa, context.NamespaceUris);
            DisplayName = new LocalizedText(Opc.Ua.BrowseNames.BaseObjectType, string.Empty, Opc.Ua.BrowseNames.BaseObjectType);
            Description = null;
            WriteMask = AttributeWriteMask.None;
            UserWriteMask = AttributeWriteMask.None;
            IsAbstract = false;
        }

    }
}
