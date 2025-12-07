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
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;

namespace Opc.Ua
{
    /// <summary>
    /// A list of guids.
    /// </summary>
    public class GuidCollection : List<Guid>, ICloneable
    {
        /// <inheritdoc/>
        public GuidCollection()
        {
        }

        /// <inheritdoc/>
        public GuidCollection(IEnumerable<Guid> collection)
            : base(collection)
        {
        }

        /// <inheritdoc/>
        public GuidCollection(int capacity)
            : base(capacity)
        {
        }

        /// <summary>
        /// Converts an array to a collection.
        /// </summary>
        /// <param name="values">The array of <see cref="Guid"/>
        /// values to return as a collection</param>
        public static GuidCollection ToGuidCollection(Guid[] values)
        {
            if (values != null)
            {
                return [.. values];
            }

            return [];
        }

        /// <summary>
        /// Converts an array to a collection.
        /// </summary>
        /// <param name="values">The array of <see cref="Guid"/>
        /// values to return as a collection</param>
        public static implicit operator GuidCollection(Guid[] values)
        {
            return ToGuidCollection(values);
        }

        /// <inheritdoc/>
        public virtual object Clone()
        {
            return MemberwiseClone();
        }

        /// <inheritdoc/>
        public new object MemberwiseClone()
        {
            return new GuidCollection(this);
        }
    }

    /// <summary>
    /// A wrapper for a GUID used during object serialization.
    /// </summary>
    /// <remarks>
    /// This class provides a wrapper around the <see cref="Guid"/>
    /// object, allowing it to be serialized  and encoded/decoded
    /// to/from an underlying stream.
    /// </remarks>x
    [DataContract(Name = "Guid", Namespace = Namespaces.OpcUaXsd)]
    public sealed class Uuid :
        IComparable,
        IFormattable,
        IEquatable<Uuid>,
        IEquatable<Guid>,
        ICloneable,
        ISurrogateFor<Guid>
    {
        /// <summary>
        /// Initializes the object with a string.
        /// </summary>
        /// <param name="text">The string that will be turned
        /// into a Guid</param>
        public Uuid(string text)
        {
            Value = new Guid(text);
        }

        /// <summary>
        /// Initializes the object with a Guid.
        /// </summary>
        /// <param name="guid">The Guid to wrap</param>
        public Uuid(Guid guid)
        {
            Value = guid;
        }

        /// <summary>
        /// A constant containing an empty GUID.
        /// </summary>
        public static Uuid Empty { get; } = new Uuid(Guid.Empty);

        /// <summary>
        /// The GUID serialized as a string.
        /// </summary>
        /// <remarks>
        /// The GUID serialized as a string.
        /// </remarks>
        [DataMember(Name = "String", Order = 1)]
        public string GuidString
        {
            get => Value.ToString();
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    Value = Guid.Empty;
                }
                else
                {
                    Value = new Guid(value);
                }
            }
        }

        /// <summary>
        /// The wrapped guid value.
        /// </summary>
        public Guid Value { get; private set; }

        /// <summary>
        /// Converts Uuid to a Guid structure.
        /// </summary>
        /// <param name="guid">The Guid to convert to a Uuid</param>
        public static implicit operator Guid(Uuid guid)
        {
            return guid.Value;
        }

        /// <summary>
        /// Converts Guid to a Uuid.
        /// </summary>
        /// <param name="guid">The <see cref="Guid"/> to convert
        /// to a <see cref="Uuid"/></param>
        public static implicit operator Uuid(Guid guid)
        {
            return new Uuid(guid);
        }

        /// <inheritdoc/>
        public static bool operator ==(Uuid a, Uuid b)
        {
            return a.Equals(b);
        }

        /// <inheritdoc/>
        public static bool operator !=(Uuid a, Uuid b)
        {
            return !a.Equals(b);
        }

        /// <inheritdoc/>
        public static bool operator ==(Uuid a, Guid b)
        {
            return a.Equals(b);
        }

        /// <inheritdoc/>
        public static bool operator !=(Uuid a, Guid b)
        {
            return !a.Equals(b);
        }

        /// <inheritdoc/>
        public static bool operator <(Uuid a, Uuid b)
        {
            return a.CompareTo(b) < 0;
        }

        /// <inheritdoc/>
        public static bool operator >(Uuid a, Uuid b)
        {
            return a.CompareTo(b) > 0;
        }

        /// <inheritdoc/>
        public static bool operator <=(Uuid a, Uuid b)
        {
            return a.CompareTo(b) <= 0;
        }

        /// <inheritdoc/>
        public static bool operator >=(Uuid a, Uuid b)
        {
            return a.CompareTo(b) >= 0;
        }

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            return obj switch
            {
                Uuid uuidValue => Equals(uuidValue),
                Guid guidValue => Equals(guidValue),
                _ => CompareTo(obj) == 0
            };
        }

        /// <inheritdoc/>
        public bool Equals(Uuid other)
        {
            if (other is null)
            {
                return false;
            }
            return Value.Equals(other.Value);
        }

        /// <inheritdoc/>
        public bool Equals(Guid other)
        {
            return Value.Equals(other);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            return Value.ToString();
        }

        /// <inheritdoc/>
        public int CompareTo(object obj)
        {
            // check for uuids.
            if (obj is Uuid uuidValue)
            {
                return uuidValue.Value.CompareTo(Value);
            }

            // compare guids.
            if (obj is Guid guidValue)
            {
                return Value.CompareTo(guidValue);
            }

            return +1;
        }

        /// <inheritdoc/>
        public string ToString(string format, IFormatProvider formatProvider)
        {
            return Value.ToString(format);
        }

        /// <inheritdoc/>
        public object Clone()
        {
            return MemberwiseClone();
        }

        /// <inheritdoc/>
        public new object MemberwiseClone()
        {
            return new Uuid(Value);
        }
    }

    /// <summary>
    /// A collection of Uuids.
    /// </summary>
    [CollectionDataContract(
        Name = "ListOfGuid",
        Namespace = Namespaces.OpcUaXsd,
        ItemName = "Guid")]
    public class UuidCollection : List<Uuid>,
        ISurrogateFor<GuidCollection>,
        ICloneable
    {
        /// <inheritdoc/>
        public UuidCollection()
        {
        }

        /// <inheritdoc/>
        public UuidCollection(IEnumerable<Uuid> collection)
            : base(collection)
        {
        }

        /// <inheritdoc/>
        public UuidCollection(IEnumerable<Guid> collection)
            : this(collection.Select(g => new Uuid(g)))
        {
        }

        /// <inheritdoc/>
        public UuidCollection(int capacity)
            : base(capacity)
        {
        }

        /// <inheritdoc/>
        public GuidCollection Value => (GuidCollection)this;

        /// <inheritdoc/>
        public static implicit operator UuidCollection(Guid[] values)
        {
            return values != null ? [.. values.Select(g => new Uuid(g))] : [];
        }

        /// <inheritdoc/>
        public static implicit operator UuidCollection(GuidCollection values)
        {
            return values != null ? [.. values.Select(g => new Uuid(g))] : [];
        }

        /// <inheritdoc/>
        public static implicit operator UuidCollection(Uuid[] values)
        {
            return values != null ? [.. values.Select(g => g.Value)] : [];
        }

        /// <inheritdoc/>
        public static implicit operator GuidCollection(UuidCollection values)
        {
            return values != null ? [.. values.Select(g => g.Value)] : [];
        }

        /// <inheritdoc/>
        public virtual object Clone()
        {
            return MemberwiseClone();
        }

        /// <inheritdoc/>
        public new object MemberwiseClone()
        {
            return new UuidCollection(this);
        }
    }
}
