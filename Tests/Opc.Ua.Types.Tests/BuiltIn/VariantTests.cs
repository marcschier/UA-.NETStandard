/* ========================================================================
 * Copyright (c) 2005-2018 The OPC Foundation, Inc. All rights reserved.
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
using NUnit.Framework;
using Opc.Ua.Tests;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace Opc.Ua.Types.Tests.BuiltIn
{
    /// <summary>
    /// Tests for the BuiltIn Types.
    /// </summary>
    [TestFixture]
    [Category("BuiltInType")]
    [SetCulture("en-us")]
    [SetUICulture("en-us")]
    [Parallelizable]
    public class VariantTests
    {
        [DatapointSource]
        public static readonly BuiltInType[] BuiltInTypes =
#if NET8_0_OR_GREATER && !NET_STANDARD_TESTS
        [
            .. Enum.GetValues<BuiltInType>()
#else
        [
            .. Enum.GetValues(typeof(BuiltInType))
                .Cast<BuiltInType>()
#endif
                .Where(b => b is > BuiltInType.Null and < BuiltInType.DataValue)
        ];

        /// <summary>
        /// Variant constructor.
        /// </summary>
        [Test]
        public void VariantConstructor()
        {
            var uuid = new Uuid(Guid.NewGuid());
            var variant1 = new Variant(uuid);
            Assert.AreEqual(BuiltInType.Guid, variant1.TypeInfo.BuiltInType);
        }

        /// <summary>
        /// Initialize Variant with Enum array.
        /// </summary>
        [Test]
        public void VariantFromEnumArray()
        {
            // Enum Scalar
            _ = new Variant(DayOfWeek.Monday);

            _ = new Variant(
                DayOfWeek.Monday,
                TypeInfo.Scalars.Enumeration);

            // Enum array
            var days = new DayOfWeek[] { DayOfWeek.Monday, DayOfWeek.Tuesday };

            _ = new Variant(days, TypeInfo.Arrays.Enumeration);

            _ = new Variant(days);

            // Enum 2-dim Array
            var daysdays = new DayOfWeek[,]
            {
                { DayOfWeek.Monday, DayOfWeek.Tuesday },
                { DayOfWeek.Monday, DayOfWeek.Tuesday }
            };

            _ = new Variant(
                daysdays,
                TypeInfo.Create(BuiltInType.Enumeration, ValueRanks.TwoDimensions));

            // not supported
            // Variant variant6 = new Variant(daysdays);
        }
    }
}
