using System.Text;
using NUnit.Framework;

namespace Opc.Ua.Core.Experimental.Tests
{
    [TestFixture]
    public sealed class SchemaIdTests
    {
        [Test]
        public void AvroSingleObjectPrefixUsesMagicAndLittleEndianFingerprint()
        {
            byte[] prefix = SchemaId.AvroSingleObjectPrefix(0x0102030405060708UL);

            Assert.That(prefix, Is.EqualTo(new byte[] { 0xC3, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 }));
        }

        [Test]
        public void RabinCrc64AvroIsStableForSameCanonicalBytes()
        {
            byte[] canonical = Encoding.UTF8.GetBytes("""{"type":"record","name":"Stable","fields":[]}""");

            ulong first = SchemaId.RabinCrc64Avro(canonical);
            ulong second = SchemaId.RabinCrc64Avro(canonical);

            Assert.That(second, Is.EqualTo(first));
        }
    }
}

