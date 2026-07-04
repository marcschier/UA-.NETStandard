using System;
using System.Security.Cryptography;

namespace Opc.Ua.Core.Experimental
{
    /// <summary>
    /// Computes compact schema identifiers used by experimental encodings.
    /// </summary>
    public static class SchemaId
    {
        private const ulong RabinAvroEmpty = 0xC15D213AA4D7A795UL;

        private static readonly ulong[] s_rabinAvroTable = CreateRabinAvroTable();

        /// <summary>
        /// Computes the CRC-64-AVRO Rabin fingerprint for canonical schema bytes.
        /// </summary>
        public static ulong RabinCrc64Avro(ReadOnlySpan<byte> canonical)
        {
            ulong result = RabinAvroEmpty;

            for (int ii = 0; ii < canonical.Length; ii++)
            {
                result = (result >> 8) ^ s_rabinAvroTable[(byte)(result ^ canonical[ii])];
            }

            return result;
        }

        /// <summary>
        /// Builds the Avro single-object encoding prefix for a Rabin fingerprint.
        /// </summary>
        public static byte[] AvroSingleObjectPrefix(ulong fp)
        {
            byte[] prefix = new byte[10];
            prefix[0] = 0xC3;
            prefix[1] = 0x01;

            for (int ii = 0; ii < sizeof(ulong); ii++)
            {
                prefix[ii + 2] = (byte)(fp >> (8 * ii));
            }

            return prefix;
        }

        /// <summary>
        /// Computes the first bytes of the SHA-256 digest for canonical schema bytes.
        /// </summary>
        public static byte[] Sha256Id(ReadOnlySpan<byte> canonical, int nbytes = 8)
        {
            if (nbytes < 0 || nbytes > 32)
            {
                throw new ArgumentOutOfRangeException(nameof(nbytes), nbytes, "The identifier length must be between 0 and 32 bytes.");
            }

#if NET5_0_OR_GREATER
            byte[] hash = SHA256.HashData(canonical);
#else
            using SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(canonical.ToArray());
#endif
            if (nbytes == hash.Length)
            {
                return hash;
            }

            byte[] id = new byte[nbytes];
            Array.Copy(hash, id, nbytes);
            return id;
        }

        private static ulong[] CreateRabinAvroTable()
        {
            ulong[] table = new ulong[256];

            for (int ii = 0; ii < table.Length; ii++)
            {
                ulong fp = (ulong)ii;

                for (int jj = 0; jj < 8; jj++)
                {
                    fp = (fp >> 1) ^ (RabinAvroEmpty & (0UL - (fp & 1UL)));
                }

                table[ii] = fp;
            }

            return table;
        }
    }
}
