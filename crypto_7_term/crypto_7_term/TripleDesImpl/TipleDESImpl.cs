using crypto_7_term.DesImp;
using crypto_7_term.interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace crypto_7_term.TripleDesImpl
{
    /// <summary>
    /// Реализация Triple DES 
    /// </summary>
    public class TripleDES : CipherBase
    {
        private readonly DES des = new DES();
        public override int BlockSize => 8; // 64 бита

        public override byte[] EncryptBlock(byte[] block, byte[] key)
        {
            if (key.Length != 16 && key.Length != 24)
                throw new ArgumentException("TripleDES key must be 16 or 24 bytes");

            byte[] key1 = new byte[8];
            byte[] key2 = new byte[8];
            byte[] key3 = new byte[8];

            if (key.Length == 16)
            {
                // 2-key TripleDES: K1, K2, K1
                Array.Copy(key, 0, key1, 0, 8);
                Array.Copy(key, 8, key2, 0, 8);
                key3 = key1;
            }
            else
            {
                // 3-key TripleDES: K1, K2, K3
                Array.Copy(key, 0, key1, 0, 8);
                Array.Copy(key, 8, key2, 0, 8);
                Array.Copy(key, 16, key3, 0, 8);
            }

            // Encrypt(K1) -> Decrypt(K2) -> Encrypt(K3)
            byte[] step1 = des.EncryptBlock(block, key1);
            byte[] step2 = des.DecryptBlock(step1, key2);
            return des.EncryptBlock(step2, key3);
        }

        public override byte[] DecryptBlock(byte[] block, byte[] key)
        {
            if (key.Length != 16 && key.Length != 24)
                throw new ArgumentException("TripleDES key must be 16 or 24 bytes");

            byte[] key1 = new byte[8];
            byte[] key2 = new byte[8];
            byte[] key3 = new byte[8];

            if (key.Length == 16)
            {
                // 2-key TripleDES: K1, K2, K1
                Array.Copy(key, 0, key1, 0, 8);
                Array.Copy(key, 8, key2, 0, 8);
                key3 = key1;
            }
            else
            {
                // 3-key TripleDES: K1, K2, K3
                Array.Copy(key, 0, key1, 0, 8);
                Array.Copy(key, 8, key2, 0, 8);
                Array.Copy(key, 16, key3, 0, 8);
            }

            // Decrypt(K3) -> Encrypt(K2) -> Decrypt(K1)
            byte[] step1 = des.DecryptBlock(block, key3);
            byte[] step2 = des.EncryptBlock(step1, key2);
            return des.DecryptBlock(step2, key1);
        }
    }
}
