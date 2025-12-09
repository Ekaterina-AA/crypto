using crypto_7_term.DesImp;
using crypto_7_term.interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace crypto_7_term.DealImpl
{
    /// <summary>
    /// Реализация алгоритма DEAL (Data Encryption Algorithm with Larger blocks)
    /// </summary>
    public class DEAL : CipherBase
    {
        private readonly DES des = new DES();
        public override int BlockSize => 16; // 128 бит

        private byte[][] GenerateRoundKeys(byte[] key, int rounds)
        {
            int keyLength = key.Length;
            byte[][] roundKeys = new byte[rounds][];

            // DES в режиме CBC для генерации раундовых ключей
            byte[] temp = new byte[8];
            Array.Copy(key, 0, temp, 0, Math.Min(8, keyLength));

            for (int i = 0; i < rounds; i++)
            {
                roundKeys[i] = new byte[8];
                byte[] keyMaterial = GetSubKey(key, i);
                temp = des.EncryptBlock(temp, keyMaterial);
                Array.Copy(temp, 0, roundKeys[i], 0, 8);
            }

            return roundKeys;
        }

        private byte[] GetSubKey(byte[] key, int index)
        {
            byte[] subKey = new byte[8];
            int offset = (index * 8) % key.Length;
            for (int i = 0; i < 8; i++)
            {
                subKey[i] = key[(offset + i) % key.Length];
            }
            return subKey;
        }

        public override byte[] EncryptBlock(byte[] block, byte[] key)
        {
            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes");

            int rounds = key.Length == 16 ? 6 : 8; 
            byte[][] roundKeys = GenerateRoundKeys(key, rounds);

            byte[] left = new byte[8];
            byte[] right = new byte[8];
            Array.Copy(block, 0, left, 0, 8);
            Array.Copy(block, 8, right, 0, 8);

            // Раунды DEAL
            for (int i = 0; i < rounds; i++)
            {
                // Шифр правой части
                byte[] encryptedRight = des.EncryptBlock(right, roundKeys[i]);

                // XOR с левой частью
                byte[] newLeft = new byte[8];
                for (int j = 0; j < 8; j++)
                {
                    newLeft[j] = (byte)(left[j] ^ encryptedRight[j]);
                }

                left = right;
                right = newLeft;
            }

            // Финальная перестановка
            byte[] result = new byte[16];
            Array.Copy(right, 0, result, 0, 8);  
            Array.Copy(left, 0, result, 8, 8);   
            return result;
        }

        public override byte[] DecryptBlock(byte[] block, byte[] key)
        {
            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes");

            int rounds = key.Length == 16 ? 6 : 8;
            byte[][] roundKeys = GenerateRoundKeys(key, rounds);

            // Обратный порядок раундовых ключей
            Array.Reverse(roundKeys);

            byte[] left = new byte[8];
            byte[] right = new byte[8];
            Array.Copy(block, 0, right, 0, 8);  
            Array.Copy(block, 8, left, 0, 8);   

            // Обратные раунды DEAL
            for (int i = 0; i < rounds; i++)
            {
                byte[] encryptedLeft = des.EncryptBlock(left, roundKeys[i]);

                byte[] newRight = new byte[8];
                for (int j = 0; j < 8; j++)
                {
                    newRight[j] = (byte)(right[j] ^ encryptedLeft[j]);
                }

                right = left;
                left = newRight;
            }

            byte[] result = new byte[16];
            Array.Copy(right, 0, result, 0, 8);  
            Array.Copy(left, 0, result, 8, 8);   
            return result;
        }
    }
}