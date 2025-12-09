using System;
using crypto_7_term.interfaces;

namespace crypto_7_term.DesImp
{
    /// <summary>
    /// Реализация алгоритма DES (Data Encryption Standard)
    /// </summary>
    public class DES : CipherBase
    {
        public override int BlockSize => 8; // 64 бита

        // Начальная перестановка IP
        private static readonly int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };

        // Конечная перестановка IP^-1
        private static readonly int[] IP_INV = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };

        // Расширение E
        private static readonly int[] E = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };

        // P-перестановка
        private static readonly int[] P = {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
        };

        // S-блоки
        private static readonly int[,,] SBoxes = {
            {
                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
            },
            {
                {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            {
                {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
            },
            {
                {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
            },
            {
                {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            },
            {
                {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
            },
            {
                {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
            },
            {
                {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
            }
        };

        // PC-1 перестановка для ключа
        private static readonly int[] PC1 = {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };

        // PC-2 перестановка для ключа
        private static readonly int[] PC2 = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };

        // Сдвиги для раундовых ключей
        private static readonly int[] ShiftBits = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        /// <summary>
        /// Проверка битов четности ключа
        /// </summary>
        private void ValidateKeyParity(byte[] key)
        {
            for (int i = 0; i < 8; i++)
            {
                int count = 0;
                for (int j = 0; j < 7; j++)
                {
                    if (((key[i] >> j) & 1) == 1)
                        count++;
                }

                bool parityBit = ((key[i] >> 7) & 1) == 1;
                bool shouldBeOdd = (count % 2) == 1;

                if (parityBit != shouldBeOdd)
                {
                    if (shouldBeOdd)
                        key[i] |= 0x80; // Устанавливаем бит четности
                    else
                        key[i] &= 0x7F; // Сбрасываем бит четности
                }
            }
        }

        /// <summary>
        /// Генерация раундовых ключей
        /// </summary>
        private byte[][] GenerateRoundKeys(byte[] key)
        {
            if (key.Length != 8)
                throw new ArgumentException("DES key must be 64 bits (8 bytes)");

            ValidateKeyParity(key);

            bool[] keyBits = ByteArrayToBits(key, 64);

            // Применение PC-1
            bool[] pc1Key = new bool[56];
            for (int i = 0; i < 56; i++)
            {
                pc1Key[i] = keyBits[PC1[i] - 1];
            }

            // Разделение на C0 и D0
            bool[] C = new bool[28];
            bool[] D = new bool[28];
            Array.Copy(pc1Key, 0, C, 0, 28);
            Array.Copy(pc1Key, 28, D, 0, 28);

            // Генерация 16 раундовых ключей
            byte[][] roundKeys = new byte[16][];

            for (int round = 0; round < 16; round++)
            {
                // Сдвиг C и D
                C = LeftShift(C, ShiftBits[round]);
                D = LeftShift(D, ShiftBits[round]);

                // Объединение C и D
                bool[] CD = new bool[56];
                Array.Copy(C, 0, CD, 0, 28);
                Array.Copy(D, 0, CD, 28, 28);

                // Применение PC-2
                bool[] pc2Key = new bool[48];
                for (int i = 0; i < 48; i++)
                {
                    pc2Key[i] = CD[PC2[i] - 1];
                }

                roundKeys[round] = BitsToByteArray(pc2Key);
            }

            return roundKeys;
        }

        /// <summary>
        /// Циклический сдвиг влево
        /// </summary>
        private bool[] LeftShift(bool[] bits, int shift)
        {
            bool[] result = new bool[bits.Length];
            for (int i = 0; i < bits.Length; i++)
            {
                int sourceIndex = (i + shift) % bits.Length;
                result[i] = bits[sourceIndex];
            }
            return result;
        }

        /// <summary>
        /// Функция Фейстеля
        /// </summary>
        private bool[] FeistelFunction(bool[] Rbits, byte[] roundKey)
        {
            // Расширение E (32 бита → 48 бит)
            bool[] expanded = new bool[48];
            for (int i = 0; i < 48; i++)
            {
                expanded[i] = Rbits[E[i] - 1];
            }

            // XOR с ключом раунда
            bool[] xored = new bool[48];
            bool[] keyBits = ByteArrayToBits(roundKey, 48);

            for (int i = 0; i < 48; i++)
            {
                xored[i] = expanded[i] ^ keyBits[i];
            }

            // S-блоки (8 S-блоков по 6 бит → 4 бита каждый)
            bool[] substituted = new bool[32];
            for (int i = 0; i < 8; i++)
            {
                // 6 бит для текущего S-блока
                int blockStart = i * 6;

                // Вычисление строки первый и последний биты
                int row = (xored[blockStart] ? 2 : 0) | (xored[blockStart + 5] ? 1 : 0);

                // Вычисление столбца 4 средних бита
                int col = (xored[blockStart + 1] ? 8 : 0) |
                          (xored[blockStart + 2] ? 4 : 0) |
                          (xored[blockStart + 3] ? 2 : 0) |
                          (xored[blockStart + 4] ? 1 : 0);

                // значение из S-блока (4 бита)
                int value = SBoxes[i, row, col];

                // Запись 4 бит (старший бит первый)
                for (int j = 0; j < 4; j++)
                {
                    substituted[i * 4 + j] = ((value >> (3 - j)) & 1) == 1;
                }
            }

            // Перестановка P
            bool[] result = new bool[32];
            for (int i = 0; i < 32; i++)
            {
                result[i] = substituted[P[i] - 1];
            }

            return result;
        }

        /// <summary>
        /// Основной процесс шифрования/дешифрования DES
        /// </summary>
        private byte[] DESProcess(byte[] block, byte[] key, bool encrypt)
        {
            if (block.Length != 8)
                throw new ArgumentException("DES block must be 64 bits (8 bytes)");

            byte[][] roundKeys = GenerateRoundKeys(key);

            if (!encrypt)
            {
                Array.Reverse(roundKeys);
            }

            bool[] blockBits = ByteArrayToBits(block, 64);

            // Начальная перестановка IP
            bool[] permuted = new bool[64];
            for (int i = 0; i < 64; i++)
            {
                permuted[i] = blockBits[IP[i] - 1];
            }

            // Разделение на L0 и R0 (32 бита каждый)
            bool[] Lbits = new bool[32];
            bool[] Rbits = new bool[32];
            Array.Copy(permuted, 0, Lbits, 0, 32);
            Array.Copy(permuted, 32, Rbits, 0, 32);

            // 16 раундов Фейстеля
            for (int round = 0; round < 16; round++)
            {
                // текущий R как новый L
                bool[] newLbits = Rbits;

                // F(R, K)
                bool[] fResult = FeistelFunction(Rbits, roundKeys[round]);

                // новый R: L XOR F(R, K)
                bool[] newRbits = new bool[32];
                for (int i = 0; i < 32; i++)
                {
                    newRbits[i] = Lbits[i] ^ fResult[i];
                }

                // Обновление L и R для следующего раунда
                Lbits = newLbits;
                Rbits = newRbits;
            }

            // Объединение R16 + L16 
            bool[] finalBits = new bool[64];
            Array.Copy(Rbits, 0, finalBits, 0, 32);  // R16 первые
            Array.Copy(Lbits, 0, finalBits, 32, 32); // L16 последние

            // Обратная начальная перестановка IP⁻¹
            bool[] ipInvBits = new bool[64];
            for (int i = 0; i < 64; i++)
            {
                ipInvBits[i] = finalBits[IP_INV[i] - 1];
            }

            return BitsToByteArray(ipInvBits);
        }

        /// <summary>
        /// Преобразование массива байтов в массив битов
        /// </summary>
        private bool[] ByteArrayToBits(byte[] bytes, int bitLength)
        {
            bool[] bits = new bool[bitLength];
            for (int i = 0; i < bitLength; i++)
            {
                int byteIndex = i / 8;
                int bitIndex = 7 - (i % 8); // Старший бит первый
                bits[i] = ((bytes[byteIndex] >> bitIndex) & 1) == 1;
            }
            return bits;
        }

        /// <summary>
        /// Преобразование массива битов в массив байтов
        /// </summary>
        private byte[] BitsToByteArray(bool[] bits)
        {
            return BitsToByteArray(bits, bits.Length);
        }

        /// <summary>
        /// Преобразование массива битов в массив байтов
        /// </summary>
        private byte[] BitsToByteArray(bool[] bits, int bitLength)
        {
            if (bits.Length < bitLength)
                throw new ArgumentException("Bits array is too short");

            int byteCount = (bitLength + 7) / 8;
            byte[] bytes = new byte[byteCount];

            for (int i = 0; i < bitLength; i++)
            {
                if (bits[i])
                {
                    int byteIndex = i / 8;
                    int bitIndex = 7 - (i % 8);
                    bytes[byteIndex] |= (byte)(1 << bitIndex);
                }
            }

            return bytes;
        }

        /// <summary>
        /// Шифрование блока
        /// </summary>
        public override byte[] EncryptBlock(byte[] block, byte[] key)
        {
            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes");
            if (key.Length != 8)
                throw new ArgumentException("DES key must be 8 bytes");

            return DESProcess(block, key, true);
        }

        /// <summary>
        /// Дешифрование блока
        /// </summary>
        public override byte[] DecryptBlock(byte[] block, byte[] key)
        {
            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes");
            if (key.Length != 8)
                throw new ArgumentException("DES key must be 8 bytes");

            return DESProcess(block, key, false);
        }
    }
}