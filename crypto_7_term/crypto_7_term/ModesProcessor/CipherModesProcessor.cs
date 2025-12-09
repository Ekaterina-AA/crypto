using crypto_7_term.interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CipherMode = crypto_7_term.interfaces.CipherMode;
using PaddingMode = crypto_7_term.interfaces.PaddingMode;

namespace crypto_7_term.ModesProcessor
{
    /// <summary>
    /// Обработчик различных режимов шифрования
    /// </summary>
    public class CipherModeProcessor
    {
        private readonly IBlockCipher cipher;
        private readonly CipherMode mode;
        private readonly PaddingMode paddingMode;
        private byte[] iv;

        public CipherModeProcessor(IBlockCipher cipher, CipherMode mode, PaddingMode paddingMode, byte[] iv = null)
        {
            this.cipher = cipher;
            this.mode = mode;
            this.paddingMode = paddingMode;
            this.iv = iv ?? GenerateIV();
        }

        private byte[] GenerateIV()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var iv = new byte[cipher.BlockSize];
                rng.GetBytes(iv);
                return iv;
            }
        }

        /// <summary>
        /// Шифрование данных
        /// </summary>
        public byte[] Encrypt(byte[] data, byte[] key)
        {
            byte[] paddedData = ApplyPadding(data);

            return mode switch
            {
                CipherMode.ECB => EncryptECB(paddedData, key),
                CipherMode.CBC => EncryptCBC(paddedData, key),
                CipherMode.PCBC => EncryptPCBC(paddedData, key),
                CipherMode.CFB => EncryptCFB(paddedData, key),
                CipherMode.OFB => EncryptOFB(paddedData, key),
                CipherMode.CTR => EncryptCTR(paddedData, key),
                CipherMode.RandomDelta => EncryptRandomDelta(paddedData, key),
                _ => throw new ArgumentException($"Unsupported cipher mode: {mode}")
            };
        }

        /// <summary>
        /// Дешифрование данных
        /// </summary>
        public byte[] Decrypt(byte[] data, byte[] key)
        {
            if (data.Length % cipher.BlockSize != 0)
                throw new ArgumentException($"Data length must be multiple of block size ({cipher.BlockSize})");

            byte[] decryptedData = mode switch
            {
                CipherMode.ECB => DecryptECB(data, key),
                CipherMode.CBC => DecryptCBC(data, key),
                CipherMode.PCBC => DecryptPCBC(data, key),
                CipherMode.CFB => DecryptCFB(data, key),
                CipherMode.OFB => DecryptOFB(data, key),
                CipherMode.CTR => DecryptCTR(data, key),
                CipherMode.RandomDelta => DecryptRandomDelta(data, key),
                _ => throw new ArgumentException($"Unsupported cipher mode: {mode}")
            };

            return RemovePadding(decryptedData);
        }

        #region Cipher modes
        /// <summary>
        /// ECB (Electronic Codebook)
        /// </summary>
        private byte[] EncryptECB(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];

            Parallel.For(0, data.Length / cipher.BlockSize, i =>
            {
                int offset = i * cipher.BlockSize;
                byte[] block = new byte[cipher.BlockSize];
                Array.Copy(data, offset, block, 0, cipher.BlockSize);

                byte[] encrypted = cipher.EncryptBlock(block, key);
                Array.Copy(encrypted, 0, result, offset, cipher.BlockSize);
            });

            return result;
        }

        /// <summary>
        /// ECB (Electronic Codebook)
        /// </summary>
        private byte[] DecryptECB(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];

            Parallel.For(0, data.Length / cipher.BlockSize, i =>
            {
                int offset = i * cipher.BlockSize;
                byte[] block = new byte[cipher.BlockSize];
                Array.Copy(data, offset, block, 0, cipher.BlockSize);

                byte[] decrypted = cipher.DecryptBlock(block, key);
                Array.Copy(decrypted, 0, result, offset, cipher.BlockSize);
            });

            return result;
        }

        /// <summary>
        /// CBC (Cipher Block Chaining)
        /// </summary>
        private byte[] EncryptCBC(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            byte[] previousBlock = new byte[cipher.BlockSize];
            Array.Copy(iv, previousBlock, cipher.BlockSize);

            for (int i = 0; i < data.Length; i += cipher.BlockSize)
            {
                byte[] block = new byte[cipher.BlockSize];
                Array.Copy(data, i, block, 0, cipher.BlockSize);

                // XOR с предыдущим зашифрованным блоком
                for (int j = 0; j < cipher.BlockSize; j++)
                    block[j] ^= previousBlock[j];

                byte[] encrypted = cipher.EncryptBlock(block, key);
                Array.Copy(encrypted, 0, result, i, cipher.BlockSize);
                Array.Copy(encrypted, previousBlock, cipher.BlockSize);
            }

            return result;
        }

        /// <summary>
        /// CBC (Cipher Block Chaining)
        /// </summary>
        private byte[] DecryptCBC(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            byte[] previousBlock = new byte[cipher.BlockSize];
            Array.Copy(iv, previousBlock, cipher.BlockSize);

            for (int i = 0; i < data.Length; i += cipher.BlockSize)
            {
                byte[] block = new byte[cipher.BlockSize];
                Array.Copy(data, i, block, 0, cipher.BlockSize);

                byte[] decrypted = cipher.DecryptBlock(block, key);

                // XOR с предыдущим зашифрованным блоком
                for (int j = 0; j < cipher.BlockSize; j++)
                    decrypted[j] ^= previousBlock[j];

                Array.Copy(decrypted, 0, result, i, cipher.BlockSize);
                Array.Copy(block, previousBlock, cipher.BlockSize);
            }

            return result;
        }

        /// <summary>
        /// PCBC (Propagating cipher block chaining)
        /// </summary>
        private byte[] EncryptPCBC(byte[] data, byte[] key)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (cipher == null)
                throw new InvalidOperationException("Cipher is not initialized");
            if (iv == null || iv.Length != cipher.BlockSize)
                throw new InvalidOperationException($"IV must be {cipher.BlockSize} bytes");

            if (data.Length % cipher.BlockSize != 0)
                throw new ArgumentException($"Data length ({data.Length}) must be multiple of block size ({cipher.BlockSize})");

            byte[] result = new byte[data.Length];

            byte[] previousPlain = new byte[cipher.BlockSize];
            byte[] previousCipher = new byte[cipher.BlockSize];

            Array.Copy(iv, 0, previousCipher, 0, cipher.BlockSize);

            for (int i = 0; i < data.Length; i += cipher.BlockSize)
            {
                byte[] currentPlain = new byte[cipher.BlockSize];
                Array.Copy(data, i, currentPlain, 0, cipher.BlockSize);

                // PCBC: XOR текущего открытого текста с XOR предыдущих блоков
                byte[] block = new byte[cipher.BlockSize];
                for (int j = 0; j < cipher.BlockSize; j++)
                {
                    block[j] = (byte)(currentPlain[j] ^ previousPlain[j] ^ previousCipher[j]);
                }

                byte[] encrypted = cipher.EncryptBlock(block, key);

                Array.Copy(encrypted, 0, result, i, cipher.BlockSize);

                Array.Copy(currentPlain, 0, previousPlain, 0, cipher.BlockSize);

                Array.Copy(encrypted, 0, previousCipher, 0, cipher.BlockSize);
            }

            return result;
        }

        /// <summary>
        /// PCBC (Propagating cipher block chaining)
        /// </summary>
        private byte[] DecryptPCBC(byte[] data, byte[] key)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (cipher == null)
                throw new InvalidOperationException("Cipher is not initialized");
            if (iv == null || iv.Length != cipher.BlockSize)
                throw new InvalidOperationException($"IV must be {cipher.BlockSize} bytes");

            if (data.Length % cipher.BlockSize != 0)
                throw new ArgumentException($"Data length ({data.Length}) must be multiple of block size ({cipher.BlockSize})");

            byte[] result = new byte[data.Length];

            byte[] previousPlain = new byte[cipher.BlockSize];
            byte[] previousCipher = new byte[cipher.BlockSize];

            Array.Copy(iv, 0, previousCipher, 0, cipher.BlockSize);

            for (int i = 0; i < data.Length; i += cipher.BlockSize)
            {
                byte[] currentCipher = new byte[cipher.BlockSize];
                Array.Copy(data, i, currentCipher, 0, cipher.BlockSize);

                byte[] decrypted = cipher.DecryptBlock(currentCipher, key);

                // PCBC: XOR дешифрованного текста с XOR предыдущих блоков
                byte[] plain = new byte[cipher.BlockSize];
                for (int j = 0; j < cipher.BlockSize; j++)
                {
                    plain[j] = (byte)(decrypted[j] ^ previousPlain[j] ^ previousCipher[j]);
                }

                Array.Copy(plain, 0, result, i, cipher.BlockSize);
                Array.Copy(plain, 0, previousPlain, 0, cipher.BlockSize);

                Array.Copy(currentCipher, 0, previousCipher, 0, cipher.BlockSize);
            }

            return result;
        }
        /// <summary>
        /// CFB (Cipher Feedback)
        /// </summary>
        private byte[] EncryptCFB(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            byte[] shiftRegister = new byte[cipher.BlockSize];
            Array.Copy(iv, shiftRegister, cipher.BlockSize);

            for (int i = 0; i < data.Length; i += cipher.BlockSize)
            {
                byte[] encrypted = cipher.EncryptBlock(shiftRegister, key);

                int blockSize = Math.Min(cipher.BlockSize, data.Length - i);
                for (int j = 0; j < blockSize; j++)
                {
                    result[i + j] = (byte)(data[i + j] ^ encrypted[j]);
                }

                // Обновление регистра сдвига
                if (blockSize == cipher.BlockSize)
                {
                    Array.Copy(result, i, shiftRegister, 0, cipher.BlockSize);
                }
                else
                {
                    // Частичный блок
                    Array.Copy(shiftRegister, blockSize, shiftRegister, 0, cipher.BlockSize - blockSize);
                    Array.Copy(result, i, shiftRegister, cipher.BlockSize - blockSize, blockSize);
                }
            }

            return result;
        }
        /// <summary>
        /// CFB (Cipher Feedback)
        /// </summary>
        private byte[] DecryptCFB(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            byte[] shiftRegister = new byte[cipher.BlockSize];
            Array.Copy(iv, shiftRegister, cipher.BlockSize);

            for (int i = 0; i < data.Length; i += cipher.BlockSize)
            {
                byte[] encrypted = cipher.EncryptBlock(shiftRegister, key);

                int blockSize = Math.Min(cipher.BlockSize, data.Length - i);
                for (int j = 0; j < blockSize; j++)
                {
                    result[i + j] = (byte)(data[i + j] ^ encrypted[j]);
                }

                // Обновление регистра сдвига
                if (blockSize == cipher.BlockSize)
                {
                    Array.Copy(data, i, shiftRegister, 0, cipher.BlockSize);
                }
                else
                {
                    Array.Copy(shiftRegister, blockSize, shiftRegister, 0, cipher.BlockSize - blockSize);
                    Array.Copy(data, i, shiftRegister, cipher.BlockSize - blockSize, blockSize);
                }
            }

            return result;
        }
        /// <summary>
        /// OFB (Output Feedback)
        /// </summary>
        private byte[] EncryptOFB(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            byte[] feedback = new byte[cipher.BlockSize];
            Array.Copy(iv, feedback, cipher.BlockSize);

            for (int i = 0; i < data.Length; i += cipher.BlockSize)
            {
                feedback = cipher.EncryptBlock(feedback, key);

                int blockSize = Math.Min(cipher.BlockSize, data.Length - i);
                for (int j = 0; j < blockSize; j++)
                {
                    result[i + j] = (byte)(data[i + j] ^ feedback[j]);
                }
            }

            return result;
        }
        /// <summary>
        /// OFB (Output Feedback)
        /// </summary>
        private byte[] DecryptOFB(byte[] data, byte[] key)
        {
            // OFB режим симметричен для шифрования/дешифрования
            return EncryptOFB(data, key);
        }

        /// <summary>
        /// CTR (Counter)
        /// </summary>
        private byte[] EncryptCTR(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            byte[] counter = new byte[cipher.BlockSize];
            Array.Copy(iv, counter, cipher.BlockSize);

            for (int i = 0; i < data.Length; i += cipher.BlockSize)
            {
                byte[] encryptedCounter = cipher.EncryptBlock(counter, key);

                int blockSize = Math.Min(cipher.BlockSize, data.Length - i);
                for (int j = 0; j < blockSize; j++)
                {
                    result[i + j] = (byte)(data[i + j] ^ encryptedCounter[j]);
                }

                counter = IncrementCounter(counter);
            }

            return result;
        }
        /// <summary>
        /// CTR (Counter)
        /// </summary>
        private byte[] DecryptCTR(byte[] data, byte[] key)
        {
            // CTR режим симметричен для шифрования/дешифрования
            return EncryptCTR(data, key);
        }

        /// <summary>
        /// Random Delta
        /// </summary>
        private byte[] EncryptRandomDelta(byte[] data, byte[] key)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] delta = new byte[cipher.BlockSize];
                rng.GetBytes(delta);

                byte[] result = new byte[data.Length + delta.Length];
                Array.Copy(delta, 0, result, 0, delta.Length);

                byte[] previousBlock = new byte[cipher.BlockSize];
                Array.Copy(delta, previousBlock, cipher.BlockSize);

                for (int i = 0; i < data.Length; i += cipher.BlockSize)
                {
                    byte[] block = new byte[cipher.BlockSize];
                    int blockSize = Math.Min(cipher.BlockSize, data.Length - i);
                    Array.Copy(data, i, block, 0, blockSize);

                    // XOR с предыдущим блоком и дельтой
                    for (int j = 0; j < cipher.BlockSize; j++)
                        block[j] ^= (byte)(previousBlock[j] ^ delta[j]);

                    byte[] encrypted = cipher.EncryptBlock(block, key);
                    Array.Copy(encrypted, 0, result, delta.Length + i, cipher.BlockSize);
                    Array.Copy(encrypted, previousBlock, cipher.BlockSize);
                }

                return result;
            }
        }
        /// <summary>
        /// Random Delta
        /// </summary>
        private byte[] DecryptRandomDelta(byte[] data, byte[] key)
        {
            if (data.Length < cipher.BlockSize)
                throw new ArgumentException("Data too short");

            byte[] delta = new byte[cipher.BlockSize];
            Array.Copy(data, 0, delta, 0, cipher.BlockSize);

            byte[] result = new byte[data.Length - cipher.BlockSize];
            byte[] previousBlock = new byte[cipher.BlockSize];
            Array.Copy(delta, previousBlock, cipher.BlockSize);

            for (int i = cipher.BlockSize; i < data.Length; i += cipher.BlockSize)
            {
                byte[] block = new byte[cipher.BlockSize];
                int blockSize = Math.Min(cipher.BlockSize, data.Length - i);
                Array.Copy(data, i, block, 0, blockSize);

                byte[] decrypted = cipher.DecryptBlock(block, key);

                // XOR с предыдущим блоком и дельтой
                for (int j = 0; j < cipher.BlockSize; j++)
                    decrypted[j] ^= (byte)(previousBlock[j] ^ delta[j]);

                Array.Copy(decrypted, 0, result, i - cipher.BlockSize, blockSize);
                Array.Copy(block, previousBlock, cipher.BlockSize);
            }

            return result;
        }

        #endregion

        #region Вспомогательные методы
        /// <summary>
        /// Добавление дополнения для данных
        /// </summary>
        private byte[] ApplyPadding(byte[] data)
        {
            int blockSize = cipher.BlockSize;
            int originalLength = data.Length;

            int padLength;
            if (originalLength % blockSize == 0)
            {
                padLength = blockSize;
            }
            else
            {
                padLength = blockSize - (originalLength % blockSize);
            }

            byte[] padded = new byte[originalLength + padLength];
            Buffer.BlockCopy(data, 0, padded, 0, originalLength);

            switch (paddingMode)
            {
                case PaddingMode.Zeros:
                    break;

                case PaddingMode.ANSIX923:
                    for (int i = originalLength; i < padded.Length - 1; i++)
                    {
                        padded[i] = 0x00; 
                    }
                    padded[padded.Length - 1] = (byte)padLength;
                    break;

                case PaddingMode.PKCS7:
                    for (int i = originalLength; i < padded.Length; i++)
                    {
                        padded[i] = (byte)padLength;
                    }
                    break;

                case PaddingMode.ISO10126:
                    using (var rng = RandomNumberGenerator.Create())
                    {
                        if (padLength > 1)
                        {
                            byte[] randomBytes = new byte[padLength - 1];
                            rng.GetBytes(randomBytes);
                            Buffer.BlockCopy(randomBytes, 0, padded, originalLength, randomBytes.Length);
                        }
                    }
                    padded[padded.Length - 1] = (byte)padLength;
                    break;
            }

            return padded;
        }

        /// <summary>
        /// Удаление дополнения из данных
        /// </summary>
        protected byte[] RemovePadding(byte[] data)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("Data cannot be null or empty");

            switch (paddingMode)
            {
                case PaddingMode.Zeros:
                    return RemoveZerosPadding(data);

                case PaddingMode.PKCS7:
                    return RemovePKCS7Padding(data);

                case PaddingMode.ANSIX923:
                    return RemoveANSIX923Padding(data);

                case PaddingMode.ISO10126:
                    return RemoveISO10126Padding(data);

                default:
                    throw new ArgumentException($"Unsupported padding mode: {paddingMode}");
            }
        }

        /// <summary>
        /// Удаление нулевого заполнения 
        /// </summary>
        private byte[] RemoveZerosPadding(byte[] data)
        {
            int i = data.Length - 1;
            while (i >= 0 && data[i] == 0)
                i--;

            if (i < 0)
                return new byte[0];

            byte[] result = new byte[i + 1];
            Buffer.BlockCopy(data, 0, result, 0, i + 1);
            return result;
        }

        /// <summary>
        /// Удаление PKCS7 
        /// </summary>
        private byte[] RemovePKCS7Padding(byte[] data)
        {
            int blockSize = cipher.BlockSize;
            if (data.Length < 1)
                throw new CryptographicException("Invalid padding: data too short");

            int padLength = data[data.Length - 1];

            if (padLength < 1 || padLength > data.Length || padLength > blockSize)
                throw new CryptographicException($"Invalid padding length: {padLength}");

            for (int i = data.Length - padLength; i < data.Length; i++)
            {
                if (data[i] != padLength)
                    throw new CryptographicException($"Invalid PKCS7 padding at position {i}");
            }

            byte[] result = new byte[data.Length - padLength];
            Buffer.BlockCopy(data, 0, result, 0, result.Length);
            return result;
        }

        /// <summary>
        /// Удаление ANSI X.923 
        /// </summary>
        private byte[] RemoveANSIX923Padding(byte[] data)
        {
            int blockSize = cipher.BlockSize;
            if (data.Length < 1)
                throw new CryptographicException("Invalid padding: data too short");

            int padLength = data[data.Length - 1];

            if (padLength < 1 || padLength > data.Length || padLength > blockSize)
                throw new CryptographicException($"Invalid padding length: {padLength}");

            for (int i = data.Length - padLength; i < data.Length - 1; i++)
            {
                if (data[i] != 0)
                    throw new CryptographicException($"Invalid ANSIX923 padding at position {i}");
            }

            byte[] result = new byte[data.Length - padLength];
            Buffer.BlockCopy(data, 0, result, 0, result.Length);
            return result;
        }

        /// <summary>
        /// Удаление ISO 10126 
        /// </summary>
        private byte[] RemoveISO10126Padding(byte[] data)
        {
            int blockSize = cipher.BlockSize;
            if (data.Length < 1)
                throw new CryptographicException("Invalid padding: data too short");

            int padLength = data[data.Length - 1];

            if (padLength < 1 || padLength > data.Length || padLength > blockSize)
                throw new CryptographicException($"Invalid padding length: {padLength}");

            byte[] result = new byte[data.Length - padLength];
            Buffer.BlockCopy(data, 0, result, 0, result.Length);
            return result;
        }

        private byte[] IncrementCounter(byte[] counter)
        {
            byte[] result = new byte[counter.Length];
            Array.Copy(counter, result, counter.Length);

            for (int i = result.Length - 1; i >= 0; i--)
            {
                if (++result[i] != 0)
                    break;
            }

            return result;
        }

        #endregion

        #region Асинхронное шифрование
        public byte[] GetIV() => iv;
        public int GetIVSize() => cipher.BlockSize;
        public void SetIV(byte[] newIv) => iv = newIv ?? throw new ArgumentNullException(nameof(newIv));

        /// <summary>
        /// Потоковое шифрование с поддержкой параллельной обработки
        /// </summary>
        public async Task<byte[]> EncryptStreamAsync(Stream inputStream, byte[] key, CancellationToken cancellationToken = default)
        {
            using (var memoryStream = new MemoryStream())
            {
                await ProcessStreamAsync(inputStream, memoryStream, key, encrypt: true, cancellationToken);
                return memoryStream.ToArray();
            }
        }

        /// <summary>
        /// Потоковое дешифрование с поддержкой параллельной обработки
        /// </summary>
        public async Task<byte[]> DecryptStreamAsync(Stream inputStream, byte[] key, CancellationToken cancellationToken = default)
        {
            using (var memoryStream = new MemoryStream())
            {
                await ProcessStreamAsync(inputStream, memoryStream, key, encrypt: false, cancellationToken);
                return memoryStream.ToArray();
            }
        }

        private async Task ProcessStreamAsync(
            Stream inputStream,
            Stream outputStream,
            byte[] key,
            bool encrypt,
            CancellationToken cancellationToken)
        {
            int blockSize = cipher.BlockSize;
            var buffer = new byte[blockSize * 1024]; // 1024 блоков за раз

            while (true)
            {
                int bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                if (bytesRead == 0)
                    break;

                int blocks = bytesRead / blockSize;
                if (bytesRead % blockSize != 0 && encrypt)
                    throw new ArgumentException("Input must be padded for encryption");

                byte[] processedData;
                processedData = await Task.Run(() =>
                    encrypt
                        ? Encrypt(buffer.Take(bytesRead).ToArray(), key)
                        : Decrypt(buffer.Take(bytesRead).ToArray(), key)
                );

                await outputStream.WriteAsync(processedData, 0, processedData.Length, cancellationToken);
            }
        }
        #endregion
    }
}
