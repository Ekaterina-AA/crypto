using crypto_7_term.FileProcessor;
using crypto_7_term.interfaces;
using crypto_7_term.ModesProcessor;
using crypto_7_term.Primes;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace crypto_7_term.rsa
{
    public class RSAImpl
    {
        #region Атака Винера
        public class WienerAttack
        {
            /// <summary>
            /// Разложение непрерывных дробей
            /// </summary>
            private static List<BigInteger> ContinuedFraction(BigInteger a, BigInteger b)
            {
                var result = new List<BigInteger>();
                while (b != 0)
                {
                    result.Add(a / b);
                    (a, b) = (b, a % b);
                }
                return result;
            }

            /// <summary>
            /// Вычисление подходящих дробей
            /// </summary>
            private static List<(BigInteger, BigInteger)> Convergents(List<BigInteger> fraction)
            {
                var convergents = new List<(BigInteger, BigInteger)>();

                if (fraction.Count == 0) return convergents;

                BigInteger h0 = 0, h1 = 1;
                BigInteger k0 = 1, k1 = 0;

                for (int i = 0; i < fraction.Count; i++)
                {
                    BigInteger a = fraction[i];
                    BigInteger h2 = a * h1 + h0;
                    BigInteger k2 = a * k1 + k0;

                    convergents.Add((h2, k2));

                    (h0, k0) = (h1, k1);
                    (h1, k1) = (h2, k2);
                }

                return convergents;
            }

            /// <summary>
            /// Проверка, является ли кандидат секретным ключом
            /// </summary>
            private static bool CheckPrivateKey(BigInteger n, BigInteger e, BigInteger d)
            {
                // Проверяем, что e*d ≡ 1 mod φ(n)
                BigInteger k = (e * d - 1);

                // Пробуем факторизовать n используя d
                for (BigInteger g = 2; g < 100; g++)
                {
                    BigInteger m = BigInteger.ModPow(g, e * d, n);
                    if (m == g)
                    {
                        return true;
                    }
                }
                return false;
            }

            /// <summary>
            /// Атака Винера
            /// </summary>
            public static BigInteger? Attack(BigInteger n, BigInteger e)
            {
                var fraction = ContinuedFraction(e, n);
                var convergents = Convergents(fraction);

                foreach (var (k, d) in convergents)
                {
                    if (k == 0) continue;

                    // φ(n) = (ed - 1)/k
                    if ((e * d - 1) % k != 0) continue;

                    BigInteger phi = (e * d - 1) / k;

                    // x^2 - (n - phi + 1)x + n = 0
                    BigInteger b = n - phi + 1;
                    BigInteger discriminant = b * b - 4 * n;

                    if (discriminant < 0) continue;

                    // Является ли дискриминант полным квадратом
                    BigInteger sqrtDisc = Sqrt(discriminant);
                    if (sqrtDisc * sqrtDisc != discriminant) continue;

                    if (CheckPrivateKey(n, e, d))
                    {
                        return d;
                    }
                }

                return null;
            }

            private static BigInteger Sqrt(BigInteger n)
            {
                if (n < 0) throw new ArgumentException("Negative number");
                if (n == 0) return 0;

                BigInteger x = n;
                BigInteger y = (x + n / x) / 2;
                while (y < x)
                {
                    x = y;
                    y = (x + n / x) / 2;
                }
                return x;
            }
        }
        #endregion

        #region Реализация  RSA
        public class RSA
        {
            public BigInteger N { get; private set; }
            public BigInteger E { get; private set; }
            public BigInteger D { get; private set; }

            public RSA(int keySize = 2048)
            {
                var (n, e, d) = PrimeGenerator.GenerateKeys(keySize);
                N = n;
                E = e;
                D = d;
            }

            public RSA(BigInteger n, BigInteger e, BigInteger d = default)
            {
                N = n;
                E = e;
                D = d;
            }

            /// <summary>
            /// Шифрование блока
            /// </summary>
            public byte[] EncryptBlock(byte[] data)
            {
                int modulusSize = N.ToByteArray(true, true).Length; 
                if (data.Length != modulusSize)
                    throw new ArgumentException(
                        $"Data must be exactly modulus size for RSA encryption. " +
                        $"Expected: {modulusSize}, Actual: {data.Length}");

                BigInteger m = new BigInteger(data, isUnsigned: true, isBigEndian: true);
                BigInteger c = BigInteger.ModPow(m, E, N);

                byte[] encrypted =  c.ToByteArray(isUnsigned: true, isBigEndian: true);
                if (encrypted.Length < modulusSize)
                {
                    byte[] result = new byte[modulusSize];
                    Array.Copy(encrypted, 0, result, modulusSize - encrypted.Length, encrypted.Length);
                    return result;
                }
                else if (encrypted.Length == modulusSize)
                {
                    return encrypted;
                }
                else
                {
                    throw new CryptographicException($"Encrypted result is larger than modulus. Expected max: {modulusSize}, Actual: {encrypted.Length}");
                }
            }

            /// <summary>
            /// Дешифрование блока
            /// </summary>
            public byte[] DecryptBlock(byte[] data)
            {
                if (D == BigInteger.Zero)
                    throw new InvalidOperationException(
                        "Private key is not available. Cannot decrypt without private key.");

                int modulusSize = N.ToByteArray(true, true).Length;

                if (data.Length != modulusSize)
                    throw new ArgumentException(
                        $"Encrypted data must be exactly modulus size. " +
                        $"Expected: {modulusSize} bytes, Actual: {data.Length} bytes");

                BigInteger c = new BigInteger(data, isUnsigned: true, isBigEndian: true);

                if (c >= N)
                    throw new CryptographicException("Encrypted data is larger than modulus N");

                BigInteger m = BigInteger.ModPow(c, D, N);

                byte[] decrypted = m.ToByteArray(isUnsigned: true, isBigEndian: true);

                if (decrypted.Length < modulusSize)
                {
                    byte[] result = new byte[modulusSize];
                    Array.Copy(decrypted, 0, result, modulusSize - decrypted.Length, decrypted.Length);
                    return result;
                }

                return decrypted;
            }

            /// <summary>
            /// Асинхронное шифрование файла
            /// </summary>
            public async Task EncryptFileAsync(string inputFile, string outputFile,
                                              CancellationToken cancellationToken = default)
            {
                int modulusSize = N.ToByteArray(true, true).Length; 
                int maxDataSize = modulusSize - 11; 

                if (!File.Exists(inputFile))
                    throw new FileNotFoundException($"Input file not found: {inputFile}");

                await using var inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read,
                                                             FileShare.Read, bufferSize: 4096, useAsync: true);
                await using var outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write,
                                                              FileShare.None, bufferSize: 4096, useAsync: true);

                byte[] buffer = new byte[maxDataSize];
                int bytesRead;
                long totalProcessed = 0;
                var fileInfo = new FileInfo(inputFile);
                long totalBytes = fileInfo.Length;

                while ((bytesRead = await inputStream.ReadAsync(buffer, 0, maxDataSize, cancellationToken)) > 0)
                {
                    byte[] block = new byte[bytesRead];
                    Array.Copy(buffer, 0, block, 0, bytesRead);

                    if (block.Length > maxDataSize)
                        throw new InvalidOperationException($"Block size {block.Length} exceeds maximum {maxDataSize}");

                    byte[] paddedBlock = AddPKCS1Padding(block, true);

                    byte[] encrypted = EncryptBlock(paddedBlock);


                    byte[] sizeBytes = BitConverter.GetBytes(encrypted.Length);
                    await outputStream.WriteAsync(sizeBytes, 0, sizeBytes.Length, cancellationToken);

                    if (encrypted.Length != modulusSize)
                        throw new CryptographicException($"Encrypted block size mismatch: expected {modulusSize}, got {encrypted.Length}");

                    await outputStream.WriteAsync(encrypted, 0, encrypted.Length, cancellationToken);

                    totalProcessed += bytesRead;
                }
            }

            /// <summary>
            /// Асинхронное дешифрование файла
            /// </summary>
            public async Task DecryptFileAsync(string inputFile, string outputFile,
                                              CancellationToken cancellationToken = default)
            {
                if (!File.Exists(inputFile))
                    throw new FileNotFoundException($"Input file not found: {inputFile}");

                await using var inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read,
                                                             FileShare.Read, bufferSize: 4096, useAsync: true);
                await using var outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write,
                                                              FileShare.None, bufferSize: 4096, useAsync: true);

                byte[] sizeBuffer = new byte[4];
                int modulusSize = N.ToByteArray(true, true).Length; 
                long totalBlocks = 0;

                while (await inputStream.ReadAsync(sizeBuffer, 0, 4, cancellationToken) == 4)
                {
                    totalBlocks++;

                    int encryptedBlockSize = BitConverter.ToInt32(sizeBuffer, 0);

                    if (encryptedBlockSize != modulusSize)
                    {
                        throw new CryptographicException(
                            $"Invalid encrypted block size at block {totalBlocks}: " +
                            $"expected {modulusSize}, got {encryptedBlockSize}");
                    }

                    if (encryptedBlockSize <= 0 || encryptedBlockSize > modulusSize * 2)
                    {
                        throw new CryptographicException($"Suspicious block size: {encryptedBlockSize}");
                    }

                    byte[] encryptedBlock = new byte[encryptedBlockSize];

                    int totalRead = 0;
                    while (totalRead < encryptedBlockSize)
                    {
                        int bytesRead = await inputStream.ReadAsync(
                            encryptedBlock,
                            totalRead,
                            encryptedBlockSize - totalRead,
                            cancellationToken);

                        if (bytesRead == 0)
                        {
                            throw new CryptographicException(
                                $"Unexpected end of file at block {totalBlocks}. " +
                                $"Expected {encryptedBlockSize} bytes, read {totalRead}");
                        }
                        totalRead += bytesRead;
                    }

                    byte[] decryptedWithPadding = DecryptBlock(encryptedBlock);

                    if (decryptedWithPadding.Length != modulusSize)
                    {
                        throw new CryptographicException(
                            $"Decrypted block size mismatch at block {totalBlocks}: " +
                            $"expected {modulusSize}, got {decryptedWithPadding.Length}");
                    }

                    byte[] originalBlock;
                    try
                    {
                        originalBlock = RemovePKCS1Padding(decryptedWithPadding, true);
                    }
                    catch (CryptographicException ex)
                    {
                        throw new CryptographicException($"Invalid padding in block {totalBlocks}");
                    }

                    await outputStream.WriteAsync(originalBlock, 0, originalBlock.Length, cancellationToken);
                }

                if (totalBlocks == 0)
                    throw new CryptographicException("No encrypted blocks found in file");
            }

            /// <summary>
            /// PKCS#1 padding
            /// </summary>
            private byte[] AddPKCS1Padding(byte[] data, bool forEncryption)
            {
                int modulusSize = N.ToByteArray(true, true).Length;
                int blockSize = modulusSize; 

                if (data == null) throw new ArgumentNullException(nameof(data));
                if (data.Length == 0) throw new ArgumentException("Data cannot be empty", nameof(data));

                int minRandomBytes = 8;
                int maxDataSize = blockSize - minRandomBytes - 3; // 3 = 00 + type + 00 separator

                if (data.Length > maxDataSize)
                {
                    throw new ArgumentException(
                        $"Data too long for PKCS#1 padding. Max: {maxDataSize}, Actual: {data.Length}");
                }

                byte[] padded = new byte[blockSize];
                padded[0] = 0x00; 
                padded[1] = forEncryption ? (byte)0x02 : (byte)0x01;
                int randomBytesCount = blockSize - data.Length - 3;

                if (randomBytesCount < minRandomBytes)
                    throw new InvalidOperationException($"Not enough space for random bytes: {randomBytesCount}");

                byte[] randomBytes = new byte[randomBytesCount];
                RandomNumberGenerator.Fill(randomBytes);

                for (int i = 0; i < randomBytes.Length; i++)
                {
                    int attempts = 0;
                    while (randomBytes[i] == 0 && attempts < 10)
                    {
                        byte[] temp = new byte[1];
                        RandomNumberGenerator.Fill(temp);
                        randomBytes[i] = temp[0];
                        attempts++;
                    }

                    if (randomBytes[i] == 0)
                    {
                        randomBytes[i] = 0x01;
                    }
                }

                Array.Copy(randomBytes, 0, padded, 2, randomBytes.Length);
                padded[2 + randomBytes.Length] = 0x00;
                Array.Copy(data, 0, padded, 3 + randomBytes.Length, data.Length);

                return padded;
            }

            private byte[] RemovePKCS1Padding(byte[] data, bool forEncryption)
            {
                if (data == null) throw new ArgumentNullException(nameof(data));

                // Минимальный размер для PKCS#1: 00 + type + 8 random + 00 + 1 data = 12 байт
                if (data.Length < 12)
                    throw new CryptographicException("Invalid PKCS#1 padding: data too short");

                if (data[0] != 0x00)
                    throw new CryptographicException("Invalid PKCS#1 padding: first byte must be 0x00");

                byte expectedType = forEncryption ? (byte)0x02 : (byte)0x01;
                if (data[1] != expectedType)
                    throw new CryptographicException($"Invalid PKCS#1 padding type: expected 0x{expectedType:X2}");

                int separatorIndex = -1;
                for (int i = 2; i < data.Length; i++)
                {
                    if (data[i] == 0x00)
                    {
                        separatorIndex = i;
                        break;
                    }
                    if (data[i] == 0x00 && i < separatorIndex)
                        throw new CryptographicException($"Invalid PKCS#1 padding: zero byte at position {i} before separator");
                }

                if (separatorIndex == -1)
                    throw new CryptographicException("Invalid PKCS#1 padding: separator 0x00 not found");

                int randomBytesCount = separatorIndex - 2;
                if (randomBytesCount < 8)
                    throw new CryptographicException($"Invalid PKCS#1 padding: insufficient random bytes ({randomBytesCount})");

                if (separatorIndex >= data.Length - 1)
                    throw new CryptographicException("Invalid PKCS#1 padding: no data after separator");

                int dataLength = data.Length - separatorIndex - 1;
                byte[] result = new byte[dataLength];
                Array.Copy(data, separatorIndex + 1, result, 0, dataLength);

                return result;
            }

            /// <summary>
            /// Экспорт ключей
            /// </summary>
            public string ExportPublicKey()
            {
                return Convert.ToBase64String(N.ToByteArray(true, true)) + ":" +
                       Convert.ToBase64String(E.ToByteArray(true, true));
            }

            public string ExportPrivateKey()
            {
                return Convert.ToBase64String(N.ToByteArray(true, true)) + ":" +
                       Convert.ToBase64String(E.ToByteArray(true, true)) + ":" +
                       Convert.ToBase64String(D.ToByteArray(true, true));
            }

            /// <summary>
            /// Импорт ключей
            /// </summary>
            public static RSA ImportPublicKey(string key)
            {
                var parts = key.Split(':');
                BigInteger n = new BigInteger(Convert.FromBase64String(parts[0]), true, true);
                BigInteger e = new BigInteger(Convert.FromBase64String(parts[1]), true, true);
                return new RSA(n, e);
            }

            public static RSA ImportPrivateKey(string key)
            {
                var parts = key.Split(':');
                BigInteger n = new BigInteger(Convert.FromBase64String(parts[0]), true, true);
                BigInteger e = new BigInteger(Convert.FromBase64String(parts[1]), true, true);
                BigInteger d = new BigInteger(Convert.FromBase64String(parts[2]), true, true);
                return new RSA(n, e, d);
            }
        }
        #endregion
    }
}
