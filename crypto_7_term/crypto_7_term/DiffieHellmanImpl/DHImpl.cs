using crypto_7_term.Primes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


namespace crypto_7_term.DiffieHellmanImpl
{
    /// <summary>
    /// Участник протокола Диффи-Хеллмана
    /// </summary>
    public class DiffieHellmanParticipant
    {
        private BigInteger _privateKey;    // Закрытый ключ (a или b)
        private BigInteger _publicKey;     // Открытый ключ (A = g^a mod p или B = g^b mod p)
        private BigInteger _sharedSecret;  // Общий секрет (K = B^a mod p = A^b mod p)

        // Публичные параметры 
        public BigInteger P { get; }       // Большое простое число
        public BigInteger G { get; }       // Первообразный корень по модулю p

        /// <summary>
        /// Создание участника с заданными параметрами
        /// </summary>
        public DiffieHellmanParticipant(BigInteger p, BigInteger g)
        {
            if (!PrimeGenerator.IsProbablePrime(p, 20))
                throw new ArgumentException("P must be a prime number");

            P = p;
            G = g;
            GeneratePrivateKey();
            GeneratePublicKey();
        }

        /// <summary>
        /// Создание участника со стандартными параметрами 
        /// </summary>
        public DiffieHellmanParticipant() : this(GetStandardP(), 2)
        {
        }

        /// <summary>
        /// Генерация закрытого ключа
        /// </summary>
        private void GeneratePrivateKey()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                int byteCount = P.ToByteArray().Length;
                byte[] bytes = new byte[byteCount + 1]; 

                BigInteger privateKey;
                do
                {
                    rng.GetBytes(bytes);
                    bytes[bytes.Length - 1] &= 0x7F;

                    privateKey = new BigInteger(bytes);
                    privateKey %= (P - 3); 
                    privateKey += 2;       

                } while (privateKey >= P - 1 || privateKey < 2);

                _privateKey = privateKey;
            }
        }


        /// <summary>
        /// Генерация открытого ключа
        /// </summary>
        private void GeneratePublicKey()
        {
            _publicKey = BigInteger.ModPow(G, _privateKey, P);
        }

        /// <summary>
        /// Вычисление общего секрета на основе открытого ключа другого участника
        /// </summary>
        public void ComputeSharedSecret(BigInteger otherPublicKey)
        {
            if (otherPublicKey <= 1 || otherPublicKey >= P - 1)
                throw new ArgumentException("Invalid public key");

            _sharedSecret = BigInteger.ModPow(otherPublicKey, _privateKey, P);
        }

        public BigInteger GetPublicKey() => _publicKey;
        public BigInteger GetSharedSecret() => _sharedSecret;

        /// <summary>
        /// Генерация симметричного ключа из общего секрета
        /// </summary>
        public byte[] DeriveSymmetricKey(int keySizeBytes = 32)
        {
            if (_sharedSecret == 0)
                throw new InvalidOperationException("Shared secret not computed yet");

            using (var sha256 = SHA256.Create())
            {
                byte[] secretBytes = _sharedSecret.ToByteArray(isUnsigned: true, isBigEndian: false);
                byte[] hash = sha256.ComputeHash(secretBytes);

                if (keySizeBytes <= 32)
                {
                    byte[] key = new byte[keySizeBytes];
                    Array.Copy(hash, key, keySizeBytes);
                    return key;
                }
                else
                {
                    using (var hmac = new HMACSHA256(secretBytes))
                    {
                        byte[] key = new byte[keySizeBytes];
                        byte[] counter = new byte[1] { 0 };

                        for (int i = 0; i < keySizeBytes; i += 32)
                        {
                            counter[0] = (byte)(i / 32);
                            byte[] chunk = hmac.ComputeHash(counter);
                            int bytesToCopy = Math.Min(32, keySizeBytes - i);
                            Array.Copy(chunk, 0, key, i, bytesToCopy);
                        }
                        return key;
                    }
                }
            }
        }

        /// <summary>
        /// Стандартное простое число из RFC 3526 (2048 бит)
        /// </summary>
        public static BigInteger GetStandardP()
        {
            string hexP =
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
                "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
                "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
                "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
                "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
                "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

            return BigInteger.Parse("00" + hexP, System.Globalization.NumberStyles.HexNumber);
        }

        /// <summary>
        /// Шифрование AES
        /// </summary>
        public static byte[] EncryptWithAES(string plaintext, byte[] key)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw new ArgumentException("Текст для шифрования не может быть пустым");
            if (key == null || key.Length != 32)
                throw new ArgumentException("Ключ должен быть 256-битным (32 байта)");

            byte[] encrypted;

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV(); 

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                    byte[] ciphertextBytes = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);

                    encrypted = new byte[aes.IV.Length + ciphertextBytes.Length];
                    Buffer.BlockCopy(aes.IV, 0, encrypted, 0, aes.IV.Length);
                    Buffer.BlockCopy(ciphertextBytes, 0, encrypted, aes.IV.Length, ciphertextBytes.Length);
                }
            }

            return encrypted;
        }

        /// <summary>
        /// Дешифрование AES
        /// </summary>

        public static string DecryptWithAES(byte[] ciphertext, byte[] key)
        {
            if (ciphertext == null || ciphertext.Length < 16)
                throw new ArgumentException("Некорректный зашифрованный текст");
            if (key == null || key.Length != 32)
                throw new ArgumentException("Ключ должен быть 256-битным (32 байта)");

            string decrypted;

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                byte[] iv = new byte[16];
                Buffer.BlockCopy(ciphertext, 0, iv, 0, iv.Length);
                aes.IV = iv;

                byte[] ciphertextWithoutIv = new byte[ciphertext.Length - iv.Length];
                Buffer.BlockCopy(ciphertext, iv.Length, ciphertextWithoutIv, 0, ciphertextWithoutIv.Length);

                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    byte[] plaintextBytes = decryptor.TransformFinalBlock(ciphertextWithoutIv, 0, ciphertextWithoutIv.Length);
                    decrypted = Encoding.UTF8.GetString(plaintextBytes);
                }
            }

            return decrypted;
        }
    }
}