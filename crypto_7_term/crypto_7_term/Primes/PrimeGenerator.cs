using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace crypto_7_term.Primes
{
    public class PrimeGenerator
    {
        private static readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        /// <summary>
        /// Генерация простого числа заданной битовой длины
        /// </summary>
        public static BigInteger GeneratePrime(int bitLength)
        {
            while (true)
            {
                BigInteger number = GenerateRandomBigInteger(bitLength);

                // Старший и младший бит установка в 1
                number |= (BigInteger.One << (bitLength - 1)) | BigInteger.One;

                if (IsProbablePrime(number, 10))
                {
                    return number;
                }
            }
        }

        /// <summary>
        /// Генерация случайного BigInteger
        /// </summary>
        private static BigInteger GenerateRandomBigInteger(int bitLength)
        {
            byte[] bytes = new byte[bitLength / 8 + 1];
            rng.GetBytes(bytes);
            bytes[bytes.Length - 1] &= 0x7F; 
            return new BigInteger(bytes);
        }


        /// <summary>
        /// Тест Миллера-Рабина
        /// </summary>
        public static bool IsProbablePrime(BigInteger n, int k)
        {
            if (n <= 1) return false;
            if (n <= 3) return true;
            if (n % 2 == 0) return false;

            // n-1 = 2^r * d
            BigInteger d = n - 1;
            int r = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                r++;
            }

            for (int i = 0; i < k; i++)
            {
                BigInteger a = GenerateRandomBigInteger(n.ToByteArray().Length * 8 - 1) % (n - 4) + 2;
                BigInteger x = BigInteger.ModPow(a, d, n);

                if (x == 1 || x == n - 1)
                    continue;

                bool continueLoop = false;
                for (int j = 0; j < r - 1; j++)
                {
                    x = BigInteger.ModPow(x, 2, n);
                    if (x == n - 1)
                    {
                        continueLoop = true;
                        break;
                    }
                }

                if (continueLoop) continue;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Расширенный алгоритм Евклида
        /// </summary>
        private static (BigInteger, BigInteger, BigInteger) ExtendedEuclidean(BigInteger a, BigInteger b)
        {
            if (b == 0)
                return (a, 1, 0);

            var (gcd, x1, y1) = ExtendedEuclidean(b, a % b);
            BigInteger x = y1;
            BigInteger y = x1 - (a / b) * y1;

            return (gcd, x, y);
        }

        /// <summary>
        /// Генерация ключей с защитой от атаки Винера
        /// </summary> 
        public static (BigInteger n, BigInteger e, BigInteger d) GenerateKeys(int keySize = 2048)
        {
            if (keySize < 1024)
                throw new ArgumentException("Key size should be at least 1024 bits for security");

            BigInteger p = GeneratePrime(keySize / 2);
            BigInteger q = GeneratePrime(keySize / 2);

            while (p == q)
            {
                q = GeneratePrime(keySize / 2);
            }

            BigInteger n = p * q;
            BigInteger phi = (p - 1) * (q - 1);

            BigInteger e = 65537; // Стандартное значение открытой экспоненты

            while (BigInteger.GreatestCommonDivisor(e, phi) != 1)
            {
                e = GenerateRandomBigInteger(32) % (phi - 3) + 3;
            }

            var (gcd, x, _) = ExtendedEuclidean(e, phi);
            BigInteger d = (x % phi + phi) % phi;

            // Проверка на уязвимость к атаке Винера
            if (d.ToByteArray().Length * 8 < keySize / 4)
            {
                return GenerateKeys(keySize);
            }

            return (n, e, d);
        }
    }
}
