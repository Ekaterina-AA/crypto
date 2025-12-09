using System.Text;
using crypto_7_term.DealImpl;
using crypto_7_term.ModesProcessor;
using TripleDES = crypto_7_term.TripleDesImpl.TripleDES;
using CipherMode = crypto_7_term.interfaces.CipherMode;
using PaddingMode = crypto_7_term.interfaces.PaddingMode;
using DES = crypto_7_term.DesImp.DES;
using crypto_7_term.FileProcessor;
using System.Security.Cryptography;
using static crypto_7_term.rsa.RSAImpl;
using RSA = crypto_7_term.rsa.RSAImpl.RSA;
using crypto_7_term.RC4;
using crypto_7_term.DiffieHellmanImpl;
using System.Numerics;

namespace crypto_7_term
{
    class Program
    {
        static async Task Main(string[] args)
        {
            #region 
            // Использование DES
            //Console.WriteLine("\n1. DES Example:");
            //TestDES();

            // Использование TripleDES
            //Console.WriteLine("\n2. TripleDES Example:");
            //TestTripleDES();

            // Использование DEAL
            //Console.WriteLine("\n3. DEAL Example:");
            //TestDEAL();
            #endregion

            //Шифрование файла с помощью des, 3des, deal 
            await TestDes3desDealAsync();

            // Пример RSA
            //await TestRSAAsync();

            // Протокол Диффи Хеллмана
            //DiffieHellmanProtocol();

            // Пример RС4
            //await TestRC4Async();

        }

        static async Task TestDes3desDealAsync()
        {
            var cipher = new DES(); 
            var processor = new CipherModeProcessor(
                (interfaces.IBlockCipher)cipher,
                CipherMode.CBC,
                PaddingMode.PKCS7);

            var fileCipher = new AsyncFileCipher(processor);

            var key = Encoding.UTF8.GetBytes("8bytekey");

            var progress = new Progress<double>(p =>
            {
                Console.WriteLine($"Progress: {p:P2}");
            });

            await fileCipher.EncryptFileAsync(
                "test.jpg",
                "test.jpg.enc",
                key,
                progress);

            await fileCipher.DecryptFileAsync(
                "test.jpg.enc",
                "test_decrypted.jpg",
                key,
                progress);
        }

        static async Task TestRSAAsync()
        {

            Console.WriteLine("\n1. Генерация ключей RSA...");
            var rsa = new RSA(2048);

            Console.WriteLine("\n2. Проверка уязвимости к атаке Винера: ");
            var d = WienerAttack.Attack(rsa.N, rsa.E);
            if (d == null)
            {
                Console.WriteLine("Атака Винера не удалась");
            }
            else
            {
                Console.WriteLine($"Найден секретный ключ: {d}");
            }
            Console.WriteLine("\n4. Шифрование файла...");

            string testFile = "test.txt";
            await File.WriteAllTextAsync(testFile, "This is a test file for RSA encryption.\n" +
                                                  "It contains multiple lines of text.\n" +
                                                  "Hopefully it works");

            string encryptedFile = "test.encrypted";
            string decryptedFile = "test.decrypted.txt";

            await rsa.EncryptFileAsync(testFile, encryptedFile);
            Console.WriteLine($"Файл зашифрован: {encryptedFile}");
            await rsa.DecryptFileAsync(encryptedFile, decryptedFile);
            Console.WriteLine($"Файл дешифрован: {decryptedFile}");

            // Проверка
            string originalContent = await File.ReadAllTextAsync(testFile);
            string decryptedContent = await File.ReadAllTextAsync(decryptedFile);
            Console.WriteLine($"Содержимое совпадает: {originalContent == decryptedContent}");

            // Экспорт/импорт ключей
            //Console.WriteLine("\n5. Экспорт/импорт ключей...");
            //string publicKey = rsa.ExportPublicKey();
            //string privateKey = rsa.ExportPrivateKey();
            //
            //Console.WriteLine($"Публичный ключ (base64): {publicKey.Substring(0, 50)}...");
            //Console.WriteLine($"Приватный ключ (base64): {privateKey.Substring(0, 50)}...");

            //
            //File.Delete(testFile);
            //File.Delete(encryptedFile);
            //File.Delete(decryptedFile);
        }

        static void DiffieHellmanProtocol ()
        {
            // Общие параметры
            BigInteger p = DiffieHellmanParticipant.GetStandardP();
            BigInteger g = 2; 

            // Алиса и Боб создают свои ключи
            var alice = new DiffieHellmanParticipant(p, g);
            var bob = new DiffieHellmanParticipant(p, g);

            // Обмен публичными ключами
            BigInteger alicePublicKey = alice.GetPublicKey();
            BigInteger bobPublicKey = bob.GetPublicKey();

            Console.WriteLine($"Алиса отправляет Бобу: A = {alicePublicKey.ToString("X").Substring(0, 32)}...");
            Console.WriteLine($"Боб отправляет Алисе: B = {bobPublicKey.ToString("X").Substring(0, 32)}...");
            Console.WriteLine();

            // Вычисление общего секрета
            alice.ComputeSharedSecret(bobPublicKey);
            bob.ComputeSharedSecret(alicePublicKey);

            BigInteger aliceSecret = alice.GetSharedSecret();
            BigInteger bobSecret = bob.GetSharedSecret();

            Console.WriteLine($"Общий секрет Алисы: {aliceSecret.ToString("X").Substring(0, 32)}...");
            Console.WriteLine($"Общий секрет Боба:   {bobSecret.ToString("X").Substring(0, 32)}...");
            Console.WriteLine($"Секреты совпадают: {aliceSecret == bobSecret}");
            Console.WriteLine();

            // Генерация симметричных ключей для шифрования
            byte[] aliceSymmetricKey = alice.DeriveSymmetricKey(32); 
            byte[] bobSymmetricKey = bob.DeriveSymmetricKey(32);

            Console.WriteLine($"Ключ Алисы: {BitConverter.ToString(aliceSymmetricKey).Replace("-", "").Substring(0, 32)}...");
            Console.WriteLine($"Ключ Боба:  {BitConverter.ToString(bobSymmetricKey).Replace("-", "").Substring(0, 32)}...");
            Console.WriteLine($"Ключи совпадают: {aliceSymmetricKey.SequenceEqual(bobSymmetricKey)}");
            Console.WriteLine();

            // Демонстрация симметричного шифрования
            string originalMessage = "This is a secret message between Bob and Alice";
            Console.WriteLine($"Оригинальное сообщение: {originalMessage}");

            // Алиса шифрует сообщение
            byte[] encrypted = DiffieHellmanParticipant.EncryptWithAES(originalMessage, aliceSymmetricKey);
            Console.WriteLine($"Зашифрованное сообщение (hex): {BitConverter.ToString(encrypted).Replace("-", "").Substring(0, 32)}...");

            // Боб дешифрует сообщение
            string decrypted = DiffieHellmanParticipant.DecryptWithAES(encrypted, bobSymmetricKey);
            Console.WriteLine($"Дешифрованное сообщение: {decrypted}");
            Console.WriteLine($"Дешифрование успешно: {originalMessage == decrypted}");
            Console.WriteLine();
        }

        static async Task TestRC4Async()
        {
            // Создание тестового файла
            string testFile = "test_rc4.txt";
            string encryptedFile = "test_rc4.encrypted";
            string decryptedFile = "test_rc4.decrypted.txt";

            string testText = "  3This is a test file for RC4 encryption.\n" +
                              "It contains multiple lines of text.\n" +
                              "Hopefully it works";

            await File.WriteAllTextAsync(testFile, testText, Encoding.UTF8);

            // Генерация ключа
            byte[] key = RC4Impl.GenerateKey(32);
            Console.WriteLine($"Сгенерирован ключ (hex): {BitConverter.ToString(key).Replace("-", "")}");

            // Шифрование 
            Console.Write("Шифрование... ");
            using (var rc4 = new RC4Impl(key))
            {
                await rc4.EncryptFileAsync(testFile, encryptedFile);
            }
            Console.WriteLine("Файл зашифрован.");

            // Дешифрование
            Console.Write("Дешифрование... ");
            using (var rc4 = new RC4Impl(key)) 
            {
                await rc4.DecryptFileAsync(encryptedFile, decryptedFile);
            }
            Console.WriteLine("Файл дешифрован.");

            // Проверка 
            string original = await File.ReadAllTextAsync(testFile, Encoding.UTF8);
            string decrypted = await File.ReadAllTextAsync(decryptedFile, Encoding.UTF8);

            Console.WriteLine($"Оригинальный текст: {original.Substring(0, Math.Min(50, original.Length))}...");
            Console.WriteLine($"Дешифрованный текст: {decrypted.Substring(0, Math.Min(50, decrypted.Length))}...");
            Console.WriteLine($"Файлы совпадают: {original == decrypted}");
        }

        static void TestDES()
        {
            var des = new DES();
            var key = Encoding.UTF8.GetBytes("8bytekey");
            var data = Encoding.UTF8.GetBytes("jjjj777721у");

            var processor = new CipherModeProcessor((interfaces.IBlockCipher)des, CipherMode.CBC, PaddingMode.PKCS7);
            var encrypted = processor.Encrypt(data, key);
            Console.WriteLine($"Original: {Encoding.UTF8.GetString(data)}");
            Console.WriteLine($"Encrypted: {BitConverter.ToString(encrypted)}");
            var decrypted = processor.Decrypt(encrypted, key);

            Console.WriteLine($"Decrypted: {Encoding.UTF8.GetString(decrypted)}");
        }

        static void TestTripleDES()
        {
            var tripleDes = new TripleDES();
            var key = Encoding.UTF8.GetBytes("jjdjj7778bytekey");
            var data = Encoding.UTF8.GetBytes("Test еуы");

            var processor = new CipherModeProcessor((interfaces.IBlockCipher)tripleDes, CipherMode.CTR, PaddingMode.PKCS7);
            var encrypted = processor.Encrypt(data, key);
            var decrypted = processor.Decrypt(encrypted, key);

            Console.WriteLine($"Original: {Encoding.UTF8.GetString(data)}");
            Console.WriteLine($"Encrypted: {BitConverter.ToString(encrypted)}");
            Console.WriteLine($"Decrypted: {Encoding.UTF8.GetString(decrypted)}");
        }

        static void TestDEAL()
        {
            var deal = new DEAL();
            var key = Encoding.UTF8.GetBytes("16byteDEALkey!!");
            var data = Encoding.UTF8.GetBytes("DEAц12");

            var processor = new CipherModeProcessor((interfaces.IBlockCipher)deal, CipherMode.CFB, PaddingMode.ISO10126); //cfb, ctr, ofb
            var encrypted = processor.Encrypt(data, key);
            var decrypted = processor.Decrypt(encrypted, key);

            Console.WriteLine($"Original: {Encoding.UTF8.GetString(data)}");
            Console.WriteLine($"Encrypted: {BitConverter.ToString(encrypted)}");
            Console.WriteLine($"Decrypted: {Encoding.UTF8.GetString(decrypted)}");
        }
    }
}
