using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace crypto_7_term.RC4
{
    /// <summary>
    /// Реализация алгоритма RC4 (Rivest Cipher 4)
    /// </summary>
    public class RC4Impl : IDisposable
    {
        private readonly byte[] _s = new byte[256]; // State array
        private int _i = 0;
        private int _j = 0;
        private bool _disposed = false;
        private readonly byte[] _key;

        /// <summary>
        /// Инициализация RC4 с ключом
        /// </summary>
        public RC4Impl(byte[] key)
        {
            if (key == null || key.Length == 0)
                throw new ArgumentException("Key cannot be null or empty", nameof(key));

            if (key.Length > 256)
                throw new ArgumentException("Key length cannot exceed 256 bytes", nameof(key));

            _key = new byte[key.Length];
            Array.Copy(key, _key, key.Length);

            Initialize(_key);
        }

        /// <summary>
        /// Инициализация состояния алгоритма
        /// </summary>
        private void Initialize(byte[] key)
        {
            for (int i = 0; i < 256; i++)
            {
                _s[i] = (byte)i;
            }

            // Key Scheduling Algorithm (KSA)
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + _s[i] + key[i % key.Length]) & 255;
                // Swap
                byte temp = _s[i];
                _s[i] = _s[j];
                _s[j] = temp;
            }

            _i = 0;
            _j = 0;
        }

        /// <summary>
        /// Генерация одного байта ключевого потока
        /// </summary>
        private byte NextByte()
        {
            _i = (_i + 1) & 255;
            _j = (_j + _s[_i]) & 255;

            // Swap 
            byte temp = _s[_i];
            _s[_i] = _s[_j];
            _s[_j] = temp;

            int t = (_s[_i] + _s[_j]) & 255;
            return _s[t];
        }

        /// <summary>
        /// Шифрование/дешифрование данных (RC4 симметричен)
        /// </summary>
        public void Process(Span<byte> data)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(RC4Impl));

            for (int k = 0; k < data.Length; k++)
            {
                data[k] ^= NextByte();
            }
        }

        /// <summary>
        /// Генерация случайного ключа заданной длины
        /// </summary>
        public static byte[] GenerateKey(int length)
        {
            if (length < 1 || length > 256)
                throw new ArgumentException("Key length must be between 1 and 256 bytes", nameof(length));

            byte[] key = new byte[length];
            RandomNumberGenerator.Fill(key);
            return key;
        }

        /// <summary>
        /// Асинхронное шифрование файла 
        /// </summary>
        public async Task EncryptFileAsync(
            string inputFile,
            string outputFile,
            CancellationToken cancellationToken = default)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(RC4Impl));

            await ProcessFileAsync(inputFile, outputFile, cancellationToken);
        }

        /// <summary>
        /// Асинхронное дешифрование файла
        /// </summary>
        public async Task DecryptFileAsync(
            string inputFile,
            string outputFile,
            CancellationToken cancellationToken = default)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(RC4Impl));

            // дешифрование = шифрование в RC4
            await ProcessFileAsync(inputFile, outputFile, cancellationToken);
        }

        /// <summary>
        /// Обработка файла с асинхронным конвейером
        /// </summary>
        private async Task ProcessFileAsync(string inputFile,
                                                        string outputFile,
                                                        CancellationToken cancellationToken)
        {
            if (!File.Exists(inputFile))
                throw new FileNotFoundException($"Input file not found: {inputFile}", inputFile);

            const int bufferSize = 81920; // 80KB

            using var inputStream = new FileStream(
                inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            using var outputStream = new FileStream(
                outputFile, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            // Канал для передачи обработанных данных
            var channel = Channel.CreateBounded<(byte[] buffer, int count)>(
                new BoundedChannelOptions(3)
                {
                    SingleWriter = true,
                    SingleReader = true,
                    FullMode = BoundedChannelFullMode.Wait
                });

            var processingTask = Task.Run(async () =>
            {
                await foreach (var (buffer, count) in channel.Reader.ReadAllAsync(cancellationToken))
                {
                    try
                    {
                        Process(new Span<byte>(buffer, 0, count));

                        await outputStream.WriteAsync(buffer, 0, count, cancellationToken);
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(buffer);
                    }
                }
            }, cancellationToken);

            try
            {
                while (true)
                {
                    byte[] buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
                    int bytesRead = await inputStream.ReadAsync(buffer, 0, bufferSize, cancellationToken);

                    if (bytesRead == 0)
                    {
                        ArrayPool<byte>.Shared.Return(buffer);
                        break;
                    }

                    await channel.Writer.WriteAsync((buffer, bytesRead), cancellationToken);
                }

                channel.Writer.Complete();

                await processingTask;

                await outputStream.FlushAsync(cancellationToken);
            }
            catch (Exception)
            {
                channel.Writer.TryComplete();
                throw;
            }
        }

        /// <summary>
        /// Освобождение ресурсов
        /// </summary>
        private readonly object _disposeLock = new object();

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        /// <summary>
        /// Освобождение ресурсов
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            lock (_disposeLock)
            {
                if (_disposed)
                {
                    return;
                }

                try
                {
                    _i = 0;
                    _j = 0;

                    if (_s != null)
                    {
                        CryptographicOperations.ZeroMemory(_s);
                    }

                    if (_key != null)
                    {
                        CryptographicOperations.ZeroMemory(_key);
                    }
                }
                finally
                {
                    _disposed = true;
                }
            }
        }

        /// <summary>
        /// Финализатор 
        /// </summary>
        ~RC4Impl()
        {
            Dispose(false);
        }
    }
}