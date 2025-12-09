using crypto_7_term.ModesProcessor;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace crypto_7_term.FileProcessor
{
    /// <summary>
    /// Асинхронный обработчик шифрования/дешифрования файлов
    /// </summary>
    public class AsyncFileCipher
    {
        private readonly CipherModeProcessor _modeProcessor;
        private readonly int _bufferSize;
        private readonly int _maxDegreeOfParallelism;

        public AsyncFileCipher(
            CipherModeProcessor modeProcessor,
            int bufferSize = 1024 * 1024, 
            int maxDegreeOfParallelism = -1) 
        {
            _modeProcessor = modeProcessor ?? throw new ArgumentNullException(nameof(modeProcessor));
            _bufferSize = bufferSize;
            _maxDegreeOfParallelism = maxDegreeOfParallelism == -1
                ? Environment.ProcessorCount
                : maxDegreeOfParallelism;
        }

        /// <summary>
        /// Асинхронное шифрование файла
        /// </summary>
        public async Task EncryptFileAsync(
            string inputFilePath,
            string outputFilePath,
            byte[] key,
            IProgress<double> progress = null,
            CancellationToken cancellationToken = default)
        {
            await ProcessFileAsync(
                inputFilePath,
                outputFilePath,
                key,
                encrypt: true,
                progress,
                cancellationToken);
        }

        /// <summary>
        /// Асинхронное дешифрование файла
        /// </summary>
        public async Task DecryptFileAsync(
            string inputFilePath,
            string outputFilePath,
            byte[] key,
            IProgress<double> progress = null,
            CancellationToken cancellationToken = default)
        {
            await ProcessFileAsync(
                inputFilePath,
                outputFilePath,
                key,
                encrypt: false,
                progress,
                cancellationToken);
        }

        private async Task ProcessFileAsync(
            string inputFilePath,
            string outputFilePath,
            byte[] key,
            bool encrypt,
            IProgress<double> progress,
            CancellationToken cancellationToken)
        {
            var fileInfo = new FileInfo(inputFilePath);
            long totalBytes = fileInfo.Length;
            long processedBytes = 0;

            byte[] iv = null;
            if (encrypt)
            {
                iv = _modeProcessor.GetIV(); 
            }

            using (var inputStream = new FileStream(
                inputFilePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                useAsync: true))
            using (var outputStream = new FileStream(
                outputFilePath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                useAsync: true))
            {
                if (encrypt && iv != null)
                {
                    await outputStream.WriteAsync(iv, 0, iv.Length, cancellationToken);
                }
                else if (!encrypt)
                {
                    iv = new byte[_modeProcessor.GetIVSize()]; 
                    await inputStream.ReadAsync(iv, 0, iv.Length, cancellationToken);
                    _modeProcessor.SetIV(iv); 
                }

                var bufferPool = new Pool<byte[]>(() => new byte[_bufferSize], _maxDegreeOfParallelism);
                var semaphore = new SemaphoreSlim(_maxDegreeOfParallelism);

                var tasks = new List<Task>();

                while (processedBytes < totalBytes)
                {
                    await semaphore.WaitAsync(cancellationToken);

                    var buffer = bufferPool.Get();
                    int bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                    if (bytesRead == 0)
                        break;

                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            byte[] processedData;
                            if (encrypt)
                            {
                                processedData = _modeProcessor.Encrypt(buffer.Take(bytesRead).ToArray(), key);
                            }
                            else
                            {
                                processedData = _modeProcessor.Decrypt(buffer.Take(bytesRead).ToArray(), key);
                            }

                            await outputStream.WriteAsync(processedData, 0, processedData.Length, cancellationToken);

                            Interlocked.Add(ref processedBytes, bytesRead);
                            progress?.Report((double)processedBytes / totalBytes);
                        }
                        finally
                        {
                            bufferPool.Return(buffer);
                            semaphore.Release();
                        }
                    }, cancellationToken));
                }

                await Task.WhenAll(tasks);
            }
        }

        /// <summary>
        /// Пул объектов для уменьшения аллокаций памяти
        /// </summary>
        private class Pool<T>
        {
            private readonly Stack<T> _pool = new Stack<T>();
            private readonly Func<T> _factory;
            private readonly int _maxSize;
            private readonly object _lock = new object();

            public Pool(Func<T> factory, int maxSize)
            {
                _factory = factory;
                _maxSize = maxSize;
            }

            public T Get()
            {
                lock (_lock)
                {
                    if (_pool.Count > 0)
                        return _pool.Pop();
                }
                return _factory();
            }

            public void Return(T item)
            {
                lock (_lock)
                {
                    if (_pool.Count < _maxSize)
                        _pool.Push(item);
                }
            }
        }
    }
}