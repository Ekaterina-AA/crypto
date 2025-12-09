using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace crypto_7_term.interfaces
{
    /// <summary>
    /// Интерфейс для блочных шифров
    /// </summary>
    public interface IBlockCipher
    {
        int BlockSize { get; }
        byte[] EncryptBlock(byte[] block, byte[] key);
        byte[] DecryptBlock(byte[] block, byte[] key);
    }

    /// <summary>
    /// Базовый класс для шифров
    /// </summary>
    public abstract class CipherBase: IBlockCipher
    {
        public abstract int BlockSize { get; }
        public abstract byte[] EncryptBlock(byte[] block, byte[] key);
        public abstract byte[] DecryptBlock(byte[] block, byte[] key);
    }
}
