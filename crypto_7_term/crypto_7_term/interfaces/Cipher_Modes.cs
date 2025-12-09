using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace crypto_7_term.interfaces
{

    /// <summary>
    /// Режимы шифрования
    /// </summary>
    public enum CipherMode
    {
        ECB,
        CBC,
        PCBC,
        CFB,
        OFB,
        CTR,
        RandomDelta
    }
}
