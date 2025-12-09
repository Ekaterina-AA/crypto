using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace crypto_7_term.interfaces
{
    /// <summary>
    /// Режимы дополнения (padding)
    /// </summary>
    public enum PaddingMode
    {
        Zeros,
        ANSIX923,
        PKCS7,
        ISO10126
    }
}
