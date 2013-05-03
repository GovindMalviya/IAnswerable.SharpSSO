using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace IAnswerable.SharpSSO.Security
{
    public class Encryption
    {
        public byte[] AES_Encrypt(byte[] textBytes, byte[] Key, byte[] IV)
        {
            using (MemoryStream ms = new MemoryStream())
            using (RijndaelManaged aesAlgo = new RijndaelManaged())
            {
                aesAlgo.Mode = CipherMode.CBC;
                aesAlgo.Padding = PaddingMode.PKCS7;
                aesAlgo.KeySize = 128;
                aesAlgo.BlockSize = 128;
                aesAlgo.Key = Key;
                aesAlgo.IV = IV;

                ICryptoTransform encryptor = aesAlgo.CreateEncryptor();

                using (CryptoStream csEncrypt = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(textBytes, 0, textBytes.Length);
                    csEncrypt.FlushFinalBlock();
                }

                byte[] encrypted = ms.ToArray();

                return encrypted;
            }
        }
    }
}
