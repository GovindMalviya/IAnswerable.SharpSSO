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

        //public byte[] AES_Encrypt(byte[] plainTextBytes, byte[] Key, byte[] IV)
        //{
        //    Aes myAes = Aes.Create();

        //    ICryptoTransform encryptor = myAes.CreateEncryptor(Key, IV);

        //    MemoryStream memoryStream = new MemoryStream();

        //    CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);

        //    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);

        //    cryptoStream.FlushFinalBlock();

        //    byte[] cipherTextBytes = memoryStream.ToArray();

        //    // Close both streams.
        //    memoryStream.Close();
        //    cryptoStream.Close();

        //    return cipherTextBytes;
        //}

        public byte[] AES_Decrypt(byte[] textBytes, byte[] Key, byte[] IV)
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

                ICryptoTransform encryptor = aesAlgo.CreateDecryptor();

                using (CryptoStream csEncrypt = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(textBytes, 0, textBytes.Length);
                    csEncrypt.FlushFinalBlock();
                }

                byte[] encrypted = ms.ToArray();

                return encrypted;
            }
        }

        //public byte[] AES_Decrypt(byte[] cipherTextBytes, byte[] Key, byte[] IV)
        //{
           
        //    Aes myAes = Aes.Create();

        //    ICryptoTransform decryptor = myAes.CreateDecryptor(Key, IV);

        //    MemoryStream memoryStream = new MemoryStream(cipherTextBytes);

        //    CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);

        //    byte[] plainTextBytes = new byte[cipherTextBytes.Length];

        //    // Start decrypting.
        //    int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);

        //    // Close both streams.
        //    memoryStream.Close();
        //    cryptoStream.Close();

            
        //    // Return decrypted string.
        //    return plainTextBytes;
        //}
    }
}
