using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;
using IAnswerable.Utility;
using System.Security.Cryptography;
using IAnswerable.SharpSSO.Security;

namespace IAnswerable.SharpSSO.Multipass
{
    public class Transmitter<T> where T : class, new()
    {
        JavaScriptSerializer _jsserializer = new JavaScriptSerializer();
        Encryption encryption = new Encryption();

        string _destinationUrl;
        T _data;
        string _apikey;
        string _sitekey;
        string _initVector;


        public string ApiKey
        {
            private get
            {
                return _apikey;
            }
            set
            {
                _apikey = value;
            }
        }

        public string SiteKey
        {
            private get
            {
                return _sitekey;
            }
            set
            {
                _sitekey = value;
            }
        }

        public string InitVector
        {
            private get
            {
                return _initVector;
            }
            set
            {
                _initVector = value;
            }
        }


        public Transmitter(string destinationUrl, T data)
        {
            if (destinationUrl.IsNotNullOrEmptyOrWhiteSpace())
            {
                throw new ArgumentNullException("Argument is null or empty or whitespace.", "destinationUrl");
            }

            if (Uri.IsWellFormedUriString(destinationUrl, UriKind.RelativeOrAbsolute))
            {
                throw new ArgumentException("Url not valid", "destinationUrl");
            }

            this._destinationUrl = destinationUrl;
            this._data = data;
        }

        public string CreateMultipass(out string signature)
        {
            if (_apikey.IsNotNullOrEmptyOrWhiteSpace())
            {
                throw new ArgumentException("Encryption Key cannot be empty.", "EncryptionKey");
            }

            if (_sitekey.IsNotNullOrEmptyOrWhiteSpace())
            {
                throw new ArgumentException("Site Key cannot be empty.", "SiteKey");
            }

            if (_initVector.IsNotNullOrEmptyOrWhiteSpace())
            {
                throw new ArgumentException("Init Vector cannot be empty.", "InitVector");
            }


            //serialize object to json string
            string strdata = _jsserializer.Serialize(_data);

            byte[] bInitVector = _initVector.ToByteArray();
            byte[] bData = strdata.ToByteArray();
            byte[] keyBytesLong;
            byte[] keyBytes = new byte[16];


            using (SHA1CryptoServiceProvider sha = new SHA1CryptoServiceProvider())
            {
                keyBytesLong = sha.ComputeHash((_apikey + _sitekey).ToByteArray());
            }

            Array.Copy(keyBytesLong, keyBytes, 16);

            // XOR first 16 bytes of data
            for (int i = 0; i < 16; i++)
            {
                bData[i] ^= bInitVector[i];
            }


            byte[] encrypted = encryption.AES_Encrypt(bData, keyBytes, bInitVector);

            string encoded = Convert.ToBase64String(encrypted);

            encoded = encoded.Replace("\n", "")     //remove \n
                             .TrimEnd('=')          // remove leading and trailing =
                             .Replace("+", "-")     // replace + with -
                             .Replace("/", "_");    // replace / with _

            //generate HMAC-SHA1 
            HMACSHA1 hmacSha = new HMACSHA1(_apikey.ToByteArray());
            hmacSha.Initialize();

            byte[] hmac = hmacSha.ComputeHash(Encoding.UTF8.GetBytes(encoded));

            signature = Convert.ToBase64String(hmac);

            return encoded;
        }
    }
}
