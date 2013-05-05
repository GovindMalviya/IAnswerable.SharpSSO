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

        IMultipassBuilder _multipassbuilder;


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


        public Transmitter(T data)
        {
            _multipassbuilder = new MultipassBuilder();

            if (data.IsNull())
            {
                throw new ArgumentNullException("Argument cannot be null", "destinationUrl");
            }

            this._data = data;
        }

        public IMultipass CreateMultipass()
        {
            IMultipass multipass = new Multipass();

            if (string.IsNullOrEmpty(_apikey))
            {
                throw new ArgumentException("Encryption Key cannot be empty.", "EncryptionKey");
            }

            if (string.IsNullOrEmpty(_sitekey))
            {
                throw new ArgumentException("Site Key cannot be empty.", "SiteKey");
            }

            if (string.IsNullOrEmpty(_initVector))
            {
                throw new ArgumentException("Init Vector cannot be empty.", "InitVector");
            }


            //serialize object to json string
            string strdata = _multipassbuilder.Serialize(_data);

            //encryption
            string encrypted = _multipassbuilder.Encrypt(strdata, InitVector, _apikey, _sitekey);

            //generate signature
            string signature = _multipassbuilder.GenerateSignature(encrypted,_apikey);

            //encode and combine
            multipass = _multipassbuilder.Encode(encrypted, signature);

            return multipass;
        }
    }
}
