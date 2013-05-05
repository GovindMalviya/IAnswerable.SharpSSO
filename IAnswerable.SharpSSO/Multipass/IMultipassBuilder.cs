using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IAnswerable.SharpSSO.Multipass
{
    public interface IMultipassBuilder
    {
        string Serialize<T>(T data);
        string Encrypt(string strdata, string initVector, string apikey, string sitekey);
        string GenerateSignature(string text, string apikey);
        IMultipass Encode(string encrypted, string signature);
    }
}
