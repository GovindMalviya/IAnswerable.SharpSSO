using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using IAnswerable.SharpSSO.Multipass;

namespace IAnswerable.SharpSSO.Test
{
    [TestClass]
    public class SSOProcess
    {
        Data _data;
        Transmitter<Data> _transmitter;
        Receiver<Data> _receiver;

        [TestInitialize]
        public void Setup()
        {
            _data = new Data() { Id = 2343, Name = "Govind Kumar", Description = "Software Developer" };
            _transmitter = new Transmitter<Data>(_data);
            _receiver = new Receiver<Data>();
        }

        [TestMethod]
        public void Sucesstest()
        {
            _transmitter.ApiKey = "govindkumar";
            _transmitter.InitVector = "OpenSSL for Ruby";
            _transmitter.SiteKey = "656566566h3rhr98rrh2r92rh2rn2rnr200";

            var multipass = _transmitter.CreateMultipass();


            _receiver.ApiKey = "govindkumar";
            _receiver.InitVector = "OpenSSL for Ruby";
            _receiver.SiteKey = "656566566h3rhr98rrh2r92rh2rn2rnr200";

            var data = _receiver.GetData(multipass.MultipassText,multipass.Signature);

            Assert.AreEqual(data, _data);
        }
    }

    public class Data
    {
        public string Name {get;set;}
        public int  Id {get;set;}
        public string Description {get;set;}

        public override bool Equals(object obj)
        {
            var data = (Data)obj;
            return data.Name == this.Name && data.Id == this.Id && data.Description == this.Description;
        }
    }
}
