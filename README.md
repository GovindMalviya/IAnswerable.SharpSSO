IAnswerable.SharpSSO
====================


Mutipass SSO is common protocol to use SSO (single sign on) among two or more websites. This protocol uses by various 
big companies to implement SSO. [Desk.com](http://Desk.com) and [Tenderapp](http://tenderapp.com).

To implement in your asp.net site. you can use this libarary just in simple steps.

###for transmitter
            
            //Data is simple class example class, use whatever you want
            
            var _transmitter = new Transmitter<Data>(_data);
            
            _transmitter.ApiKey = "any-api-key-which-you-want";   // just a key, its good to use strong key
            _transmitter.InitVector = "OpenSSL for Ruby";         // Don't chnage
            _transmitter.SiteKey = "your-site-key";               // any site key (friendly name)

            var multipass = _transmitter.CreateMultipass();
            
            //Redirect user to destination website
            
            Response.Redirect(string.Format("http://www.mysite.com?multipass={0}&sig={1}",multipass.MultipassText,multipass.Signature));
            
###for receiver 
            var _receiver = new Receiver<Data>();
            
            _receiver.ApiKey = "any-api-key-which-you-want";    // same as transmitter
            _receiver.InitVector = "OpenSSL for Ruby";          // Don't change
            _receiver.SiteKey = "your-site-key";                // same as transmitter
            
            string multipass = Request.QueryString["multipass"];
            string signature = Request.QueryString["sig"];
            
            //get your which is transmitted from transmitter
            var data = _receiver.GetData(multipass, signature);

