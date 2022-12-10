using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace ECDH_P_256_js2cs.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class KeyExangeController : ControllerBase
    {
        [HttpPost]
        public ActionResult<PortPkey> Post([FromBody] PortPkey pkey)
        {
            var alicePublicKey =string.Empty;
            string sharedSecret = WorkWithJSPublicKey(pkey.Pkey, out alicePublicKey);
            pkey.Pkey = alicePublicKey;
            return pkey;
        }


        public class PortPkey
        {
            public string Pkey { get; set; } = string.Empty;
        }

        private string WorkWithJSPublicKey(string bobPublicKeyB64, out string alicePublicKey)
        {
            alicePublicKey = null;
            using (ECDiffieHellman alice = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
            {
                alicePublicKey = Convert.ToBase64String(alice.ExportSubjectPublicKeyInfo());
                //Console.WriteLine("Alice's public:        " + alicePublicKey);
                //Console.WriteLine("Alice's private:       " + Convert.ToBase64String(alice.ExportPkcs8PrivateKey()));
                ECDiffieHellman bob = ECDiffieHellman.Create();
                bob.ImportSubjectPublicKeyInfo(Convert.FromBase64String(bobPublicKeyB64), out _);
                byte[] sharedSecret = alice.DeriveKeyMaterial(bob.PublicKey);
                return Convert.ToBase64String(sharedSecret);
            }
        }
    }
}
