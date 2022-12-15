using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ECDH_P_256_js2cs.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class KeyExangeController : ControllerBase
    {
        private readonly ILogger<KeyExangeController> _logger;
        private readonly IMemoryCache _memoryCache;
        public KeyExangeController(ILogger<KeyExangeController> logger, IMemoryCache memoryCache)
        {
            _logger = logger;
            _memoryCache = memoryCache;
        }

        [HttpPost]
        public ActionResult<PortPkey> Post([FromBody] PortPkey pkey)
        {
            var alicePublicKey =string.Empty;
            string sharedSecret = WorkWithJSPublicKey(pkey.Pkey, out alicePublicKey);
            pkey.Pkey = alicePublicKey;
            _logger.LogInformation(sharedSecret);
            _memoryCache.Set("sharedSecret", sharedSecret);
            return pkey;
        }

        [HttpPost("AesPackage")]
        public ActionResult PostAesPackage([FromBody] AesPackage pack)
        {
            //var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // MaxSize = 16
            //var key = Convert.FromBase64String(pack.key);

            var key= Convert.FromBase64String(_memoryCache.Get<string>("sharedSecret"));
            var iv=  Convert.FromBase64String(pack.iv);
            var cipher = Convert.FromBase64String(pack.cipher);
            var tag = cipher.Skip(cipher.Length-16).Take(16).ToArray();
            cipher = cipher.Take(cipher.Length-16).ToArray();
            var text=Decrypt(cipher,iv,tag,key);
            _logger.LogInformation(text);
            return Ok();
        }


        public class PortPkey
        {
            public string Pkey { get; set; } = string.Empty;
        }

        public class AesPackage
        {
            public string cipher { get; set; } = string.Empty;
            public string iv { get; set; } = string.Empty;
            //// teste óbivio 
            //public string key { get; set; } = string.Empty;
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
//                byte[] sharedSecret = alice.DeriveKeyMaterial(bob.PublicKey);
                var sharedSecret =  alice.DeriveKeyFromHash(bob.PublicKey,HashAlgorithmName.SHA256); // esse sha tem q ser do mesmo tamanho da curva ! p-256 = sha256 , p-256 = sha256 e p-512 =sha512
                return Convert.ToBase64String(sharedSecret);
            }
        }

        private string Decrypt(byte[] ciphertext, byte[] nonce, byte[] tag, byte[] key)
        {
            using (var aes = new AesGcm(key))
            {
                var plaintextBytes = new byte[ciphertext.Length];

                aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);

                return Encoding.UTF8.GetString(plaintextBytes);
            }
        }

        private byte[] Encrypt(byte[] nonce,byte[] key,string plaintext)
        {
            //var key = new byte[32];
            //RandomNumberGenerator.Fill(key);
            using var aes = new AesGcm(key);
            var plaintextBytes = Encoding.UTF8.GetBytes("got more soul than a sock with a hole");
            var ciphertext = new byte[plaintextBytes.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // MaxSize = 16
            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
            return ciphertext;
        }

    }
}
