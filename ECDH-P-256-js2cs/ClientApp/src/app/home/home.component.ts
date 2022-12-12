import { Component, Inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';


@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
})
export class HomeComponent {

  constructor(http: HttpClient, @Inject('BASE_URL') baseUrl: string) {

    this.setUpDFHKeys().then(() => {
      http.post(baseUrl + 'api/keyexange', { pkey: this.publicKeyB64 }).subscribe(result => {
      //this.forecasts = result;
        this.getSharedSecret((result as any).pkey).then(async () => {
          /* @ts-ignore */
          let key = await crypto.subtle.importKey(
            "raw",
            this.sharedSecretHash,
            "AES-GCM",
            true,
            ["encrypt", "decrypt"]
          );

          const { cipher, iv } = await this.encrypt(first, key);
          /* @ts-ignore */
          console.log(btoa(String.fromCharCode.apply(null, iv)));
          /* @ts-ignore */
          console.log(btoa(String.fromCharCode.apply(null, new Uint8Array(this.sharedSecretHash))));
          /* @ts-ignore */
          console.log(btoa(String.fromCharCode.apply(null, new Uint8Array(cipher))));

          
          http.post(baseUrl + 'api/keyexange/AesPackage', {
            /* @ts-ignore */
            iv: btoa(String.fromCharCode.apply(null, iv)),
            /* @ts-ignore */
            cipher: btoa(String.fromCharCode.apply(null, new Uint8Array(cipher)))
/*            ,
            key: btoa(String.fromCharCode.apply(null, new Uint8Array(this.sharedSecretHash)))*/
          }).subscribe(result => {
            
          });
          
          let t = 0;

        });
    }, error => console.error(error));


    });
    const first = 'Hello, World!'
  }

  


  /*parte para ECDH mover para modulo  */

  //private async setUpDFHKeys().then(() => { });
  private publicKeyB64:string='';
  private privateKeyB64: string = '';
  public sharedSecretHashB64: string = '';
  private sharedSecretHash: ArrayBuffer | undefined ;
private async setUpDFHKeys() {
  var bobKey = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ["deriveKey"]
  );
  var publicKeyData = await window.crypto.subtle.exportKey("spki", bobKey.publicKey);
  var publicKeyBytes = new Uint8Array(publicKeyData);
  /* @ts-ignore */
  this.publicKeyB64 = btoa(String.fromCharCode.apply(null, publicKeyBytes));
  //console.log("Bob's public: \n" + publicKeyB64.replace(/(.{56})/g, '$1\n'));
  var privateKeyData = await window.crypto.subtle.exportKey("pkcs8", bobKey.privateKey);
  var privateKeyBytes = new Uint8Array(privateKeyData);
  /* @ts-ignore */
  this.privateKeyB64 = btoa(String.fromCharCode.apply(null, privateKeyBytes));
  //console.log("Bob's private:\n" + privateKeyB64.replace(/(.{56})/g, '$1\n'));
  };


  private async getSharedSecret(alicePublicKeyB64:string) {
    var bobPrivateKeyB64 = this.privateKeyB64;
    //var alicePublicKeyB64 = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJVUW57L2QeswZhnIp5gjMSiHhqyOVTsPUq2QwHv+R4jQetMQ8JDT+3VQyP/dPpskUhzDd3lKxdRBaiZrWby+VQ==';
    
    var privateKey = await window.crypto.subtle.importKey(
      "pkcs8",
      /* @ts-ignore */
      new Uint8Array(this._base64ToArrayBuffer(bobPrivateKeyB64)),
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );
  var publicKey = await window.crypto.subtle.importKey(
    "spki",
    /* @ts-ignore */
    new Uint8Array(this._base64ToArrayBuffer(alicePublicKeyB64)),
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
    var sharedSecret = await window.crypto.subtle.deriveBits(
      /* @ts-ignore */
    { name: "ECDH", namedCurve: "P-256", public: publicKey },
    privateKey,
    256
  );
    this.sharedSecretHash = await crypto.subtle.digest('SHA-256', sharedSecret);
    /* @ts-ignore */
    this.sharedSecretHashB64 = btoa(String.fromCharCode.apply(null, new Uint8Array(this.sharedSecretHash)));
  //console.log("Bob's shared secret: " + sharedSecretHashB64.replace(/(.{64})/g, '$1\n'));
};

// from https://stackoverflow.com/a/21797381/9014097
  private  _base64ToArrayBuffer(base64: any) {
  var binary_string = window.atob(base64);
  var len = binary_string.length;
  var bytes = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
  }


  /*parte para AES+GSM mover para modulo  */
  //https://voracious.dev/blog/a-practical-guide-to-the-web-cryptography-api
  // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey
  private generateKey = async () => { return window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256, }, true, ['encrypt', 'decrypt']) }

  private encode = (data: any) => { const encoder = new TextEncoder(); return encoder.encode(data) }

  private generateIv = () => { return window.crypto.getRandomValues(new Uint8Array(12)) }
  private encrypt = async (data: any, key: any) =>
  {
    const encoded = this.encode(data);
    const iv = this.generateIv();
    const cipher = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, }, key, encoded);
    return { cipher, iv, }
  }
  private pack = (buffer: any) => {
    /* @ts-ignore */
    return window.btoa(String.fromCharCode.apply(null, new Uint8Array(buffer))
    )
  }
  private unpack = (packed: any) => {
    const string = window.atob(packed);
    const buffer = new ArrayBuffer(string.length);
    const bufferView = new Uint8Array(buffer);
    for (let i = 0; i < string.length; i++) { bufferView[i] = string.charCodeAt(i) };
    return buffer;
  }
  private decode = (bytestream: any) => { const decoder = new TextDecoder(); return decoder.decode(bytestream); }

  private decrypt = async (cipher: any, key: any, iv: any) => { const encoded = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv, }, key, cipher); return this.decode(encoded) }


}
