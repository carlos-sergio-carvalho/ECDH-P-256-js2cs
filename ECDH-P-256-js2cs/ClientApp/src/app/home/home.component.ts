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
        this.getSharedSecret((result as any).pkey).then(() => { console.log(this.sharedSecretHashB64.replace(/(.{64})/g, '$1\n'))});
    }, error => console.error(error));


    });
    
  }


  //private async setUpDFHKeys().then(() => { });
  private publicKeyB64:string='';
  private privateKeyB64: string = '';
  public sharedSecretHashB64: string = '';
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
    var sharedSecretHash = await crypto.subtle.digest('SHA-256', sharedSecret);
    /* @ts-ignore */
  this.sharedSecretHashB64 = btoa(String.fromCharCode.apply(null, new Uint8Array(sharedSecretHash)));
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
}
