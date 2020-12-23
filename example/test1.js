const CryptoJS = require('crypto-js');

function encrypt(pText, init_key, init_iv) {

    var key = CryptoJS.enc.Utf8.parse(init_key);

    var iv = CryptoJS.enc.Utf8.parse(init_iv);



    var cipherData = CryptoJS.AES.encrypt(pText, key, {

        iv: iv,

        mode: CryptoJS.mode.CBC,

        padding: CryptoJS.pad.Pkcs7,

        format: CryptoJS.format.OpenSSL

    });



    return cipherData

}



function decrypt(cipherText, init_key, init_iv) {

    var key = CryptoJS.enc.Utf8.parse(init_key);

    var iv = CryptoJS.enc.Utf8.parse(init_iv);



    var Data = CryptoJS.AES.decrypt(cipherText, key, {

        iv: iv,

        mode: CryptoJS.mode.CBC,

        padding: CryptoJS.pad.Pkcs7,

        format: CryptoJS.format.OpenSSL

    });



    return Data

}



var ct = encrypt('aaa', 'key', 'iv').toString();

console.log('암호화:' + ct);

console.log('복호화:' + decrypt(ct, 'key', 'iv').toString(CryptoJS.enc.Utf8));