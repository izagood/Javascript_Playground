const CryptoJS = require('crypto-js');

const encrypt = function (pText, init_key, init_iv) {

    var key = CryptoJS.enc.Utf8.parse(init_key);

    var iv = CryptoJS.enc.Utf8.parse(init_iv);

    var encryptData = CryptoJS.AES.encrypt(pText, key, {

        iv: iv

    });

    return encryptData
}

const decrypt = function (encryptData, init_key, init_iv) {

    var key = CryptoJS.enc.Utf8.parse(init_key);

    var iv = CryptoJS.enc.Utf8.parse(init_iv);

    var Data = CryptoJS.AES.decrypt(encryptData, key, {

        iv: iv

    });

    return Data
}

// 테스트
var ct = encrypt('aaa', 'key', 'iv').toString();

console.log('암호화:' + ct);

console.log('복호화:' + decrypt(ct, 'key', 'iv').toString());