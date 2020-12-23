const CryptoJS = require('crypto-js');

// const dataPw = 'password1234'

// const sha256Salt = 'mcnc';
// const sha256Password = CryptoJS.SHA256(dataPw + sha256Salt).toString(CryptoJS.enc.SHA256);

const iv = CryptoJS.lib.WordArray.random(128 / 8).toString()

console.log(iv)
for (var i in iv){
    console.log(i)
}
