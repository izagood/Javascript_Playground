// 클라쪽에서 올때
//page.mainLogin(userId,util.encrypt($('.inpPw').val(), "adminCertification"))
// var passwd = util.encrypt($("#pw").val(),"userCertification");

const testPassword = '464504872f6e3079ad8d30b4c6ebc605av+n0p1q5ssmpBH5iyWtTA==ff0bc4341a6260c90bdbafde5897cbe5';

const CryptoJS = require('crypto-js');

const pbkdf2AesDecrypt = function (salt, iv, SecurityKey, encryptedPasswd, iterationCount, keySize) {
    // AES -> PBKDF2 로 변경

    const key256Bits10000Iterations =
        CryptoJS.PBKDF2(SecurityKey, CryptoJS.enc.Hex.parse(salt), {
            keySize: keySize / 32,
            iterations: iterationCount
        });

    const decryptedAES = CryptoJS.AES.decrypt(
        encryptedPasswd,
        key256Bits10000Iterations, {
            iv: CryptoJS.enc.Hex.parse(iv)
        }
    );
    const password = decryptedAES.toString(CryptoJS.enc.Utf8);

    return password;

}

const sortingEncryptedWord = function (saltSize, ivSize, encryptedWord, SecurityKey, iterationCount, keySize) {

    /** 암호문의 전체 길이*/
    const cryptPasswdLength = encryptedWord.length;
    /** 암호문에서 initial vector를 ivSize로 잘라줌 */
    const iv = encryptedWord.substring(0, ivSize);
    /** 암호문에서 passwd를 ivSize, saltSize로 잘라줌 */
    const encryptedPasswd = encryptedWord.substring(ivSize, cryptPasswdLength - saltSize);
    /** 암호문에서 salt를 saltSize로 잘라줌 */
    const salt = encryptedWord.substring(cryptPasswdLength - saltSize, cryptPasswdLength);

    return pbkdf2AesDecrypt(salt, iv, SecurityKey, encryptedPasswd, iterationCount, keySize);
}

console.log(sortingEncryptedWord(32, 32, testPassword, 'A조김예은', 10000, 256));