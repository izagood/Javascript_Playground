//page.mainLogin(userId,util.encrypt($('.inpPw').val(), "adminCertification"))


// var passwd = util.encrypt($("#pw").val(),"userCertification");

const PBKDF2_HMAC_SHA1 = "PBKDF2WithHmacSHA1";
const AES = "AES";
const AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding";
const UTF8 = "UTF-8";

const cryptoJS = require('crypto-js');
const aes = require('crypto-js/aes');
const hmacSha1 = require('crypto-js/hmac-sha1');
const pbkdf2 = require('crypto-js/pbkdf2');


const pbkdf2AesDecrypt = (salt, iv, SecurityKey, encryptedPasswd, iterationCount, keySize) => {

    const decryptedAES = this.cryptoJS.AES.decrypt(encryptedPasswd, 'A조김예은', { iv: iv });
    const decryptedPBKDF2HMACSHA1 = pbkdf2Sync()
    console.log(decrypted);

    const passwd = de;



    return passwd;

}
// public pbkdf2AesDecrypt(salt: string, iv: string, SecurityKey: string, encryptedPasswd: string,
//     iterationCount: number, keySize: number): string {
//     /** SecretKeyFactory에서 지원하는 PBKDF2-HMAC-SHA1 알고리즘을 적용*/
//     SecretKeyFactory factory = SecretKeyFactory.getInstance(this.PBKDF2_HMAC_SHA1);
//     /** Interface KeySpec을 PBEKeySpec생성자에 params를 넣어 구현
//      * 	salt가 16진수로 encoding되어 있기 때문에 16진수 byte[]로 decoding해준다.
//      *  decoding은 apache.commons.codec 라이브러리 사용 */
//     KeySpec spec = new PBEKeySpec(SecurityKey.toCharArray(), Hex.decodeHex(salt.toCharArray()), iterationCount, keySize);
//     /** Interface SecretKey를 SecretKeySpec생성자에 params를 넣어 구현
//      * AlgorithmParameters Algorithms name 중 AES 사용 */
//     SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), this.AES);
//     /** Cipher transformations 중 AES/CBC/PKCS5Padding(128bits) 사용 
//      *  PKCS5Padding은 RSA Laboratories, "PKCS #5: Password-Based Encryption Standard," version 1.5, November 1993.*/
//     Cipher cipher = Cipher.getInstance(this.AES_CBC_PKCS5PADDING);
//     /** iv가 16진수로 encoding되어 있기 때문에 16진수 byte[]로 decoding해준다.
//      *  @param int opmode : Cipher.DECRYPT_MODE : 2
//      *  @param Key key : key 
//      *  @param AlgorithmParameterSpec params : new IvParameterSpec(Hex.decodeHex(iv.toCharArray())) */
//     cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(Hex.decodeHex(iv.toCharArray())));
//     /* encryptedPasswd는 byte[]이고 Base64로 encoding되어 있기 때문에 Base64로 decoding해준다.*/
//     byte[] decrypted = cipher.doFinal(Base64.decodeBase64(encryptedPasswd));

//     return new String(decrypted, this.UTF8);
// }

const sortingEncryptedWord = (saltSize, ivSize, encryptedWord, SecurityKey, iterationCount, keySize) => {

    /** 암호문의 전체 길이*/
    const cryptPasswdLength = encryptedWord.length;
    /** 암호문에서 initial vector를 ivSize로 잘라줌 */
    const iv = encryptedWord.substring(0, ivSize);
    /** 암호문에서 passwd를 ivSize, saltSize로 잘라줌 */
    const encryptedPasswd = encryptedWord.substring(ivSize, cryptPasswdLength - saltSize);
    /** 암호문에서 salt를 saltSize로 잘라줌 */
    const salt = encryptedWord.substring(cryptPasswdLength - saltSize, cryptPasswdLength);

    return this.pbkdf2AesDecrypt(salt, iv, SecurityKey, encryptedPasswd, iterationCount, keySize);
}