const CryptoJS = require('crypto-js');

// mainLogin(userId, encrypt($('.inpPw').val(), "adminCertification"))

// const passwd = encrypt($("#pw").val(),"userCertification");

/** 테스트 input */
const TEST_PASSWORD = 'password';

/**
 * 관리자 계정 암호화
 */
const encrypt = function (userPassword) {
    //사용자 비밀번호
    const password = userPassword;

    //이니셜 벡터 (암호화 알고리즘에서 필요)
    const iv = CryptoJS.lib.WordArray.random(128 / 8).toString(CryptoJS.enc.Hex);
    const salt = CryptoJS.lib.WordArray.random(128 / 8).toString(CryptoJS.enc.Hex);
    const keySize = 256;
    const iterationCount = 10000;
    const securityKey = "A조김예은";

    //PBKDF2 키 생성
    const key256Bits10000Iterations =
        CryptoJS.PBKDF2(securityKey, CryptoJS.enc.Hex.parse(salt), {
            keySize: keySize / 32,
            iterations: iterationCount
        });
    const encrypted = CryptoJS.AES.encrypt(
        password,
        key256Bits10000Iterations, {
            iv: CryptoJS.enc.Hex.parse(iv)
        });
    const encryptedString = encrypted.toString();
    const passwd = iv + encryptedString + salt;
    return passwd;
}

const returnPassword = encrypt(TEST_PASSWORD);

console.log(returnPassword);