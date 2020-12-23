const CryptoJS = require('crypto-js');

// mainLogin(userId, encrypt($('.inpPw').val(), "adminCertification"))

// const passwd = encrypt($("#pw").val(),"userCertification");

/** 테스트 input */
const TEST_PASSWORD = 'password';

/**
 * 관리자 계정 암호화
 */
const encrypt = function (dataPw) {
    //관리자인증에서 salt를 붙여서 사용자 비밀번호 암호화
    const sha256Salt = "mcnc";
    const sha256Password = CryptoJS.SHA256(dataPw + sha256Salt).toString();
    //사용자 인증에서 사용자 비밀번호
    const password = dataPw;
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
    //관리자인증
    let encrypted = CryptoJS.AES.encrypt(
        sha256Password,
        key256Bits10000Iterations, {
            iv: CryptoJS.enc.Hex.parse(iv)
        });

    const encryptedString = encrypted.toString();
    const passwd = iv + encryptedString + salt;
    return passwd;
}

const returnPassword = encrypt(TEST_PASSWORD);

console.log(returnPassword);