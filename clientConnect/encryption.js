const CryptoJS = require('crypto-js');

// mainLogin(userId, encrypt($('.inpPw').val(), "adminCertification"))

// const passwd = encrypt($("#pw").val(),"userCertification");

/** 테스트 input */
const TEST_PASSWORD = 'leejaebin';
const ADMIN_LOGIN = 'adminCertification';
const USER_LOGIN = 'userCertification';

/**
 * 관리자 계정 암호화
 */
const encrypt = function(dataPw, division) {
    //관리자인증에서 salt를 붙여서 사용자 비밀번호 암호화
    const shaSalt = "mcnc";
    const shaPw = CryptoJS.SHA256(dataPw + shaSalt).toString();
    //사용자 인증에서 사용자 비밀번호
    const password = dataPw;
    //이니셜 벡터 (암호화 알고리즘에서 필요)
    const iv = CryptoJS.lib.WordArray.random(128 / 8).toString(CryptoJS.enc.Hex);
    const salt = CryptoJS.lib.WordArray.random(128 / 8).toString(CryptoJS.enc.Hex);
    const keySize = 256;
    const iterationCount = 10000;
    const securityKey = "A조김예은";

    //PBKDF2 키 생성
    const key256Bits100Iterations =
        CryptoJS.PBKDF2(securityKey, CryptoJS.enc.Hex.parse(salt), {
            keySize: keySize / 32,
            iterations: iterationCount
        });
    //관리자인증
    let encrypted;
    if (division == "adminCertification") {
        encrypted = CryptoJS.AES.encrypt(
            shaPw,
            key256Bits100Iterations, {
                iv: CryptoJS.enc.Hex.parse(iv)
            });
    }
    //사용자 인증
    else if (division == "userCertification") {
        encrypted = CryptoJS.AES.encrypt(
            password,
            key256Bits100Iterations, {
                iv: CryptoJS.enc.Hex.parse(iv)
            });
    }
    const encryptedString = encrypted.toString();
    const passwd = iv + encryptedString + salt;
    return passwd;
}

const returnPassword = encrypt(TEST_PASSWORD, USER_LOGIN);

console.log(returnPassword);