//page.mainLogin(userId,util.encrypt($('.inpPw').val(), "adminCertification"))


// var passwd = util.encrypt($("#pw").val(),"userCertification");


/**
 * 관리자 계정 암호화
 */
const encrypt = (dataPw, division) => {
    //관리자인증에서 salt를 붙여서 사용자 비밀번호 암호화
    var shaSalt = "mcnc";
    var shaPw = CryptoJS.SHA256(dataPw + shaSalt).toString();
    //사용자 인증에서 사용자 비밀번호
    var password = dataPw;
    //이니셜 벡터 (암호화 알고리즘에서 필요)
    var iv = CryptoJS.lib.WordArray.random(128 / 8).toString(CryptoJS.enc.Hex);
    var salt = CryptoJS.lib.WordArray.random(128 / 8).toString(CryptoJS.enc.Hex);
    var keySize = 256;
    var iterationCount = 10000;
    var securityKey = "A조김예은";

    //PBKDF2 키 생성
    var key256Bits100Iterations =
        CryptoJS.PBKDF2(securityKey, CryptoJS.enc.Hex.parse(salt), {
            keySize: keySize / 32,
            iterations: iterationCount
        });
    //관리자인증
    if (division == "adminCertification") {
        var encrypted = CryptoJS.AES.encrypt(
            shaPw,
            key256Bits100Iterations, {
                iv: CryptoJS.enc.Hex.parse(iv)
            });
    }
    //사용자 인증
    else if (division == "userCertification") {
        var encrypted = CryptoJS.AES.encrypt(
            password,
            key256Bits100Iterations, {
                iv: CryptoJS.enc.Hex.parse(iv)
            });
    }
    var encryptedString = encrypted.toString();
    var passwd = iv + encryptedString + salt;
    return passwd;
}

encrypt()