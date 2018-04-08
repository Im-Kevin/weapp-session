const co = require('co');
const merge = require('merge');
const config = require('./config');
const { headers, errors } = require('./constants');
const makeStore = require('./lib/makeStore');
const sha1 = require('./lib/sha1');
const wrapError = require('./lib/wrapError');
const jscode2session = require('./lib/jscode2session');
const Crypto = require('cryptojs/cryptojs.js').Crypto;

let store;

const handler = co.wrap(function *(req, res, next) {
    req.$wxUserInfo = null;

    if (config.ignore(req, res)) {
        return next();
    }

    let code = String(req.header(headers.WX_CODE) || '');
    let rawData = String(req.header(headers.WX_RAW_DATA) || '');
    let signature = String(req.header(headers.WX_SIGNATURE) || '');
    let ecryptedData = String(req.header(headers.WX_ENCRYPTED_DATA) || '');

    let wxUserInfo, sessionKey, openId;

    // 1、`code` not passed
    if (!code) {
        return next();
    }

    // 2、`rawData` not passed
    if (!rawData) {
        try {
            wxUserInfo = yield store.get(code);
        } catch (error) {
            return next(error);
        }

        if (!wxUserInfo) {
            let error = new Error('`wxUserInfo` not found by `code`');
            return res.json(wrapError(error, { reason: errors.ERR_SESSION_EXPIRED }));
        }

        req.$wxUserInfo = wxUserInfo;
        return next();
    }

    // 3、both `code` and `rawData` passed

    try {
        rawData = decodeURIComponent(rawData);
        wxUserInfo = JSON.parse(rawData);
    } catch (error) {
        return res.json(wrapError(error));
    }

    if (config.ignoreSignature === true) {
        openId = ('PSEUDO_OPENID_' + sha1(wxUserInfo.avatarUrl)).slice(0, 28);
    } else {
        try {
            ({ sessionKey, openId } = yield jscode2session.exchange(code));
        } catch (error) {
            return res.json(wrapError(error, { reason: errors.ERR_SESSION_KEY_EXCHANGE_FAILED }));
        }

        // check signature
        if (sha1(rawData + sessionKey) !== signature) {
            let error = new Error('untrusted raw data');
            return res.json(wrapError(error, { reason: errors.ERR_UNTRUSTED_RAW_DATA }));
        }
    }

    try {
        if(sessionKey)
        {
            ecryptedData = decodeURIComponent(ecryptedData);
            let jsEcryptedData = JSON.parse(ecryptedData);
            let tempObj = decryptData(config.appId,sessionKey,jsEcryptedData.data,jsEcryptedData.iv);
            tempObj.language = wxUserInfo.language;
            wxUserInfo = tempObj;
        }else{
            wxUserInfo.openId = openId;
        }

        let oldCode = yield store.get(openId);
        oldCode && (yield store.del(oldCode));

        yield store.set(code, wxUserInfo, config.redisConfig.ttl);
        yield store.set(openId, code, config.redisConfig.ttl);

        req.$wxUserInfo = wxUserInfo;
        return next();

    } catch (error) {
        return next(error);
    }

});

function decryptData(appId,sessionKey,_encryptedData, _iv) {
    // base64 decode ：使用 CryptoJS 中 Crypto.util.base64ToBytes()进行 base64解码
    let encryptedData = Crypto.util.base64ToBytes(_encryptedData);
    let key = Crypto.util.base64ToBytes(sessionKey);
    let iv = Crypto.util.base64ToBytes(_iv);
    let decryptResult = null;


    // 对称解密使用的算法为 AES-128-CBC，数据采用PKCS#7填充
    let mode = new Crypto.mode.CBC(Crypto.pad.pkcs7);

    try {
        // 解密
        let bytes = Crypto.AES.decrypt(encryptedData, key, {
            asBpytes:true,
            iv: iv,
            mode: mode
        });
        decryptResult = JSON.parse(bytes);

    } catch (err) {
        console.log(err)
    }

    if (decryptResult.watermark.appid !== appId) {
        console.log(err)
    }

    return decryptResult
}

module.exports = (options = {}) => {
    if (!store) {
        merge.recursive(config, options);
        store = makeStore(config.redisConfig);
        return handler;
    }

    throw new Error('weapp-session can only be called once.');
};