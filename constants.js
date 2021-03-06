module.exports = {
    headers: {
        WX_CODE: 'X-WX-Code',
        WX_RAW_DATA: 'X-WX-RawData',
        WX_SIGNATURE: 'X-WX-Signature',
        WX_ENCRYPTED_DATA:'X-WX-EncryptedData'
    },

    errors: {
        ERR_SESSION_EXPIRED: 'ERR_SESSION_EXPIRED',
        ERR_SESSION_KEY_EXCHANGE_FAILED: 'ERR_SESSION_KEY_EXCHANGE_FAILED',
        ERR_UNTRUSTED_RAW_DATA: 'ERR_UNTRUSTED_RAW_DATA',
    },

    SESSION_MAGIC_ID: 'F2C224D4-2BCE-4C64-AF9F-A6D872000D1A',
};