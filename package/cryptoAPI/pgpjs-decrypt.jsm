/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["pgpjs_decrypt"];


var Services = ChromeUtils.import("resource://gre/modules/Services.jsm").Services;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailLazy = ChromeUtils.import("chrome://enigmail/content/modules/lazy.jsm").EnigmailLazy;
const getOpenPGPLibrary = ChromeUtils.import("chrome://enigmail/content/modules/stdlib/openpgp-loader.jsm").getOpenPGPLibrary;
const EnigmailTime = ChromeUtils.import("chrome://enigmail/content/modules/time.jsm").EnigmailTime;
const EnigmailFuncs = ChromeUtils.import("chrome://enigmail/content/modules/funcs.jsm").EnigmailFuncs;
const EnigmailData = ChromeUtils.import("chrome://enigmail/content/modules/data.jsm").EnigmailData;
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
const getOpenPGP = EnigmailLazy.loader("enigmail/openpgp.jsm", "EnigmailOpenPGP");
const getArmor = EnigmailLazy.loader("enigmail/armor.jsm", "EnigmailArmor");
const pgpjs_keys = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keys.jsm").pgpjs_keys;
const pgpjs_keyStore = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keystore.jsm").pgpjs_keyStore;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;

Components.utils.importGlobalProperties(["TextDecoder"]);

/**
 * OpenPGP.js implementation of CryptoAPI
 *
 * Decryption-related functions
 */

var pgpjs_decrypt = {
  /**
   * Process an OpenPGP message
   *
   * @param {String} encrypted     The encrypted data
   * @param {Object} options       Decryption options
   *
   * @return {Promise<Object>} - Return object with decryptedData and status information:
   *     - {String} decryptedData
   *     - {Number} exitCode
   *     - {Number} statusFlags
   *     - {String} errorMsg
   *     - {String} blockSeparation
   *
   * Use Promise.catch to handle failed decryption.
   * retObj.errorMsg will be an error message in this case.
   */

  processPgpMessage: async function(encrypted, options) {
    EnigmailLog.DEBUG(`pgpjs-decrypt.jsm: processPgpMessage(${encrypted.length})\n`);

    const PgpJS = getOpenPGPLibrary();
    const retData = getReturnObj();

    try {
      let message = await PgpJS.message.readArmored(encrypted);

      if (message.packets[0].tag === PgpJS.enums.packet.compressed) {
        message = await message.unwrapCompressed();
      }

      // determine with which keys the message is encrypted
      let pubKeyIds = message.getEncryptionKeyIds().map(keyId => {
        return keyId.toHex().toUpperCase();
      });

      if (pubKeyIds.length === 0 && message.getSigningKeyIds().length > 0) {
        // message is signed only
        return this.verifyMessage(message, true);
      }

      if (message.packets[0].tag === PgpJS.enums.packet.literal) {
        retData.decryptedData = await readFromStream(message.getLiteralData().getReader());
        retData.statusFlags = 0;
        return retData;
      }

      return this.decryptMessage(message, pubKeyIds, options);
    }
    catch (ex) {
      EnigmailLog.DEBUG(`pgpjs-decrypt.jsm: processPgpMessage: ERROR: ${ex.toString()}\n`);
      retData.errorMsg = ex.toString();
      retData.exitCode = 1;
    }

    return retData;
  },

  decryptMessage: async function(message, pubKeyIds, options) {
    EnigmailLog.DEBUG(`pgpjs-decrypt.jsm: decryptMessage(${pubKeyIds.join(", ")})\n`);

    const PgpJS = getOpenPGPLibrary();
    const retData = getReturnObj();
    let encToDetails = "";

    try {
      encToDetails = getKeydesc(pubKeyIds);

      // get OpenPGP.js key objects for secret keys
      let secretKeys = await pgpjs_keyStore.getKeysForKeyIds(true, pubKeyIds.length === 0 ? null : pubKeyIds);

      if (secretKeys.length === 0) {
        retData.statusFlags |= EnigmailConstants.NO_SECKEY;
      }

      // try to decrypt the message using the secret keys one-by-one
      for (let secKey of secretKeys) {
        if (await pgpjs_keys.decryptSecretKey(secKey, EnigmailConstants.KEY_DECRYPT_REASON_ENCRYPTED_MSG)) {
          let result = await PgpJS.decrypt({
            message: message,
            format: "binary",
            privateKeys: secKey
          });

          // TODO: check multiple plaintexts, etc.
          let verifiation;
          if (result && ("data" in result)) {
            retData.decryptedData = ensureString(result.data);
            retData.statusFlags = EnigmailConstants.DECRYPTION_OKAY;

            if (options.uiFlags & EnigmailConstants.UI_PGP_MIME) {
              retData.statusFlags |= EnigmailConstants.PGP_MIME_ENCRYPTED;
            }

            // check signature and return first verified signature
            if ("signatures" in result && result.signatures.length > 0) {
              let pkt = new PgpJS.packet.List();

              for (let sig of result.signatures) {
                pkt.concat(sig.signature.packets);
              }
              verifiation = await this.verifyDetached(result.data, pkt);

              if (verifiation.exitCode !== 2) {
                retData.statusFlags += verifiation.statusFlags;
                retData.sigDetails = verifiation.sigDetails;
                retData.keyId = verifiation.keyId;
                retData.userId = verifiation.userId;
                retData.errorMsg = verifiation.errorMsg;
              }
            }
          }
        }
        else {
          EnigmailLog.DEBUG(`pgpjs-decrypt.jsm: decrypt invalid or no passphrase supplied\n`);
          retData.statusFlags |= EnigmailConstants.BAD_PASSPHRASE;
        }
      }
    }
    catch (ex) {
      if (("message" in ex) && ex.message.search(/(missing MDC|Modification detected)/) > 0) {
        retData.statusFlags |= EnigmailConstants.MISSING_MDC;
        retData.statusMsg = EnigmailLocale.getString("missingMdcError") + "\n";
      }
      else {
        EnigmailLog.DEBUG(`pgpjs-decrypt.jsm: decryptMessage: ERROR: ${ex.toString()}\n`);
        retData.exitCode = 1;
        retData.errorMsg = ex.toString();
      }
    }

    retData.encToDetails = encToDetails;
    return retData;
  },

  verify: async function(data, options) {
    EnigmailLog.DEBUG(`pgpjs-decrypt.jsm: verify(${data.length})\n`);

    const PgpJS = getOpenPGPLibrary();
    const result = getReturnObj();
    const Armor = getArmor();
    let blocks = Armor.locateArmoredBlocks(data);

    result.statusFlags = 0;
    result.exitCode = 1;

    try {
      if (blocks && blocks.length > 0) {
        if (blocks[0].blocktype === "SIGNED MESSAGE") {
          let msg = await PgpJS.cleartext.readArmored(data.substring(blocks[0].begin, blocks[0].end));

          if (msg && "signature" in msg) {
            return await this.verifyDetached(msg.text, msg.signature.armor(), true);
          }
        }
      }
    }
    catch (ex) {
      EnigmailLog.DEBUG(`pgpjs-decrypt.jsm: verify: ERROR: ${ex.toString()}\n`);
      result.errorMsg = ex.toString();
      result.statusFlags = EnigmailConstants.UNVERIFIED_SIGNATURE;
    }
    return result;
  },

  /**
   * Verify a message with a detached signature
   *
   * @param {String|Uint8Array} data: the data to verify
   * @param {String} signature: ASCII armored signature
   * @param {Boolean} returnData: if true, inculde the verified data in the result
   *
   * @return {Promise<Object>}: ResultObj
   */
  verifyDetached: async function(data, signature, returnData = false) {
    EnigmailLog.DEBUG(`pgpjs-decrypt.jsm: verifyDetached(${data.length})\n`);
    const PgpJS = getOpenPGPLibrary();

    let result = getReturnObj();
    let sigObj;

    if (typeof(signature) === "string") {
      sigObj = await PgpJS.signature.readArmored(signature);
    }
    else
      sigObj = {
        packets: signature
      };

    if (sigObj.packets.length === 0) {
      result.exitCode = 1;
      result.statusFlags = EnigmailConstants.NO_PUBKEY;
      result.errorMsg = EnigmailLocale.getString("unverifiedSig") + EnigmailLocale.getString("msgTypeUnsupported");
      return result;
    }
    let msg;

    if (sigObj.packets[0].signatureType === PgpJS.enums.signature.binary) {
      msg = PgpJS.message.fromBinary(ensureUint8Array(data));
      msg.packets.concat(sigObj.packets);
    }
    else {
      msg = PgpJS.cleartext.fromText(ensureString(data));
      msg.signature.packets.concat(sigObj.packets);
    }

    return this.verifyMessage(msg, returnData);
  },

  /**
   * Verify a message and return the signature verification status
   *
   * @param {Object} messageObj: OpenPGP.js Message
   * @param {Boolean} returnData: if true, inculde the verified data in the result
   *
   * @return {Promise<Object>} ResultObj
   */
  verifyMessage: async function(messageObj, returnData = false) {
    EnigmailLog.DEBUG(`pgpjs-decrypt.jsm: verifyMessage()\n`);
    const PgpJS = getOpenPGPLibrary();
    const SIG_STATUS = {
      unknown_key: 0,
      bad_signature: 1,
      good_sig_invalid_key: 2,
      good_sig_expired_key: 3,
      valid_signature: 4
    };

    const result = {
      statusFlags: EnigmailConstants.UNVERIFIED_SIGNATURE,
      exitCode: 2,
      sigDetails: "",
      keyId: "",
      userId: "",
      errorMsg: "",
      blockSeparation: "",
      decryptedData: ""
    };

    let currentKey = null,
      signatureStatus = -1;

    let keyIds = messageObj.getSigningKeyIds().map(keyId => {
      return keyId.toHex().toUpperCase();
    });

    let pubKeys = await pgpjs_keyStore.getKeysForKeyIds(false, keyIds);

    try {
      let ret = (await PgpJS.verify({
        message: messageObj,
        publicKeys: pubKeys
      }));

      if (returnData && ("data" in ret)) {
        result.decryptedData = ensureString(ret.data);
      }

      for (let sig of ret.signatures) {
        let currentStatus = -1,
          sigValid = await sig.verified;
        currentKey = null;
        let keyId = sig.keyid.toHex();

        for (let k of pubKeys) {
          if (k.getKeyId().toHex() === keyId) {
            currentKey = k;
            break;
          }
        }

        if (currentKey === null) {
          currentStatus = SIG_STATUS.unknown_key;
          result.keyId = keyId.toUpperCase();
        }
        else if (!sigValid) {
          currentStatus = SIG_STATUS.bad_signature;
          result.keyId = keyId.toUpperCase();
        }
        else {
          if (!sigValid) {
            currentStatus = SIG_STATUS.bad_signature;
          }
          else {
            let keyStatus = await currentKey.verifyPrimaryKey();
            switch (keyStatus) {
              case PgpJS.enums.keyStatus.invalid:
              case PgpJS.enums.keyStatus.revoked:
              case PgpJS.enums.keyStatus.no_self_cert:
                currentStatus = SIG_STATUS.good_sig_invalid_key;
                break;
              case PgpJS.enums.keyStatus.expired:
                currentStatus = SIG_STATUS.good_sig_expired_key;
                break;
              case PgpJS.enums.keyStatus.valid:
                currentStatus = SIG_STATUS.valid_signature;
                break;
              default:
                currentStatus = SIG_STATUS.unknown_key;
            }
          }

          if (currentStatus >= signatureStatus) {
            /*  VALIDSIG args are (separated by space):
                - <fingerprint_in_hex>
                - <sig_creation_date>
                - <sig-timestamp>
                - <expire-timestamp>
                - <sig-version>
                - <reserved>
                - <pubkey-algo>
                - <hash-algo>
                - <sig-class>
                - [ <primary-key-fpr> ]
            */
            const pkt = (await sig.signature).packets[0];
            result.keyId = currentKey.getFingerprint().toUpperCase();
            result.sigDetails = result.keyId + " " +
              pkt.created.toISOString().substr(0, 10) + " " +
              (pkt.created.getTime() / 1000) + " " +
              (pkt.signatureNeverExpires ? "0" : pkt.signatureExpirationTime.getTime() / 1000) + " " +
              pkt.version + " 0 " +
              pkt.publicKeyAlgorithm + " " +
              pkt.hashAlgorithm + " 00 " + result.keyId;
          }
        }

        signatureStatus = Math.max(signatureStatus, currentStatus);
      }

      result.exitCode = 0;
      switch (signatureStatus) {
        case SIG_STATUS.unknown_key:
          result.statusFlags = EnigmailConstants.NO_PUBKEY | EnigmailConstants.UNVERIFIED_SIGNATURE;
          break;
        case SIG_STATUS.bad_signature:
          result.statusFlags = EnigmailConstants.BAD_SIGNATURE;
          result.exitCode = 1;
          break;
        case SIG_STATUS.good_sig_invalid_key:
          result.statusFlags = EnigmailConstants.GOOD_SIGNATURE | EnigmailConstants.REVOKED_KEY;
          break;
        case SIG_STATUS.good_sig_expired_key:
          result.statusFlags = EnigmailConstants.GOOD_SIGNATURE | EnigmailConstants.EXPIRED_KEY;
          break;
        case SIG_STATUS.valid_signature:
          result.statusFlags = EnigmailConstants.GOOD_SIGNATURE;
      }

      if (currentKey) {
        result.userId = currentKey.users[0].userId.userid;
      }

      if (result.statusFlags & EnigmailConstants.GOOD_SIGNATURE) {
        result.errorMsg = EnigmailLocale.getString("prefGood", [result.userId]);
      }
      else if (result.statusFlags & EnigmailConstants.BAD_SIGNATURE) {
        result.errorMsg = EnigmailLocale.getString("prefBad", [result.userId]);
      }
    }
    catch (ex) {
      EnigmailLog.DEBUG(`pgpjs-decrypt.jsm: verifyDetached: ERROR: ${ex.toString()} ${ex.stack}\n`);
    }

    return result;
  }
};

/**
 * Take a string or Uint8Array and if needed convert it to a string.
 *
 * @param {String|Uint8Array} stringOrUint8Array: input data
 *
 * @return {String}
 */
function ensureString(stringOrUint8Array) {
  if (typeof stringOrUint8Array === "string") {
    return stringOrUint8Array;
  }

  return EnigmailData.arrayBufferToString(stringOrUint8Array);
}

function ensureUint8Array(stringOrUint8Array) {
  if (typeof stringOrUint8Array === "string") {
    return new Uint8Array(Array.from(stringOrUint8Array, c => c.charCodeAt(0)));
  }

  return stringOrUint8Array;
}

function readFromStream(reader) {
  let result = "";

  return new Promise((resolve, reject) => {
    reader.read().then(function processText({
      done,
      value
    }) {
      // Result objects contain two properties:
      // done  - true if the stream has already given you all its data.
      // value - some data. Always undefined when done is true.
      if (done) {
        resolve(result);
        return null;
      }

      // value for fetch streams is a Uint8Array
      result += ensureString(value);

      // Read some more, and call this function again
      return reader.read().then(processText);
    });
  });
}

function getKeydesc(pubKeyIds) {
  EnigmailLog.DEBUG(`pgpjs-decrypt.jsm: getKeydesc()\n`);
  const EnigmailKeyRing = ChromeUtils.import("chrome://enigmail/content/modules/keyRing.jsm").EnigmailKeyRing;

  if (pubKeyIds.length > 0) {
    let encToArray = [];
    // for each key also show an associated user ID if known:
    for (let keyId of pubKeyIds) {
      // except for ID 00000000, which signals hidden keys
      if (keyId.search(/^0+$/) < 0) {
        let localKey = EnigmailKeyRing.getKeyById("0x" + keyId);
        if (localKey) {
          encToArray.push(`0x${keyId} (${localKey.userId})`);
        }
        else {
          encToArray.push(`0x${keyId}`);
        }
      }
      else {
        encToArray.push(EnigmailLocale.getString("hiddenKey"));
      }
    }
    return "\n  " + encToArray.join(",\n  ") + "\n";
  }

  return "";
}

function getReturnObj() {
  return {
    decryptedData: "",
    exitCode: 0,
    statusFlags: EnigmailConstants.DECRYPTION_FAILED,
    userId: "",
    sigDetails: "",
    keyId: "",
    errorMsg: "",
    encToDetails: "",
    blockSeparation: ""
  };
}
