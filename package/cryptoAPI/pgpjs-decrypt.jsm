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
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
const getOpenPGP = EnigmailLazy.loader("enigmail/openpgp.jsm", "EnigmailOpenPGP");
const getArmor = EnigmailLazy.loader("enigmail/armor.jsm", "EnigmailArmor");
const pgpjs_keys = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keys.jsm").pgpjs_keys;
const pgpjs_keyStore = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keystore.jsm").pgpjs_keyStore;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;


/**
 * OpenPGP.js implementation of CryptoAPI
 *
 * Decryption-related functions
 */

var pgpjs_decrypt = {
  /**
   * Decrypt a PGP/MIME-encrypted message
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

  decrypt: async function(encrypted, options) {
    EnigmailLog.DEBUG(`pgpjs-decrypt.jsm: decryptMime(${encrypted.length})\n`);

    const PgpJS = getOpenPGPLibrary();

    const retData = {
      decryptedData: "",
      exitCode: 0,
      statusFlags: EnigmailConstants.DECRYPTION_FAILED,
      userId: "",
      sigDetails: "",
      keyId: "",
      errorMsg: ""
    };


    try {
      let message = await PgpJS.message.readArmored(encrypted);

      // determine with which keys the message is encrypted
      let pubKeyIds = [];
      for (let i in message.packets) {
        try {
          pubKeyIds.push(message.packets[i].publicKeyId.toHex().toUpperCase());
        }
        catch (ex) {}
      }

      // get OpenPGP.js key objects for secret keys
      let secretKeys = await pgpjs_keyStore.getKeysForKeyIds(true, pubKeyIds.length === 0 ? null : pubKeyIds);

      // try to decrypt the message using the secret keys one-by-one
      for (let secKey of secretKeys) {
        if (await pgpjs_keys.decryptSecretKey(secKey)) {
          let result = await PgpJS.decrypt({
            message: message,
            privateKeys: secKey
          });

          // TODO: check multiple plaintexts, no MDC, etc.
          let verifiation;
          if (result && ("data" in result)) {
            retData.decryptedData = result.data;
            retData.statusFlags = EnigmailConstants.DECRYPTION_OKAY;

            if (options.uiFlags & EnigmailConstants.UI_PGP_MIME) {
              retData.statusFlags |= EnigmailConstants.PGP_MIME_ENCRYPTED;
            }

            // check signature and return first verified signature
            if ("signatures" in result) {
              let pkt = new PgpJS.packet.List();

              for (let sig of result.signatures) {
                pkt.concat(sig.signature.packets);
              }
              verifiation = await this.verifyDetached(result.data,
                await PgpJS.armor.encode(PgpJS.enums.armor.signature, pkt.write(), 0, 0));

              if (verifiation.exitCode === 0) {
                retData.statusFlags += verifiation.statusFlags;
                retData.sigDetails = verifiation.sigDetails;
                retData.keyId = verifiation.keyId;
                retData.userId = verifiation.userId;
                retData.errorMsg = verifiation.errorMsg;
              }
            }
          }
        }
      }
    }
    catch (ex) {
      retData.exitCode = 1;
      retData.errorMsg = ex.toString(); // FIXME
    }
    return retData;
  },

  verify: async function(data, options) {

  },

  /**
   * Verify a message with a detached signature
   *
   * @param {String} data: the data to verify
   * @param {String} signature: ASCII armored signature
   *
   * @return {Promise<Object>}: ResultObj
   */
  verifyDetached: async function(data, signature) {
    EnigmailLog.DEBUG(`pgpjs-decrypt.jsm: verifyDetached(${data.length})\n`);
    const PgpJS = getOpenPGPLibrary();

    let sigObj = await PgpJS.signature.readArmored(signature);
    let keyIds = sigObj.packets.map(pkt => {
      return pkt.issuerKeyId.toHex().toUpperCase();
    });

    let pubKeys = await pgpjs_keyStore.getKeysForKeyIds(false, keyIds);
    let msg;

    if (sigObj.packets[0].signatureType === PgpJS.enums.signature.binary) {
      msg = PgpJS.message.fromText(data);
    }
    else {
      msg = PgpJS.cleartext.fromText(data);
    }

    return this.verifyMessage({
      message: msg,
      signature: sigObj,
      publicKeys: pubKeys
    });
  },

  /**
   * Verify a message and return the signature verification status
   *
   * @param {Object} verifyObj: OpenPGP.js Message
   *
   * @return {Promise<Object>} ResultObj
   */
  verifyMessage: async function(verifyObj) {
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
      statusFlags: 0,
      exitCode: 1,
      sigDetails: "",
      keyId: "",
      userId: "",
      errorMsg: ""
    };

    let currentKey = null,
      signatureStatus = -1,
      pubKeys = verifyObj.publicKeys;

    try {
      let verifiation = await PgpJS.verify(verifyObj);

      for (let sig of verifiation.signatures) {
        let currentStatus = -1;
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
        }
        else if (!sig.valid) {
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
            const pkt = sig.signature.packets[0];
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

      switch (signatureStatus) {
        case SIG_STATUS.unknown_key:
          result.statusFlags = EnigmailConstants.UNVERIFIED_SIGNATURE;
          break;
        case SIG_STATUS.bad_signature:
          result.statusFlags = EnigmailConstants.BAD_SIGNATURE;
          break;
        case SIG_STATUS.good_sig_invalid_key:
          result.statusFlags = EnigmailConstants.GOOD_SIGNATURE + EnigmailConstants.REVOKED_KEY;
          break;
        case SIG_STATUS.good_sig_expired_key:
          result.statusFlags = EnigmailConstants.GOOD_SIGNATURE + EnigmailConstants.EXPIRED_KEY;
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

      result.exitCode = 0;
    }
    catch (ex) {
      EnigmailLog.DEBUG(`pgpjs-decrypt.jsm: verifyDetached: error: ${ex.toString()} ${ex.stack}\n`);
    }

    return result;
  }
};
