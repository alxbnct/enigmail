/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["pgpjs_encrypt"];


var Services = ChromeUtils.import("resource://gre/modules/Services.jsm").Services;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const getOpenPGPLibrary = ChromeUtils.import("chrome://enigmail/content/modules/stdlib/openpgp-loader.jsm").getOpenPGPLibrary;
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
const pgpjs_keys = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keys.jsm").pgpjs_keys;
const pgpjs_keyStore = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keystore.jsm").pgpjs_keyStore;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;



/**
 * OpenPGP.js implementation of CryptoAPI
 *
 * Encryption-related functions
 */

var pgpjs_encrypt = {
  /**
   * Encrypt messages
   *
   * @param {String} from: keyID of sender/signer
   * @param {String} recipients: keyIDs of recipients, separated by spaces
   * @param {String} hiddenRecipients: keyIDs or email addresses of hidden recipients (bcc), separated by spaces
   * @param {Number} encryptionFlags: Flags for Signed/encrypted/PGP-MIME etc.
   * @param {String} plainText: data to encrypt
   * @param {String} hashAlgorithm: [OPTIONAL] hash algorithm
   * @param {nsIWindow} parentWindow: [OPTIONAL] window on top of which to display modal dialogs
   *
   * @return {Promise<Object>}:
   *     - {Number} exitCode:    0 = success / other values: error
   *     - {String} data:        encrypted data
   *     - {String} errorMsg:    error message in case exitCode !== 0
   *     - {Number} statusFlags: Status flags for result
   */

  encryptMessage: async function(from, recipients, hiddenRecipients, encryptionFlags, plainText, hashAlgorithm = null, parentWindow = null) {
    EnigmailLog.DEBUG(`pgpjs-encrypt.jsm: encryptMessage(${from}, ${recipients}, ${encryptionFlags}, ${plainText.length})\n`);

    let retObj = {
      exitCode: 1,
      data: "",
      errorMsg: "",
      statusFlags: 0
    };

    try {
      if (from.substr(0, 2) !== "0x") {
        throw Error("From address is not a key ID");
      }

      if (encryptionFlags & EnigmailConstants.SEND_ENCRYPTED) {
        if (!EnigmailConstants.SEND_SIGNED) {
          from = null;
        }

        let recipientArr = [];

        if (recipients && recipients.length > 0) {
          recipientArr = recipients.split(/ +/);
          for (let i of recipientArr) {
            if (i.substr(0, 2) !== "0x") {
              throw Error(`Recipient ${i} is not a key ID`);
            }
          }
        }

        let hiddenRcpt = [];
        if (hiddenRecipients && hiddenRecipients.length > 0) {
          hiddenRcpt = hiddenRecipients.split(/ +/);
          for (let i of recipientArr) {
            if (i.substr(0, 2) !== "0x") {
              throw Error(`Hidden recipient ${i} is not a key ID`);
            }
          }
        }

        recipientArr = recipientArr.concat(hiddenRcpt);

        if (encryptionFlags & EnigmailConstants.SEND_ENCRYPT_TO_SELF) recipientArr.push(from);
        let result = await encryptData(recipientArr, from, plainText);

        if ("data" in result) {
          retObj.data = result.data;
          retObj.exitCode = 0;
        }
      }
      else {
        const detachedSig = ((encryptionFlags & EnigmailConstants.SEND_PGP_MIME) ||
          (encryptionFlags & EnigmailConstants.SEND_ATTACHMENT));

        let result = await signData(from, plainText, detachedSig ? true : false);
        if ("signature" in result) {
          retObj.data = result.signature;
          retObj.exitCode = 0;

        }
        else if ("data" in result) {
          retObj.data = result.data;
          retObj.exitCode = 0;
        }
      }
    }
    catch (ex) {
      EnigmailLog.DEBUG(`pgpjs-encrypt.jsm: encryptMessage: ERROR: ${ex.toString()}\n`);
      retObj.errorMsg = ex.toString();
    }
    return retObj;
  }

};

async function encryptData(publicKeyIds, privateKeyId, text) {
  EnigmailLog.DEBUG(`pgpjs-encrypt.jsm: encryptData(${publicKeyIds.length}, ${privateKeyId})\n`);
  const PgpJS = getOpenPGPLibrary();

  let privateKeys = null;

  if (privateKeyId) {
    privateKeys = await pgpjs_keyStore.getKeysForKeyIds(true, [privateKeyId]);
    if (!await pgpjs_keys.decryptSecretKey(privateKeys[0], "sign message")) {
      throw Error("No password provided");
    }
  }

  let uniqueKeyIds = [...new Set(publicKeyIds)]; // make key IDs unique
  let publicKeys = await pgpjs_keyStore.getKeysForKeyIds(false, uniqueKeyIds);

  return await PgpJS.encrypt({
    message: PgpJS.message.fromText(text),
    publicKeys: publicKeys,
    privateKeys: privateKeys, // for signing
    streaming: false,
    armor: true
  });
}

async function signData(privateKeyId, text, detachedSignature) {
  EnigmailLog.DEBUG(`pgpjs-encrypt.jsm: signData(${privateKeyId})\n`);
  const PgpJS = getOpenPGPLibrary();

  let privateKeys = null;

  if (!privateKeyId) {
    throw Error("No private key provided");
  }

  privateKeys = await pgpjs_keyStore.getKeysForKeyIds(true, [privateKeyId]);
  if (!await pgpjs_keys.decryptSecretKey(privateKeys[0], "sign message")) {
    throw Error("No password provided");
  }

  return await PgpJS.sign({
    message: PgpJS.cleartext.fromText(text),
    privateKeys: privateKeys,
    streaming: false,
    detached: detachedSignature,
    armor: true
  });
}
