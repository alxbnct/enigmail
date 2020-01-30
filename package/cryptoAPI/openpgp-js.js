/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["getOpenPGPjsAPI"];


var Services = ChromeUtils.import("resource://gre/modules/Services.jsm").Services;
const pgpjs_keys = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keys.jsm").pgpjs_keys;
const pgpjs_keyStore = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keystore.jsm").pgpjs_keyStore;
const EnigmailLazy = ChromeUtils.import("chrome://enigmail/content/modules/lazy.jsm").EnigmailLazy;

const getKeyRing = EnigmailLazy.loader("enigmail/keyRing.jsm", "EnigmailKeyRing");

// Load generic API
Services.scriptloader.loadSubScript("chrome://enigmail/content/modules/cryptoAPI/interface.js",
  null, "UTF-8"); /* global CryptoAPI */


/**
 * OpenPGP.js implementation of CryptoAPI
 */

class OpenPGPjsCryptoAPI extends CryptoAPI {
  constructor() {
    super();
    this.api_name = "OpenPGP.js";
  }

  /**
   * Initialize the tools/functions required to run the API
   *
   * @param {nsIWindow} parentWindow: parent window, may be NULL
   * @param {Object} enigSvc: Enigmail service object
   * @param {String } preferredPath: try to use specific path to locate tool (gpg)
   */
  initialize(parentWindow, enigSvc, preferredPath) {
    let success = this.sync(pgpjs_keyStore.init());

    if (!success) throw "Init Error";
  }

  async getKeys(onlyKeys = null) {
    return pgpjs_keyStore.readKeyMetadata(onlyKeys);
  }

  async getStrippedKey(armoredKey, emailAddr) {
    return pgpjs_keys.getStrippedKey(armoredKey, emailAddr);
  }

  async getKeyListFromKeyBlock(keyBlockStr) {
    return pgpjs_keys.getKeyListFromKeyBlock(keyBlockStr);
  }

  /**
   * Import key(s) from a string provided
   *
   * @param {String} keyData:  the key data to be imported (ASCII armored)
   * @param {Boolean} minimizeKey: import the minimum key without any 3rd-party signatures
   * @param {String} limitedUid: only import the UID specified
   *
   * @return {Object} or null in case no data / error:
   *   - {Number}          exitCode:        result code (0: OK)
   *   - {Array of String) importedKeys:    imported fingerprints
   *   - {Number}          importSum:       total number of processed keys
   *   - {Number}          importUnchanged: number of unchanged keys
   */

  async importKeyData(keyData, minimizeKey, limitedUid) {
    if (minimizeKey) {
      keyData = await pgpjs_keys.getStrippedKey(keyData, limitedUid);
    }

    try {
      let imported = await pgpjs_keyStore.writeKey(keyData);

      return {
        exitCode: 0,
        importedKeys: imported,
        importSum: imported.length,
        importUnchanged: 0,
        secCount: 0,
        secDups: 0,
        secImported: 0
      };
    }
    catch (ex) {
      return {
        exitCode: 1,
        importedKeys: [],
        importSum: 0,
        importUnchanged: 0,
        secCount: 0,
        secDups: 0,
        secImported: 0
      };
    }
  }

  /**
   * Import key(s) from a file
   *
   * @param {nsIFile} inputFile:  the file holding the keys
   *
   * @return {Object} or null in case no data / error:
   *   - {Number}          exitCode:        result code (0: OK)
   *   - {Array of String) importedKeys:    imported fingerprints
   *   - {String}          errorMsg:        human readable error message
   *   - {Number}          importSum:       total number of processed keys
   *   - {Number}          importUnchanged: number of unchanged keys
   */
  async importKeyFromFile(inputFile) {
    const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;

    let fileData = EnigmailFiles.readBinaryFile(inputFile);
    return this.importKeyData(fileData, false, null);
  }

  /**
   * Delete keys from keyring
   *
   * @param {Array<String>} fpr: fingerprint(s) to delete
   * @param {Boolean} deleteSecretKey: if true, also delete secret keys [non-op]
   * @param {nsIWindow} parentWindow: parent window for displaying modal dialogs [non-op]
   *
   * @return {Promise<Object>}:
   *      - {Number} exitCode: 0 if successful, other values indicate error
   *      - {String} errorMsg: error message if deletion not successful
   */
  async deleteKeys(fpr, deleteSecretKey, parentWindow) {
    let exitCode = 1;
    try {
      await pgpjs_keyStore.deleteKeys(fpr);
      getKeyRing().updateKeys(fpr);

      exitCode = 0;
    }
    catch (ex) {}

    return {
      exitCode: exitCode,
      errorMsg: ""
    };
  }


  /**
   * Export public key(s) as ASCII armored data
   *
   * @param {String}  fpr         Fingerprint(s), separate mutliple keys with spaces
   * @param {Boolean} minimalKey  if true, reduce key(s) to minimum required
   *
   * @return {Object}:
   *   - {Number} exitCode:  result code (0: OK)
   *   - {String} keyData:   ASCII armored key data material
   *   - {String} errorMsg:  error message in case exitCode !== 0
   */

  async extractPublicKey(fpr) {
    let exitCode = 1,
      keyData = "";
    try {
      let fprArr = fpr.split(/[ ,\t]+/);
      keyData = await pgpjs_keyStore.readPublicKeys(fprArr);

      exitCode = 0;
    }
    catch (ex) {}

    return {
      exitCode: exitCode,
      keyData: keyData,
      errorMsg: ""
    };
  }


  /**
   * Export secret key(s) as ASCII armored data
   *
   * @param {String}  fpr       Specification by fingerprint(s) separate mutliple keys with spaces
   * @param {Boolean} minimalKey  if true, reduce key to minimum required
   *
   * @return {Object}:
   *   - {Number} exitCode:  result code (0: OK)
   *   - {String} keyData:   ASCII armored key data material
   *   - {String} errorMsg:  error message in case exitCode !== 0
   */

  async extractSecretKey(fpr, minimalKey) {
    let exitCode = 1,
      keyData = "";
    try {
      let fprArr = fpr.split(/[ ,\t]+/);
      keyData = await pgpjs_keyStore.readSecretKeys(fprArr, minimalKey);

      exitCode = 0;
    }
    catch (ex) {}

    return {
      exitCode: exitCode,
      keyData: keyData,
      errorMsg: ""
    };
  }

  /**
   * Export the minimum key for the public key object:
   * public key, user ID, newest encryption subkey
   *
   * @param {String} fpr  : a single FPR
   * @param {String} email: [optional] the email address of the desired user ID.
   *                        If the desired user ID cannot be found or is not valid, use the primary UID instead
   *
   * @return {Promise<Object>}:
   *    - exitCode (0 = success)
   *    - errorMsg (if exitCode != 0)
   *    - keyData: BASE64-encded string of key data
   */
  async getMinimalPubKey(fpr, email) {
    return pgpjs_keyStore.readMinimalPubKey(fpr, email);
  }

}


function getOpenPGPjsAPI() {
  return new OpenPGPjsCryptoAPI();
}
