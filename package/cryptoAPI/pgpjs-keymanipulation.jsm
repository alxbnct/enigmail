/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["pgpjs_keymanipulation"];


var Services = ChromeUtils.import("resource://gre/modules/Services.jsm").Services;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailLazy = ChromeUtils.import("chrome://enigmail/content/modules/lazy.jsm").EnigmailLazy;
const getOpenPGPLibrary = ChromeUtils.import("chrome://enigmail/content/modules/stdlib/openpgp-loader.jsm").getOpenPGPLibrary;
const EnigmailTime = ChromeUtils.import("chrome://enigmail/content/modules/time.jsm").EnigmailTime;
const EnigmailTimer = ChromeUtils.import("chrome://enigmail/content/modules/timer.jsm").EnigmailTimer;
const EnigmailData = ChromeUtils.import("chrome://enigmail/content/modules/data.jsm").EnigmailData;
const EnigmailFuncs = ChromeUtils.import("chrome://enigmail/content/modules/funcs.jsm").EnigmailFuncs;
const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
const getOpenPGP = EnigmailLazy.loader("enigmail/openpgp.jsm", "EnigmailOpenPGP");
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
const pgpjs_keyStore = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keystore.jsm").pgpjs_keyStore;
const pgpjs_keys = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keys.jsm").pgpjs_keys;

const NS_WRONLY = 0x02;
const NS_CREATE_FILE = 0x08;
const NS_TRUNCATE = 0x20;
const STANDARD_FILE_PERMS = 0o600;
const NS_LOCALFILEOUTPUTSTREAM_CONTRACTID = "@mozilla.org/network/file-output-stream;1";


/**
 * OpenPGP.js implementation of CryptoAPI
 */

var pgpjs_keymanipulation = {
  genRevokeCert: async function(parentWindow, keyId, outFile, reasonCode, reasonText) {
    EnigmailLog.DEBUG(`pgpjs-keymanipulation.jsm: genRevokeCert: keyId=${keyId}\n`);

    const PgpJS = getOpenPGPLibrary();

    let keyList = await pgpjs_keyStore.getKeysForKeyIds(true, [keyId]);

    if (!keyList || keyList.length === 0) {
      return createError(EnigmailLocale.getString("keyNotFound", keyId));
    }

    let revokeReason = 0;
    switch (reasonCode) {
      case "1":
        revokeReason = PgpJS.enums.reasonForRevocation.key_compromised;
        break;
      case "2":
        revokeReason = PgpJS.enums.reasonForRevocation.key_superseded;
        break;
      case "3":
        revokeReason = PgpJS.enums.reasonForRevocation.key_retired;
    }

    const res = await pgpjs_keys.decryptSecretKey(keyList[0], EnigmailConstants.KEY_DECRYPT_REASON_MANIPULATE_KEY);
    if (!res) {
      return createError(EnigmailLocale.getString("noPassphrase"));
    }

    const revokedKey = await keyList[0].revoke({
      flag: revokeReason,
      string: reasonText
    });

    const revCert = await revokedKey.getRevocationCertificate();

    EnigmailFiles.writeFileContents(outFile, revCert, STANDARD_FILE_PERMS);

    return createSuccess();
  },


  /**
   * set the expiration date of the chosen key and subkeys
   *
   * @param  {nsIWindow} parent
   * @param  {String}    keyId         e.g. 8D18EB22FDF633A2
   * @param  {Array}     subKeys       List of Integer values, e.g. [0,1,3]
   *                                   "0" reflects the primary key and should always be set.
   * @param  {Integer}   expiryValue   A number between 1 and 100
   * @param  {Integer}   timeScale     1 or 30 or 365 meaning days, months, years
   * @param  {Boolean}   noExpiry      True: Expire never. False: Use expiryLength.
   * @return  {Promise<Object>}
   */
  setKeyExpiration: async function(parent, keyId, subKeys, expiryValue, timeScale, noExpiry) {
    EnigmailLog.DEBUG(`pgpjs-keymanipulation.jsm: setKeyExpiration: keyId=${keyId}\n`);
    let keyList = await pgpjs_keyStore.getKeysForKeyIds(true, [keyId]);

    if (!keyList || keyList.length === 0) {
      return createError(EnigmailLocale.getString("keyNotFound", keyId));
    }

    if (noExpiry) {
      expiryValue = 0;
    }

    let newKey = await pgpjs_keys.changeKeyExpiry(keyList[0], subKeys, parseInt(timeScale, 10) * expiryValue * 86400);
    if (newKey) {
      await pgpjs_keyStore.deleteKeys([newKey.getFingerprint().toUpperCase()]);
      await pgpjs_keyStore.writeKey(await newKey.armor());
    }

    return createSuccess();
  }
};


function createError(errorMsg) {
  return {
    returnCode: 1,
    errorMsg: errorMsg
  };
}

function createSuccess() {
  return {
    returnCode: 0,
    errorMsg: ""
  };
}
