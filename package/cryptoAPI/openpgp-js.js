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

    if (! success) throw "Init Error";
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
}


function getOpenPGPjsAPI() {
  return new OpenPGPjsCryptoAPI();
}
