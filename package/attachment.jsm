/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["EnigmailAttachment"];

const EnigmailCryptoAPI = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI.jsm").EnigmailCryptoAPI;

var EnigmailAttachment = {
  getFileName: function(parent, byteData) {
    const cApi = EnigmailCryptoAPI();
    return cApi.sync(cApi.getFileName(byteData));
  }
};
