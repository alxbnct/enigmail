/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

var Cu = Components.utils;
var Cc = Components.classes;
var Ci = Components.interfaces;

var EnigmailCore = ChromeUtils.import("chrome://enigmail/content/modules/core.jsm").EnigmailCore;
var EnigmailCryptoAPI = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI.jsm").EnigmailCryptoAPI;
var EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
var EnigmailData = ChromeUtils.import("chrome://enigmail/content/modules/data.jsm").EnigmailData;
var EnigmailDialog = ChromeUtils.import("chrome://enigmail/content/modules/dialog.jsm").EnigmailDialog;

function onLoad() {}

function onAccept() {
  var name = document.getElementById("addUid_name");
  var email = document.getElementById("addUid_email");

  if ((email.value.search(/^ *$/) === 0) || (name.value.search(/^ *$/) === 0)) {
    EnigmailDialog.alert(window, EnigmailLocale.getString("addUidDlg.nameOrEmailError"));
    return false;
  }
  if (name.value.replace(/ *$/, "").length < 5) {
    EnigmailDialog.alert(window, EnigmailLocale.getString("addUidDlg.nameMinLengthError"));
    return false;
  }
  if (email.value.search(/.@./) < 0) {
    EnigmailDialog.alert(window, EnigmailLocale.getString("addUidDlg.invalidEmailError"));
    return false;
  }

  var enigmailSvc = EnigmailCore.getService();
  if (!enigmailSvc) {
    EnigmailDialog.alert(window, EnigmailLocale.getString("accessError"));
    return true;
  }

  const keyMgmt = EnigmailCryptoAPI().getKeyManagement();
  keyMgmt.addUid(window,
    window.arguments[0].keyId,
    EnigmailData.convertFromUnicode(name.value),
    EnigmailData.convertFromUnicode(email.value),
    "" // user id comment
  ).then(retObj => {
    if (retObj.returnCode !== 0) {
      EnigmailDialog.alert(window, EnigmailLocale.getString("addUidFailed") + "\n\n" + retObj.errorMsg);
    }
    else {
      window.arguments[1].refresh = true;
      EnigmailDialog.info(window, EnigmailLocale.getString("addUidOK"));
    }
    window.close();
  });

  return false;
}


document.addEventListener("dialogaccept", function(event) {
  if (!onAccept())
    event.preventDefault(); // Prevent the dialog closing.
});
