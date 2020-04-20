/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

/* Globals from Thunderbird: */
/* global ReloadMessage: false, gDBView: false, gSignatureStatus: false, gEncryptionStatus: false, showMessageReadSecurityInfo: false */
/* global gFolderDisplay: false, messenger: false, currentAttachments: false, msgWindow: false, PanelUI: false */
/* global currentHeaderData: false, gViewAllHeaders: false, gExpandedHeaderList: false, goDoCommand: false, HandleSelectedAttachments: false */
/* global statusFeedback: false, displayAttachmentsForExpandedView: false, gMessageListeners: false, gExpandedHeaderView: false, gSignedUINode: false */

var EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
var EnigmailPrefs = ChromeUtils.import("chrome://enigmail/content/modules/prefs.jsm").EnigmailPrefs;
var EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
var EnigmailKeyRing = ChromeUtils.import("chrome://enigmail/content/modules/keyRing.jsm").EnigmailKeyRing;
var EnigmailWindows = ChromeUtils.import("chrome://enigmail/content/modules/windows.jsm").EnigmailWindows;
var EnigmailTimer = ChromeUtils.import("chrome://enigmail/content/modules/timer.jsm").EnigmailTimer;
var Services = ChromeUtils.import("resource://gre/modules/Services.jsm").Services;

var Enigmail = {};

Enigmail.msg = {
  messengerStartup: function() {
    EnigmailLog.DEBUG("enigmailMessengerOverlay.js: messengerStartup()\n");

    const lastVersion = EnigmailPrefs.getPref("configuredVersion");
    const vc = Cc["@mozilla.org/xpcom/version-comparator;1"].getService(Ci.nsIVersionComparator);

    if (vc.compare(lastVersion, "2.2b1") >= 0) {
      return;
    }

    EnigmailTimer.setTimeout(() => {
      let keyList = EnigmailKeyRing.getAllSecretKeys(false);

      if (keyList.length > 0) EnigmailWindows.openUpdateInfo();
    }, 3000);
  },


  messengerClose: function() {
    EnigmailLog.DEBUG("enigmailMessengerOverlay.js: messengerClose()\n");

  },

  onUnloadEnigmail: function() {
    EnigmailLog.DEBUG("enigmailMessengerOverlay.js: onUnloadEnigmail()\n");

    window.removeEventListener("unload", Enigmail.msg.messengerClose, false);
    window.removeEventListener("unload-enigmail", Enigmail.msg.onUnloadEnigmail, false);
    window.removeEventListener("load-enigmail", Enigmail.msg.messengerStartup, false);

    Enigmail = undefined;
  }
};

window.addEventListener("load-enigmail", Enigmail.msg.messengerStartup.bind(Enigmail.msg), false);
window.addEventListener("unload", Enigmail.msg.messengerClose.bind(Enigmail.msg), false);
window.addEventListener("unload-enigmail", Enigmail.msg.onUnloadEnigmail.bind(Enigmail.msg), false);
