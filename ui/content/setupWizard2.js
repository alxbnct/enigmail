/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

var Cu = Components.utils;
var Cc = Components.classes;
var Ci = Components.interfaces;

var E2TBPrefs = ChromeUtils.import("chrome://enigmail/content/modules/prefs.jsm").EnigmailPrefs;
var E2TBLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
var E2TBLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
var E2TBDialog = ChromeUtils.import("chrome://enigmail/content/modules/dialog.jsm").EnigmailDialog;
var E2TBFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;
var E2TBKeyRing = ChromeUtils.import("chrome://enigmail/content/modules/keyRing.jsm").EnigmailKeyRing;
var Services = ChromeUtils.import("resource://gre/modules/Services.jsm").Services;

// OpenPGP implementation in TB
var EnigmailDialog = ChromeUtils.import("chrome://openpgp/content/modules/dialog.jsm").EnigmailDialog;
var EnigmailKeyRing = ChromeUtils.import("chrome://openpgp/content/modules/keyRing.jsm").EnigmailKeyRing;


var gSelectedPrivateKeys = null,
  gAcceptButton = null,
  gDialogCancelled = false,
  gProcessing = false;

function onLoad() {
  E2TBLog.DEBUG(`setupWizard2.js: onLoad()\n`);
  let dlg = document.getElementById("setupWizardDlg");
  gAcceptButton = dlg.getButton("accept");
  gAcceptButton.setAttribute("disabled", "true");

  let secKeys = E2TBKeyRing.getAllSecretKeys(false);
  if (secKeys.length > 5) {
    document.getElementById("manyKeys").style.visibility = "visible";
  }

  gSelectedPrivateKeys = secKeys.map(keyObj => {
    return "0x" + keyObj.fpr;
  });
}

function onAccept() {
  return true;
}

function closeAfterCancel() {
  E2TBLog.DEBUG("importExportWizard: closing after Cancel clicked\n");
  window.close();
  return false;
}

function onCancel() {
  gDialogCancelled = true;
  if (gProcessing) {
    return false;
  }
  return true;
}

function selectPrivateKeys() {
  let resultObj = {};
  window.openDialog("chrome://enigmail/content/ui/enigmailKeySelection.xhtml", "", "chrome,dialog,centerscreen,modal", {
    options: `private,allowexpired,trustallkeys,multisel,nosending,sendlabel=${E2TBLocale.getString("setupWizard.selectKeysButton")},`
  }, resultObj);

  if (resultObj.cancelled) return;
  gSelectedPrivateKeys = resultObj.userList;
  E2TBLog.DEBUG(`setupWizard2.selectPrivateKeys: selKey: ${gSelectedPrivateKeys.join(", ")}\n`);
}

function startMigration() {
  for (let btn of ["btnSelectPrivateKeys", "btnStartMigration"]) {
    document.getElementById(btn).setAttribute("disabled", "true");
  }
  gProcessing = true;
  let tmpDir = E2TBFiles.createTempSubDir("enig-exp", true);
  exportKeys(tmpDir);
  importKeys(tmpDir);
  gAcceptButton.removeAttribute("disabled");
}

function exportKeys(tmpDir) {
  E2TBLog.DEBUG(`setupWizard2.exportKeys(${tmpDir.path})\n`);

  document.getElementById("exportingKeys").style.visibility = "visible";

  let exitCodeObj = {},
    errorMsgObj = {};

  for (let fpr of gSelectedPrivateKeys) {
    if (gDialogCancelled) return closeAfterCancel();

    let secKeyFile = tmpDir.clone();
    secKeyFile.append(fpr + ".sec");

    E2TBLog.DEBUG("setupWizard2.exportKeys: secFile: " + secKeyFile.path + "\n");
    E2TBKeyRing.extractKey(true, fpr, secKeyFile, exitCodeObj, errorMsgObj);

    if (exitCodeObj.value !== 0) {
      E2TBLog.DEBUG(`importExportWizard: error while exporting secret key ${fpr}\n`);
      E2TBDialog.alert(window, E2TBLocale.getString("dataExportError"));
      return false;
    }
  }

  if (gDialogCancelled) return closeAfterCancel();

  let pubKeysFile = tmpDir.clone();
  pubKeysFile.append("pubkeys.asc");

  E2TBKeyRing.extractKey(false, "", pubKeysFile, exitCodeObj, errorMsgObj);

  document.getElementById("exportingKeys").style.visibility = "collapse";

  if (exitCodeObj.value !== 0) {
    E2TBLog.DEBUG("importExportWizard: error while exporting public keys\n");
    E2TBDialog.alert(window, E2TBLocale.getString("dataExportError"));
    return false;
  }

  document.getElementById("keysExported").style.visibility = "visible";

  return true;
}


function importKeys(tmpDir) {
  E2TBLog.DEBUG(`setupWizard2.exportKeys(${tmpDir.path})\n`);

  document.getElementById("importingKeys").style.visibility = "visible";

  for (let fpr of gSelectedPrivateKeys) {
    if (gDialogCancelled) return closeAfterCancel();

    let secKeyFile = tmpDir.clone();
    secKeyFile.append(fpr + ".sec");

    E2TBLog.DEBUG("setupWizard2.exportKeys: secFile: " + secKeyFile.path + "\n");
    importKeyFile(secKeyFile, true);
  }

  let pubKeysFile = tmpDir.clone();
  pubKeysFile.append("pubkeys.asc");

  importKeyFile(pubKeysFile, false);

  document.getElementById("importingKeys").style.visibility = "collapse";
  document.getElementById("keysImported").style.visibility = "visible";

  return true;
}

function handleClick(event) {
  /*
  if (event.target.hasAttribute("href")) {
    let target = event.target;
    event.stopPropagation();
    EnigmailWindows.openMailTab(target.getAttribute("href"));
  } */
}


document.addEventListener("dialogaccept", function(event) {
  if (!onAccept())
    event.preventDefault(); // Prevent the dialog closing.
});

document.addEventListener("dialogcancel", function(event) {
  if (!onCancel())
    event.preventDefault(); // Prevent the dialog closing.
});

function importKeyFile(inFile, secret) {
  let resultKeys = {},
    errorMsgObj = {};

  try {
    let exitCode = EnigmailKeyRing.importKeyFromFile(
      window,
      passphrasePromptCallback,
      inFile,
      errorMsgObj,
      resultKeys,
      !secret,
      secret
    );

    if (exitCode !== 0) {
      EnigmailDialog.alert(
        window,
        E2TBLocale.getString("importKeysFailed") +
        "\n\n" +
        errorMsgObj.value
      );
    }
  }
  catch (ex) {
    Services.console.logMessage(ex);
    EnigmailDialog.alert(
      window,
      E2TBLocale.getString("importKeysFailed") +
      "\n\n" +
      ex.toString()
    );
  }
}

/**
 * opens a prompt, asking the user to enter passphrase for given key id
 * returns: the passphrase if entered (empty string is allowed)
 * resultFlags.canceled is set to true if the user clicked cancel
 */
function passphrasePromptCallback(win, keyId, resultFlags) {
  let p = {};
  p.value = "";
  let dummy = {};
  if (
    !Services.prompt.promptPassword(
      win,
      "",
      E2TBLocale.getString("passphrasePrompt", [keyId]),
      p,
      null,
      dummy
    )
  ) {
    resultFlags.canceled = true;
    return "";
  }

  resultFlags.canceled = false;
  return p.value;
}
