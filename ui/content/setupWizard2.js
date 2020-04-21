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
  window.openDialog("chrome://enigmail/content/ui/enigmailKeySelection.xul", "", "dialog,centerscreen,modal", {
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
  gAcceptButton.removeAttribute("disabled");
}

function exportKeys(tmpDir) {
  E2TBLog.DEBUG(`setupWizard2.exportKeys(${tmpDir.path})\n`);

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

  if (exitCodeObj.value !== 0) {
    E2TBLog.DEBUG("importExportWizard: error while exporting public keys\n");
    E2TBDialog.alert(window, E2TBLocale.getString("dataExportError"));
    return false;
  }

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
