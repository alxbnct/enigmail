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
  gPublicKeys = [],
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

  let exportProgess = document.getElementById("exportProgress");

  function setExportProgress(percentComplete) {
    exportProgess.setAttribute("value", percentComplete);
  }

  let allPubKeys = E2TBKeyRing.getAllKeys(window).keyList.map(keyObj => {
    return "0x" + keyObj.fpr;
  });

  let exitCodeObj = {},
    errorMsgObj = {},
    totalNumKeys = gSelectedPrivateKeys.length + allPubKeys.length,
    numKeysProcessed = 0;

  for (let fpr of gSelectedPrivateKeys) {
    if (gDialogCancelled) return closeAfterCancel();

    let secKeyFile = tmpDir.clone();
    secKeyFile.append(fpr + ".sec");

    E2TBLog.DEBUG("setupWizard2.exportKeys: secFile: " + secKeyFile.path + "\n");
    E2TBKeyRing.extractKey(true, fpr, secKeyFile, exitCodeObj, errorMsgObj);

    ++numKeysProcessed;
    setExportProgress(numKeysProcessed / totalNumKeys * 100);

    if (exitCodeObj.value !== 0) {
      E2TBLog.DEBUG(`importExportWizard: error while exporting secret key ${fpr}\n`);
      E2TBDialog.alert(window, E2TBLocale.getString("dataExportError"));
      return false;
    }
  }

  for (let fpr of allPubKeys) {
    if (gDialogCancelled) return closeAfterCancel();

    if (!(fpr in gSelectedPrivateKeys)) {
      let pubKeyFile = tmpDir.clone();
      pubKeyFile.append(fpr + ".asc");

      E2TBKeyRing.extractKey(false, fpr, pubKeyFile, exitCodeObj, errorMsgObj);
      if (exitCodeObj.value === 0) {
        gPublicKeys.push(fpr);
      }

      ++numKeysProcessed;
      setExportProgress(numKeysProcessed / totalNumKeys * 100);
    }
  }

  document.getElementById("exportingKeys").style.visibility = "collapse";
  document.getElementById("keysExported").style.visibility = "visible";

  return true;
}


function importKeys(tmpDir) {
  E2TBLog.DEBUG(`setupWizard2.importKeys(${tmpDir.path})\n`);

  let pubKeysFailed = [];
  let importProgess = document.getElementById("importProgress");

  function setImportProgress(percentComplete) {
    importProgess.setAttribute("value", percentComplete);
  }

  document.getElementById("importingKeys").style.visibility = "visible";

  let numKeysProcessed = 0;
  const totalNumKeys = gSelectedPrivateKeys.length + gPublicKeys.length;

  for (let fpr of gSelectedPrivateKeys) {
    if (gDialogCancelled) return closeAfterCancel();

    let secKeyFile = tmpDir.clone();
    secKeyFile.append(fpr + ".sec");

    E2TBLog.DEBUG("setupWizard2.importKeys: secFile: " + secKeyFile.path + "\n");
    importKeyFile(fpr, secKeyFile, true);
    ++numKeysProcessed;
    setImportProgress(numKeysProcessed / totalNumKeys * 100);
  }

  for (let fpr of gPublicKeys) {
    if (gDialogCancelled) return closeAfterCancel();

    let pubKeyFile = tmpDir.clone();
    pubKeyFile.append(fpr + ".asc");

    ++numKeysProcessed;
    setImportProgress(numKeysProcessed / totalNumKeys * 100);

    E2TBLog.DEBUG("setupWizard2.importKeys: pubFile: " + pubKeyFile.path + "\n");
    if (!importKeyFile(fpr, pubKeyFile, false)) {
      pubKeysFailed.push(fpr);
    }
  }

  document.getElementById("importingKeys").style.visibility = "collapse";
  document.getElementById("keysImported").style.visibility = "visible";

  if (pubKeysFailed.length > 0) {
    E2TBDialog.alert(
      window,
      E2TBLocale.getString("importPubKeysFailed", pubKeysFailed.join("\n"))
    );
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

function importKeyFile(fpr, inFile, isSecretKey) {
  let resultKeys = {},
    errorMsgObj = {};

  try {
    let exitCode = EnigmailKeyRing.importKeyFromFile(
      window,
      passphrasePromptCallback,
      inFile,
      errorMsgObj,
      resultKeys,
      !isSecretKey,
      isSecretKey
    );

    if (exitCode !== 0) {
      E2TBDialog.alert(
        window,
        E2TBLocale.getString("importKeyFailed", fpr) +
        "\n\n" +
        errorMsgObj.value
      );
    }

    return (exitCode === 0);
  }
  catch (ex) {
    Services.console.logMessage(ex);
    if (isSecretKey) {
      E2TBDialog.alert(
        window,
        E2TBLocale.getString("importKeyFailed", fpr) +
        "\n\n" +
        ex.toString()
      );
    }

    return false;
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
