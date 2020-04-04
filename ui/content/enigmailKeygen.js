/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// Uses: chrome://enigmail/content/ui/enigmailCommon.js

"use strict";

var Cu = Components.utils;
var Cc = Components.classes;
var Ci = Components.interfaces;

// modules
/* global EnigmailData: false, EnigmailLog: false, EnigmailLocale: false, EnigmailCryptoAPI: false, EnigmailKeyManagement: false */
/* global EnigmailOS: false, EnigmailPrefs: false, EnigmailApp: false, EnigmailKeyRing: false */
/* global EnigmailDialog: false, EnigmailFuncs: false */

// from enigmailCommon.js:
/* global EnigGetWindowOptions: false, EnigConfirm: false, EnigGetString: false, GetEnigmailSvc: false */
/* global EnigLongAlert: false, EnigAlert: false, EnigInitCommon: false, ENIG_ACCOUNT_MANAGER_CONTRACTID: false */
/* global EnigGetPref: false, EnigSetPref: false, EnigSavePrefs: false, EnigFilePicker: false, EnigGetFilePath: false */
/* global EnigmailWindows: false, EnigCreateRevokeCert: false */

// Initialize enigmailCommon
EnigInitCommon("enigmailKeygen");

var gAccountManager = Components.classes[ENIG_ACCOUNT_MANAGER_CONTRACTID].getService(Components.interfaces.nsIMsgAccountManager);

var gUserIdentityList;
var gUserIdentityListPopup;
var gUseForSigning;

var gKeygenRequest;
var gAllData = "";
var gGeneratedKey = null;
var gUsedId;

const KEYGEN_CANCELLED = "cancelled";

function enigmailKeygenLoad() {
  EnigmailLog.DEBUG("enigmailKeygen.js: Load\n");

  const cApi = EnigmailCryptoAPI();

  gUserIdentityList = document.getElementById("userIdentity");
  gUserIdentityListPopup = document.getElementById("userIdentityPopup");
  gUseForSigning = document.getElementById("useForSigning");

  var noPassphrase = document.getElementById("noPassphrase");

  if (!cApi.supportsFeature("keygen-passphrase")) {
    document.getElementById("passphraseRow").setAttribute("collapsed", "true");
    noPassphrase.setAttribute("collapsed", "true");
  }

  if (cApi.supportsFeature("supports-ecc-keys")) {
    let eccElem = document.getElementById("keyType_ecc");
    eccElem.removeAttribute("hidden");
    updateKeySizeSel(eccElem);
    document.getElementById("keyType").selectedItem = eccElem;
  }


  if (gUserIdentityListPopup) {
    fillIdentityListPopup();
  }
  gUserIdentityList.focus();

  // restore safe setting, which you ALWAYS explicitly have to overrule,
  // if you don't want them:
  // - specify passphrase
  // - specify expiry date
  noPassphrase.checked = false;
  EnigSetPref("noPassphrase", noPassphrase.checked);
  var noExpiry = document.getElementById("noExpiry");
  noExpiry.checked = false;

  enigmailKeygenUpdate(true, false);

  var enigmailSvc = GetEnigmailSvc();
  if (!enigmailSvc) {
    EnigAlert(EnigGetString("accessError"));
  }
}

function updateKeySizeSel(selectedObj) {
  if (selectedObj.id === "keyType_ecc") {
    document.getElementById("keySize").setAttribute("disabled", "true");
  }
  else {
    document.getElementById("keySize").removeAttribute("disabled");
  }
}

function enigmailOnClose() {
  var closeWin = true;
  if (gKeygenRequest) {
    closeWin = EnigConfirm(EnigGetString("keyAbort"), EnigGetString("keyMan.button.generateKeyAbort"), EnigGetString("keyMan.button.generateKeyContinue"));
  }
  if (closeWin) abortKeyGeneration();
  return closeWin;
}

function enigmailKeygenUnload() {
  EnigmailLog.DEBUG("enigmailKeygen.js: Unload\n");

  enigmailKeygenCloseRequest();
}


function enigmailKeygenUpdate(getPrefs, setPrefs) {
  EnigmailLog.DEBUG("enigmailKeygen.js: Update: " + getPrefs + ", " + setPrefs + "\n");

  var noPassphrase = document.getElementById("noPassphrase");
  var noPassphraseChecked = getPrefs ? EnigGetPref("noPassphrase") : noPassphrase.checked;

  if (setPrefs) {
    EnigSetPref("noPassphrase", noPassphraseChecked);
  }

  noPassphrase.checked = noPassphraseChecked;

  var passphrase1 = document.getElementById("passphrase");
  var passphrase2 = document.getElementById("passphraseRepeat");
  passphrase1.disabled = noPassphraseChecked;
  passphrase2.disabled = noPassphraseChecked;
}

function enigmailKeygenTerminate(exitCode) {
  EnigmailLog.DEBUG("enigmailKeygen.js: Terminate:\n");

  var curId = gUsedId;

  gKeygenRequest = null;

  document.getElementById("keygenProgress").style.visibility = "hidden";

  if ((!gGeneratedKey) || gGeneratedKey == KEYGEN_CANCELLED) {
    if (!gGeneratedKey)
      EnigAlert(EnigGetString("keyGenFailed"));
    return;
  }

  document.getElementById("keygenComplete").style.visibility = "visible";

  if (gGeneratedKey) {
    if (gUseForSigning.checked) {
      curId.setBoolAttribute("enablePgp", true);
      curId.setIntAttribute("pgpKeyMode", 1);
      curId.setCharAttribute("pgpkeyId", "0x" + gGeneratedKey);

      enigmailKeygenUpdate(false, true);

      EnigSavePrefs();

      EnigmailWindows.keyManReloadKeys();

      if (EnigConfirm(EnigGetString("keygenComplete", curId.email) + "\n\n" + EnigGetString("revokeCertRecommended"), EnigGetString("keyMan.button.generateCert"))) {
        EnigCreateRevokeCert(gGeneratedKey, curId.email, closeAndReset);
      }
      else
        closeAndReset();
    }
    else {
      if (EnigConfirm(EnigGetString("genCompleteNoSign") + "\n\n" + EnigGetString("revokeCertRecommended"), EnigGetString("keyMan.button.generateCert"))) {
        EnigCreateRevokeCert(gGeneratedKey, curId.email, closeAndReset);
        genAndSaveRevCert(gGeneratedKey, curId.email).then(
          function _resolve() {
            closeAndReset();
          },
          function _reject() {
            // do nothing
          }
        );
      }
      else
        closeAndReset();
    }
  }
  else {
    EnigAlert(EnigGetString("keyGenFailed"));
    window.close();
  }
}

/**
 * generate and save a revokation certificate.
 *
 * return: Promise object
 */

async function genAndSaveRevCert(keyId, uid) {
  EnigmailLog.DEBUG("enigmailKeygen.js: genAndSaveRevCert\n");

  let keyFile = EnigmailApp.getProfileDirectory();
  keyFile.append("0x" + keyId + "_rev.asc");

  // create a revokation cert in the TB profile directoy
  let retObj = await EnigmailKeyManagement.genRevokeCert(window, "0x" + keyId, keyFile, "1", "");

  if (retObj.returnCode !== 0) {
    EnigAlert(EnigGetString("revokeCertFailed") + "\n\n" + retObj.errorMsg);
    throw 1;
  }

  return saveRevCert(keyFile, keyId, uid);
}

/**
 *  create a copy of the revokation cert at a user defined location
 */
function saveRevCert(inputKeyFile, keyId, uid) {

  let defaultFileName = uid.replace(/[\\/<>]/g, "");
  defaultFileName += " (0x" + keyId + ") rev.asc";

  let outFile = EnigFilePicker(EnigGetString("saveRevokeCertAs"),
    "", true, "*.asc",
    defaultFileName, [EnigGetString("asciiArmorFile"), "*.asc"]);

  if (outFile) {
    try {
      inputKeyFile.copyToFollowingLinks(outFile.parent, outFile.leafName);
      EnigmailDialog.info(window, EnigGetString("revokeCertOK"));
    }
    catch (ex) {
      EnigAlert(EnigGetString("revokeCertFailed"));
      throw 2;
    }
  }
  return 0;
}

function closeAndReset() {
  EnigmailKeyRing.clearCache();
  window.close();
}

// Cleanup
function enigmailKeygenCloseRequest() {
  EnigmailLog.DEBUG("enigmailKeygen.js: CloseRequest\n");

  if (gKeygenRequest) {
    gKeygenRequest.cancel();
    gKeygenRequest = null;
  }
}

function enigmailCheckPassphrase() {
  var passphraseElement = document.getElementById("passphrase");
  var passphrase2Element = document.getElementById("passphraseRepeat");

  var passphrase = passphraseElement.value;

  if (passphrase != passphrase2Element.value) {
    EnigAlert(EnigGetString("passNoMatch"));
    return null;
  }

  if (passphrase.search(/[^\x20-\x7E]/) >= 0) {
    if (!EnigmailDialog.confirmDlg(window, EnigmailLocale.getString("keygen.passCharProblem"),
        EnigmailLocale.getString("dlg.button.ignore"), EnigmailLocale.getString("dlg.button.cancel"))) {
      return null;
    }
  }
  if ((passphrase.search(/^\s/) === 0) || (passphrase.search(/\s$/) >= 0)) {
    EnigAlert(EnigGetString("passSpaceProblem"));
    return null;
  }

  return passphrase;
}



function enigmailKeygenStart() {
  EnigmailLog.DEBUG("enigmailKeygen.js: Start\n");
  document.getElementById("startKeygen").setAttribute("disabled", "true");

  if (gKeygenRequest) {
    let req = gKeygenRequest.QueryInterface(Components.interfaces.nsIRequest);
    if (req.isPending()) {
      EnigmailDialog.info(window, EnigGetString("genGoing"));
      return;
    }
  }

  gGeneratedKey = null;
  gAllData = "";

  var enigmailSvc = GetEnigmailSvc();
  if (!enigmailSvc) {
    EnigAlert(EnigGetString("accessError"));
    return;
  }

  const cApi = EnigmailCryptoAPI();

  var passphrase;
  // some versions of query passphrases only using gpg-agent
  if (cApi.supportsFeature("keygen-passphrase")) {
    var noPassphraseElement = document.getElementById("noPassphrase");
    var passphraseElement = document.getElementById("passphrase");

    if (!noPassphraseElement.checked) {
      if (passphraseElement.value.trim() === "") {
        EnigmailDialog.info(window, EnigGetString("passCheckBox"));
        return;
      }

      passphrase = enigmailCheckPassphrase();
      if (passphrase === null) return;
    }

  }
  else {
    passphrase = "";
  }

  var noExpiry = document.getElementById("noExpiry");
  var expireInput = document.getElementById("expireInput");
  var timeScale = document.getElementById("timeScale");

  var expiryTime = 0;
  if (!noExpiry.checked) {
    expiryTime = Number(expireInput.value) * Number(timeScale.value);
    if (expiryTime > 36500) {
      EnigmailDialog.info(window, EnigGetString("expiryTooLong"));
      return;
    }
    if (expiryTime <= 0) {
      EnigmailDialog.info(window, EnigGetString("expiryTooShort"));
      return;
    }
  }
  var keySize = Number(document.getElementById("keySize").value);
  var keyType = document.getElementById("keyType").value;

  var curId = getCurrentIdentity();
  gUsedId = curId;

  var userName = curId.fullName;
  var userEmail = curId.email;

  if (!userName) {
    EnigmailDialog.info(window, EnigGetString("keygen.missingUserName"));
    return;
  }

  var idString = userName + " <" + userEmail + ">";

  var confirmMsg = EnigGetString("keyConfirm", idString);

  if (!EnigConfirm(confirmMsg, EnigGetString("keyMan.button.generateKey"))) {
    return;
  }

  document.getElementById("keygenProgress").style.visibility = "visible";

  EnigmailLog.WRITE("enigmailKeygen.js: Start: gKeygenRequest = " + gKeygenRequest + "\n");

  gKeygenRequest = EnigmailKeyRing.generateKey(
    EnigmailData.convertFromUnicode(userName),
    "", // user id comment
    EnigmailData.convertFromUnicode(userEmail),
    expiryTime,
    keySize,
    keyType,
    EnigmailData.convertFromUnicode(passphrase)
  );

  if (!gKeygenRequest) {
    EnigAlert(EnigGetString("keyGenFailed"));
    return;
  }

  gKeygenRequest.promise.then(result => {
    EnigmailLog.DEBUG(`enigmailKeygen.js: key ${result.generatedKeyId} created with status ${result.exitCode}\n`);
    gGeneratedKey = result.generatedKeyId;
    enigmailKeygenTerminate(result.exitCode);
  }).
  catch(ex => {
    EnigmailLog.DEBUG("enigmailKeygen.js: generateKey() failed with " + ex.toString() + "\n" + ex.stack + "\n");
    enigmailKeygenTerminate(1);
  });
}

function abortKeyGeneration() {
  gGeneratedKey = KEYGEN_CANCELLED;
  enigmailKeygenCloseRequest();
}

function enigmailKeygenCancel() {
  EnigmailLog.DEBUG("enigmailKeygen.js: Cancel\n");
  var closeWin = false;

  if (gKeygenRequest) {
    closeWin = EnigConfirm(EnigGetString("keyAbort"), EnigGetString("keyMan.button.generateKeyAbort"), EnigGetString("keyMan.button.generateKeyContinue"));
    if (closeWin) abortKeyGeneration();
  }
  else {
    closeWin = true;
  }

  if (closeWin) window.close();
}

function onNoExpiry() {
  var noExpiry = document.getElementById("noExpiry");
  var expireInput = document.getElementById("expireInput");
  var timeScale = document.getElementById("timeScale");

  expireInput.disabled = noExpiry.checked;
  timeScale.disabled = noExpiry.checked;
}


function queryISupArray(supportsArray, iid) {
  var result = [];
  var i;
  // Gecko > 20
  for (i = 0; i < supportsArray.length; i++) {
    result.push(supportsArray.queryElementAt(i, iid));
  }

  return result;
}

function getCurrentIdentity() {
  var item = gUserIdentityList.selectedItem;
  var identityKey = item.getAttribute('id');

  var identity = gAccountManager.getIdentity(identityKey);

  return identity;
}

function fillIdentityListPopup() {
  EnigmailLog.DEBUG("enigmailKeygen.js: fillIdentityListPopup\n");

  try {
    var idSupports = gAccountManager.allIdentities;
    var identities = queryISupArray(idSupports,
      Components.interfaces.nsIMsgIdentity);

    EnigmailLog.DEBUG("enigmailKeygen.js: fillIdentityListPopup: " + identities + "\n");

    // Default identity
    let defIdentity = EnigmailFuncs.getDefaultIdentity();

    EnigmailLog.DEBUG("enigmailKeygen.js: fillIdentityListPopup: default=" + defIdentity.key + "\n");

    var selected = false;
    for (var i = 0; i < identities.length; i++) {
      var identity = identities[i];

      EnigmailLog.DEBUG("id.valid=" + identity.valid + "\n");
      if (!identity.valid || !identity.email)
        continue;

      var serverSupports, inServer;
      // Gecko >= 20
      serverSupports = gAccountManager.getServersForIdentity(identity);
      if (serverSupports.length > 0) {
        inServer = serverSupports.queryElementAt(0, Components.interfaces.nsIMsgIncomingServer);
      }

      if (inServer) {
        var accountName = " - " + inServer.prettyName;

        EnigmailLog.DEBUG("enigmailKeygen.js: accountName=" + accountName + "\n");
        EnigmailLog.DEBUG("enigmailKeygen.js: email=" + identity.email + "\n");

        var item = document.createXULElement('menuitem');
        //      item.setAttribute('label', identity.identityName);
        item.setAttribute('label', identity.identityName + accountName);
        item.setAttribute('class', 'identity-popup-item');
        item.setAttribute('accountname', accountName);
        item.setAttribute('id', identity.key);
        item.setAttribute('email', identity.email);

        gUserIdentityListPopup.appendChild(item);

        if (!selected)
          gUserIdentityList.selectedItem = item;

        if (identity.key == defIdentity.key) {
          gUserIdentityList.selectedItem = item;
          selected = true;
        }
      }
    }
  }
  catch (ex) {
    EnigmailLog.writeException("enigmailKeygen.js: fillIdentityListPopup: exception\n", ex);
  }
}
