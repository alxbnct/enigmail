/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// uses enigmailCommon.js:
/* global EnigInitCommon: false, EnigGetString: false */

// uses enigmailRulesEditor.js:
/* global onAcceptDialog: false, createRow: false, getSelectedNodes: false, onLoadDialog: false */

"use strict";

var Cu = Components.utils;
var Cc = Components.classes;
var Ci = Components.interfaces;

EnigInitCommon("enigmailSelectRule");

var EnigmailKeyRing = ChromeUtils.import("chrome://enigmail/content/modules/keyRing.jsm").EnigmailKeyRing;
var EnigmailFuncs = ChromeUtils.import("chrome://enigmail/content/modules/funcs.jsm").EnigmailFuncs;

function addKeyToRule() {
  let nodes = getSelectedNodes();

  if (nodes.length > 0) {
    let node = nodes[0];
    let keyId = node.getAttribute("keyId").split(/[ ,]+/);
    keyId.push("0x" + window.arguments[0].keyId);

    let inputObj = {
      email: node.getAttribute("email"),
      keyId: keyId.join(", "),
      sign: Number(node.getAttribute("sign")),
      encrypt: Number(node.getAttribute("encrypt")),
      pgpMime: Number(node.getAttribute("pgpMime")),
      negate: Number(node.getAttribute("negateRule"))
    };

    createRow(node, inputObj);

    onAcceptDialog();
    window.close();
  }
}


function createNewRuleWithKey() {
  let inputObj = {};
  let resultObj = {};
  let keyObj = EnigmailKeyRing.getKeyById(window.arguments[0].keyId);

  inputObj.options = "nosave";
  inputObj.toAddress = "{}";
  inputObj.keyId = ["0x" + window.arguments[0].keyId];
  inputObj.command = "add";

  if (keyObj) {
    inputObj.toAddress = "{" + EnigmailFuncs.stripEmail(keyObj.userId) + "}";
  }

  window.openDialog("chrome://enigmail/content/ui/enigmailSingleRcptSettings.xul", "", "dialog,modal,centerscreen,resizable", inputObj, resultObj);
  if (!resultObj.cancelled) {
    var treeItem = document.createXULElement("treeitem");
    createRow(treeItem, resultObj);
    var treeChildren = document.getElementById("rulesTreeChildren");
    if (treeChildren.firstChild) {
      treeChildren.insertBefore(treeItem, treeChildren.firstChild);
    }
    else {
      treeChildren.appendChild(treeItem);
    }

    onAcceptDialog();
  }
  window.close();
}

function editDlgOnLoad() {
  onLoadDialog();
  document.getElementById("editDialogTitle").setAttribute("value", EnigGetString("addKeyToRule", window.arguments[0].userId, "0x" + window.arguments[0].keyId));
}
