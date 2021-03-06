/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* global currentFilter: false */

"use strict";

var Cu = Components.utils;
var Cc = Components.classes;
var Ci = Components.interfaces;

var EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;

var EnigmailListEditor = {
  onLoad: function() {
    EnigmailLog.DEBUG("EnigmailFilterOverlay.js: onLoad()\n");
    this.onSelect();

    let fl = document.getElementById("filterList");
    fl.addEventListener("select", EnigmailListEditor.onSelect.bind(EnigmailListEditor), false);
    fl.addEventListener("click", EnigmailListEditor.onClick.bind(EnigmailListEditor), true);
  },

  onUnload: function() {
    window.removeEventListener("load-enigmail", EnigmailListEditor.onLoad, false);
    window.removeEventListener("unload-enigmail", EnigmailListEditor.onUnload, false);

    let fl = document.getElementById("filterList");
    fl.removeEventListener("select", EnigmailListEditor.onSelect, false);
    fl.removeEventListener("click", EnigmailListEditor.onClick, true);
  },

  onSelect: function() {},

  onClick: function(event) {}
};

window.addEventListener("load-enigmail", EnigmailListEditor.onLoad.bind(EnigmailListEditor), false);
window.addEventListener("unload-enigmail", EnigmailListEditor.onUnload.bind(EnigmailListEditor), false);
