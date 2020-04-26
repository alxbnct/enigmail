/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

"use strict";

var Cu = Components.utils;
var Cc = Components.classes;
var Ci = Components.interfaces;

const EnigmailLocalizeHtml = ChromeUtils.import("chrome://enigmail/content/modules/localizeHtml.jsm").EnigmailLocalizeHtml;
const EnigmailWindows = ChromeUtils.import("chrome://enigmail/content/modules/windows.jsm").EnigmailWindows;
const EnigmailTimer = ChromeUtils.import("chrome://enigmail/content/modules/timer.jsm").EnigmailTimer;
const EnigmailSingletons = ChromeUtils.import("chrome://enigmail/content/modules/singletons.jsm").EnigmailSingletons;

function onload() {
  EnigmailSingletons.upgradeInfoDisplayed = true;
  EnigmailTimer.setTimeout(() => {
    EnigmailLocalizeHtml.onPageLoad(document);
  }, 50);
}

function performMigration() {
  window.openDialog("chrome://enigmail/content/ui/setupWizard2.xhtml", "", "chrome,dialog,centerscreen");
}
