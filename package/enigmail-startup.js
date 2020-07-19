/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


"use strict";

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

const XPCOMUtils = Cu.import("resource://gre/modules/XPCOMUtils.jsm").XPCOMUtils;
const Services = Cu.import("resource://gre/modules/Services.jsm").Services;
const EnigmailApp = Cu.import("chrome://enigmail/content/modules/app.jsm").EnigmailApp;
const EnigmailCore = Cu.import("chrome://enigmail/content/modules/core.jsm").EnigmailCore;
const EnigmailAmPrefsService = Cu.import("chrome://enigmail/content/modules/amPrefsService.jsm").EnigmailAmPrefsService;
const EnigmailPgpmimeHander = Cu.import("chrome://enigmail/content/modules/pgpmimeHandler.jsm").EnigmailPgpmimeHander;
const AddonManager = Components.utils.import("resource://gre/modules/AddonManager.jsm").AddonManager;

const NS_ENIGCLINE_SERVICE_CID = Components.ID("{f4d4138e-dd4d-4cb0-b408-a41429d38e34}");
const NS_CLINE_SERVICE_CONTRACTID = "@mozilla.org/enigmail/cline-handler;1";

const nsICommandLineHandler = Ci.nsICommandLineHandler;
const nsIFactory = Ci.nsIFactory;
const nsISupports = Ci.nsISupports;

function EnigmailStartup() {}

EnigmailStartup.prototype = {
  classDescription: "Enigmail Core Service",
  classID: NS_ENIGCLINE_SERVICE_CID,
  contractID: NS_CLINE_SERVICE_CONTRACTID,
  _xpcom_categories: [{
    category: "command-line-handler",
    entry: "m-cline-enigmail",
    service: false
  }],
  QueryInterface: XPCOMUtils.generateQI([nsICommandLineHandler, nsIFactory, nsISupports]),

  // nsICommandLineHandler
  handle: function(cmdLine) {
    // does nothing
  },

  helpInfo: "  -pgpkeyman         Open the OpenPGP key management.\n",

  lockFactory: function(lock) {}
};

function startup() {

  const APP_STARTUP = 1;

  // Services.console.logStringMessage("Enigmail startup ...");

  AddonManager.getAddonByID("{847b3a00-7ab1-11d4-8f02-006008948af5}", addonData => {
    const appData = {
      version: addonData.version
    };

    EnigmailApp.initAddon(appData);
    EnigmailAmPrefsService.startup(APP_STARTUP);
    EnigmailCore.startup(APP_STARTUP);
    EnigmailPgpmimeHander.startup(APP_STARTUP);

    Services.console.logStringMessage("Enigmail startup completed");
  });
}

startup();
const NSGetFactory = XPCOMUtils.generateNSGetFactory([EnigmailStartup]);
