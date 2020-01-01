/*
 * This Source Code Form is licensed under the GNU LGPL 3.0 license.
 *
 */


/*
 * This bit of code embeds the openPGP-JS libary. This is the part that is added before
 * the library code.
 */


var EXPORTED_SYMBOLS = ["getOpenPGPLibrary"];

// Complete list of gobal prpoperties (as of TB 65), taken from
// [mozilla-source]/js/xpconnect/src/Sandbox.cpp

try {
  // Gecko 68
  Components.utils.importGlobalProperties(["Blob",
    "CSS",
    "CSSRule",
    "ChromeUtils",
    "DOMParser",
    "Directory",
    "Element",
    "Event",
    "File",
    "FileReader",
    "FormData",
    "InspectorUtils",
    "MessageChannel",
    "Node",
    "NodeFilter",
    "PromiseDebugging",
    "TextDecoder",
    "TextEncoder",
    "URL",
    "URLSearchParams",
    "XMLHttpRequest",
    "XMLSerializer",
    "atob",
    "btoa",
    "caches",
    "crypto",
    "fetch",
    "indexedDB"
  ]);
}
catch(x) {
  // Gecko 52
  Components.utils.importGlobalProperties(["Blob",
    "CSS",
    "Directory",
    "File",
    "TextDecoder",
    "TextEncoder",
    "URL",
    "XMLHttpRequest",
    "atob",
    "btoa",
    "crypto",
    "fetch",
    "indexedDB"
  ]);
}

const {
  TransformStream,
  ReadableStream,
  WritableStream
} = ChromeUtils.import("chrome://enigmail/content/modules/stdlib/web-streams.jsm");

function getOpenPGPLibrary() {

  /* Prerequisites required by openpgp-lib.js */

  let setTimeout = ChromeUtils.import("resource://gre/modules/Timer.jsm").setTimeout;

  let appShellSvc = Cc["@mozilla.org/appshell/appShellService;1"].getService(Ci.nsIAppShellService);
  let userAgent = appShellSvc.hiddenDOMWindow.navigator.userAgent;

  const window = {};
  const document = {};
  const navigator = {
    userAgent: appShellSvc.hiddenDOMWindow.navigator.userAgent
  };
  window.document = document;
  window.navigator = navigator;
  window.crypto = crypto;

  // no idea why, but oenpgp.js won't load without this defined
  let self = window;

  const console = {
    assert: function() {},
    log: function() {},
    error: function() {},
    table: function() {},
    warn: function() {}
  };

  /* OpenPGP-LS library code will be copied below this line */
