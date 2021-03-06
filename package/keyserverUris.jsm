/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

const EXPORTED_SYMBOLS = ["EnigmailKeyserverURIs"];

const EnigmailPrefs = ChromeUtils.import("chrome://enigmail/content/modules/prefs.jsm").EnigmailPrefs;
const EnigmailOS = ChromeUtils.import("chrome://enigmail/content/modules/os.jsm").EnigmailOS;

const KEYSERVER_PREF = "keyserver";
const AUTO_KEYSERVER_SELECTION_PREF = "autoKeyServerSelection";

const supportedProtocols = {
  "hkps": "443",
  "vks": "443",
  "hkp": "11371",
  "ldap": "389"
};

function buildUriFor(protocol, keyserver) {
  return {
    protocol: protocol,
    domain: keyserver,
    port: supportedProtocols[protocol]
  };
}

function addUriOptionsForPoolKeyservers(keyserver, uris) {
  if (keyserver === "hkps.pool.sks-keyservers.net") {
    uris.push(buildUriFor("hkps", keyserver));
  }
  if (keyserver === "pool.sks-keyservers.net") {
    uris.push(buildUriFor("hkps", "hkps.pool.sks-keyservers.net"));
    uris.push(buildUriFor("hkp", keyserver));
  }
}

function buildUriOptionsFor(keyserver) {
  const uris = [];
  const keyserverProtocolAndDomain = keyserver.split("://");
  const protocolIncluded = keyserverProtocolAndDomain.length === 2;
  const isPoolKeyserver = ["hkps.pool.sks-keyservers.net", "pool.sks-keyservers.net"].indexOf(keyserver) > -1;

  if (isPoolKeyserver) {
    addUriOptionsForPoolKeyservers(keyserver, uris);
  }
  else if (protocolIncluded) {
    uris.push(buildUriFor(keyserverProtocolAndDomain[0].toLowerCase(), keyserverProtocolAndDomain[1]));
  }
  else {
    uris.push(buildUriFor("hkps", keyserver));
    uris.push(buildUriFor("hkp", keyserver));
  }

  return uris;
}

function getDefaultKeyServer() {
  return  EnigmailPrefs.getPref("defaultKeyserver");
}

function getUserDefinedKeyserverURIs() {
  const keyservers = EnigmailPrefs.getPref(KEYSERVER_PREF).split(/\s*[,;]\s*/g);
  return EnigmailPrefs.getPref(AUTO_KEYSERVER_SELECTION_PREF) ? [getDefaultKeyServer()] : keyservers;
}

function combineIntoURI(protocol, domain, port) {
  return protocol + "://" + domain + ":" + port;
}

function isValidProtocol(uri) {
  return uri.match(/:\/\//) === null || /^(hkps|hkp|vks|ldap):\/\//i.test(uri);
}

function validProtocolsExist() {
  const validKeyserverUris = getUserDefinedKeyserverURIs().filter(isValidProtocol);
  return validKeyserverUris.length > 0;
}

/**
 * Construct the full URIs for making gpg requests.
 * This takes the specified keyservers and adds the relevant protocol and port.
 * When no specific protocol is defined by the user, 2 URIs will be built, for hkps and hkp.
 *
 * @return array of all URIs to try refreshing keys over
 */
function buildKeyserverUris() {
  const uris = getUserDefinedKeyserverURIs().filter(isValidProtocol).map(function(keyserver) {
    return buildUriOptionsFor(keyserver);
  }).reduce(function(a, b) {
    return a.concat(b);
  });

  return uris.map(function(uri) {
    return combineIntoURI(uri.protocol, uri.domain, uri.port);
  });
}

/**
 * Checks if the default keyserver is specified and valid.
 * Key refreshes will not be attempted without valid keyserver.
 * A valid keyserver is one that is non-empty and consists of
 * - the keyserverDomain
 * - may include a protocol from hkps, hkp or ldap
 * - may include the port
 *
 * @return true if keyservers exist and are valid, false otherwise.
 */
function validKeyserversExist() {
  const keyserver = EnigmailPrefs.getPref("defaultKeyserver");
  return keyserver !== undefined && keyserver.trim() !== "" && validProtocolsExist();
}

var EnigmailKeyserverURIs = {
  getDefaultKeyServer: getDefaultKeyServer,
  buildKeyserverUris: buildKeyserverUris,
  validKeyserversExist: validKeyserversExist
};
