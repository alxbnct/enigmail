/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["pgpjs_keys"];


var Services = ChromeUtils.import("resource://gre/modules/Services.jsm").Services;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailLazy = ChromeUtils.import("chrome://enigmail/content/modules/lazy.jsm").EnigmailLazy;
const getOpenPGPLibrary = ChromeUtils.import("chrome://enigmail/content/modules/stdlib/openpgp-loader.jsm").getOpenPGPLibrary;

const getOpenPGP = EnigmailLazy.loader("enigmail/openpgp.jsm", "EnigmailOpenPGP");
const getArmor = EnigmailLazy.loader("enigmail/armor.jsm", "EnigmailArmor");

// Load generic API
Services.scriptloader.loadSubScript("chrome://enigmail/content/modules/cryptoAPI/interface.js",
  null, "UTF-8"); /* global CryptoAPI */


/**
 * OpenPGP.js implementation of CryptoAPI
 */

var pgpjs_keys = {
  /**
   * Get a minimal key, possibly reduced to a specific email address
   *
   * @param {String|Object} key: String: armored key data
   *                             Object: OpenPGP.JS Key object
   * @param {String} emailAddr:  If set, only filter for UIDs with the emailAddr
   * @param {Boolean} getPacketList: if true, return packet list instead of Uint8Array
   *
   */
  getStrippedKey: async function(key, emailAddr, getPacketList = false) {
    EnigmailLog.DEBUG("pgpjs-keys.jsm: getStrippedKey()\n");

    let searchUid = undefined;
    if (emailAddr) {
      if (emailAddr.search(/^<.{1,500}>$/) < 0) {
        searchUid = `<${emailAddr}>`;
      }
      else searchUid = emailAddr;
    }

    try {
      const openpgp = getOpenPGPLibrary();
      if (typeof(key) === "string") {
        let msg = await openpgp.key.readArmored(key);

        if (!msg || msg.keys.length === 0) {
          if (msg.err) {
            EnigmailLog.writeException("pgpjs-keys.jsm", msg.err[0]);
          }
          return null;
        }

        key = msg.keys[0];
      }

      let uid = await key.getPrimaryUser(null, searchUid);
      if (!uid || !uid.user) return null;

      let signSubkey = await key.getSigningKey();
      let encSubkey = await key.getEncryptionKey();

      let p = new openpgp.packet.List();
      p.push(key.primaryKey);
      p.concat(uid.user.toPacketlist());
      if (key !== signSubkey) {
        p.concat(signSubkey.toPacketlist());
      }
      if (key !== encSubkey) {
        p.concat(encSubkey.toPacketlist());
      }

      if (getPacketList) {
        return p;
      }

      return p.write();
    }
    catch (ex) {
      EnigmailLog.DEBUG("pgpjs-keys.jsm: getStrippedKey: ERROR " + ex.message + "\n" + ex.stack + "\n");
    }
    return null;
  },

  getKeyListFromKeyBlock: async function(keyBlockStr) {
    EnigmailLog.DEBUG("pgpjs-keys.jsm: getKeyListFromKeyBlock()\n");
    const EnigmailTime = ChromeUtils.import("chrome://enigmail/content/modules/time.jsm").EnigmailTime;

    const SIG_TYPE_REVOCATION = 0x20;

    let keyList = [];
    let key = {};
    let blocks;
    let isBinary = false;
    const EOpenpgp = getOpenPGP();
    const openPGPjs = getOpenPGPLibrary();

    if (keyBlockStr.search(/-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----/) >= 0) {
      blocks = getArmor().splitArmoredBlocks(keyBlockStr);
    }
    else {
      isBinary = true;
      blocks = [EOpenpgp.bytesToArmor(openPGPjs.enums.armor.public_key, keyBlockStr)];
    }

    for (let b of blocks) {
      let m = await openPGPjs.message.readArmored(b);

      for (let i = 0; i < m.packets.length; i++) {
        let packetType = openPGPjs.enums.read(openPGPjs.enums.packet, m.packets[i].tag);
        switch (packetType) {
          case "publicKey":
          case "secretKey":
            key = {
              id: m.packets[i].getKeyId().toHex().toUpperCase(),
              fpr: m.packets[i].getFingerprint().toUpperCase(),
              uids: [],
              created: EnigmailTime.getDateTime(m.packets[i].getCreationTime().getTime() / 1000, true, false),
              name: null,
              isSecret: false,
              revoke: false
            };

            if (!(key.id in keyList)) {
              keyList[key.id] = key;
            }

            if (packetType === "secretKey") {
              keyList[key.id].isSecret = true;
            }
            break;
          case "userid":
            if (!key.name) {
              key.name = m.packets[i].userid.replace(/[\r\n]+/g, " ");
            }
            else {
              key.uids.push(m.packets[i].userid.replace(/[\r\n]+/g, " "));
            }
            break;
          case "signature":
            if (m.packets[i].signatureType === SIG_TYPE_REVOCATION) {
              let keyId = m.packets[i].issuerKeyId.toHex().toUpperCase();
              if (keyId in keyList) {
                keyList[keyId].revoke = true;
              }
              else {
                keyList[keyId] = {
                  revoke: true,
                  id: keyId
                };
              }
            }
            break;
        }
      }
    }

    return keyList;
  }
};
