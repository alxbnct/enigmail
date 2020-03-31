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
const EnigmailTime = ChromeUtils.import("chrome://enigmail/content/modules/time.jsm").EnigmailTime;
const EnigmailTimer = ChromeUtils.import("chrome://enigmail/content/modules/timer.jsm").EnigmailTimer;
const EnigmailData = ChromeUtils.import("chrome://enigmail/content/modules/data.jsm").EnigmailData;
const EnigmailFuncs = ChromeUtils.import("chrome://enigmail/content/modules/funcs.jsm").EnigmailFuncs;
const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
const getOpenPGP = EnigmailLazy.loader("enigmail/openpgp.jsm", "EnigmailOpenPGP");
const getArmor = EnigmailLazy.loader("enigmail/armor.jsm", "EnigmailArmor");
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;

const OPENPGPKEY_REALM = "OpenPGPKey";
const ENIGMAIL_PASSWD_PREFIX = "enigmail://";
const MAX_PASSWD_ATTEMPT = 3;

const NS_WRONLY = 0x02;
const NS_CREATE_FILE = 0x08;
const NS_TRUNCATE = 0x20;
const STANDARD_FILE_PERMS = 0o600;
const NS_LOCALFILEOUTPUTSTREAM_CONTRACTID = "@mozilla.org/network/file-output-stream;1";


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
    const PgpJS = getOpenPGPLibrary();

    let searchUid = undefined;
    if (emailAddr) {
      if (emailAddr.search(/^<.{1,500}>$/) < 0) {
        searchUid = `<${emailAddr}>`;
      }
      else searchUid = emailAddr;
    }

    try {
      if (typeof(key) === "string") {
        let msg = await PgpJS.key.readArmored(key);

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

      // remove all 3rd-party signatures
      if (signSubkey && "directSignatures" in signSubkey) signSubkey.directSignatures = [];
      if ("otherCertifications" in uid.user) uid.user.otherCertifications = [];

      let p = new PgpJS.packet.List();
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

    const SIG_TYPE_REVOCATION = 0x20;

    let keyList = [];
    let key = {};
    let blocks;
    let isBinary = false;
    const EOpenpgp = getOpenPGP();
    const PgpJS = getOpenPGPLibrary();

    if (keyBlockStr.search(/-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----/) >= 0) {
      blocks = getArmor().splitArmoredBlocks(keyBlockStr);
    }
    else {
      isBinary = true;
      blocks = [EOpenpgp.bytesToArmor(PgpJS.enums.armor.public_key, keyBlockStr)];
    }

    for (let b of blocks) {
      let m = await PgpJS.message.readArmored(b);

      for (let i = 0; i < m.packets.length; i++) {
        let packetType = PgpJS.enums.read(PgpJS.enums.packet, m.packets[i].tag);
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
  },

  getSignaturesFromKey: function(pgpJsKey) {
    /*    - {String} userId
     *     - {String} rawUserId
     *     - {String} keyId
     *     - {String} fpr
     *     - {String} created
     *     - {Array} sigList:
     *            - {String} userId
     *            - {String} created
     *            - {String} signerKeyId
     *            - {String} sigType
     *            - {Boolean} sigKnown
     */

    const fpr = pgpJsKey.getFingerprint().toUpperCase();
    const keyId = pgpJsKey.getKeyId().toHex().toUpperCase();
    let sigs = [];
    for (let u of pgpJsKey.users) {
      if (u.userId) {
        if (u.selfCertifications.length > 0) {
          let uid = {
            userId: u.userId.userid,
            rawUserId: u.userId.userid,
            keyId: keyId,
            fpr: fpr,
            created: EnigmailTime.getDateTime(u.selfCertifications[0].created / 1000, true, false),
            sigList: []
          };

          for (let c of u.selfCertifications) {
            let sig = {
              created: EnigmailTime.getDateTime(c.created / 1000, true, false),
              createdTime: c.created / 1000,
              sigType: Number(c.signatureType).toString(16) + "x",
              userId: "",
              fpr: "",
              sigKnown: true
            };

            if (c.issuerFingerprint) {
              sig.signerKeyId = EnigmailFuncs.arrayToHex(c.issuerFingerprint);
            }
            else {
              sig.signerKeyId = c.issuerKeyId.toHex().toUpperCase();
            }
            uid.sigList.push(sig);
          }

          for (let c of u.otherCertifications) {
            if (c.revoked) continue;

            let sig = {
              created: EnigmailTime.getDateTime(c.created / 1000, true, false),
              createdTime: c.created / 1000,
              sigType: Number(c.signatureType).toString(16) + "x",
              userId: "",
              fpr: "",
              sigKnown: false
            };

            if (c.issuerFingerprint) {
              sig.signerKeyId = EnigmailFuncs.arrayToHex(c.issuerFingerprint);
            }
            else {
              sig.signerKeyId = c.issuerKeyId.toHex().toUpperCase();
            }
            uid.sigList.push(sig);
          }

          sigs.push(uid);
        }
      }
    }

    return sigs;
  },

  /**
   * Decrypt a secret key. If needed, request password via dialog, or use password in
   * password manager
   *
   * @param {Object} key:    OpenPGP.js key
   * @param {Number} reason: Reason code (EnigmailConstants.KEY_DECRYPT_REASON_xxx)
   */
  decryptSecretKey: async function(key, reason) {
    EnigmailLog.DEBUG(`pgpjs-keys.jsm: decryptSecretKey(${key.getFingerprint()})\n`);

    if (!key.isPrivate()) return false;
    if (key.isDecrypted()) return true;

    const pm = Cc["@mozilla.org/login-manager;1"].getService(Ci.nsILoginManager);
    const queryString = ENIGMAIL_PASSWD_PREFIX + key.getFingerprint().toUpperCase();

    let logins = pm.getAllLogins();
    let password = null,
      attempts = 0;

    // Find user from returned array of nsILoginInfo objects
    for (let login of logins) {
      if (login.hostname === queryString && login.httpRealm === OPENPGPKEY_REALM) {
        password = login.password;
        break;
      }
    }

    while (attempts < MAX_PASSWD_ATTEMPT) {
      if (!password) {
        ++attempts;
        password = requestPassword(key, reason, attempts);
        if (!password) break;
      }

      if (password) {
        try {
          let success = await key.decrypt(password);
          if (success) {
            return true;
          }
          else {
            password = null;
          }
        }
        catch (ex) {
          if (("message" in ex) && ex.message.search(/Incorrect .*passphrase/) >= 0) {
            password = null;
          }
          else {
            EnigmailLog.DEBUG(`pgpjs-keys.jsm: decryptSecretKey: ERROR: ${ex.toString()}\n`);
            attempts = MAX_PASSWD_ATTEMPT;
          }

          if (ex.toString().search(/s2k/i) >= 0) {
            displayMd5Error();
          }
        }
      }
    }

    return false;
  },

  generateKey: async function(name, comment, email, expiryDate, keyLength, keyType, passphrase) {
    EnigmailLog.DEBUG(`pgpjs-keys.jsm: generateKey(${name}, ${email}, ${expiryDate}, ${keyLength}, ${keyType})\n`);

    const PgpJS = getOpenPGPLibrary();
    let genName = name;
    if (comment && comment.length > 0) {
      genName += ` (${comment})`;
    }

    if (email) {
      genName += ` <${email}>`;
    }

    // Name, comment and email are in UTF-8
    genName = EnigmailData.convertToUnicode(genName.trim(), 'utf-8');

    let options = {
      userIds: genName,
      keyExpirationTime: expiryDate * 86400,
      passphrase: EnigmailData.convertToUnicode(passphrase, 'utf-8'),
      subkeys: [{}]
    };

    switch (keyType) {
      case "ECC":
        options.curve = "ed25519";
        break;
      case "RSA":
        options.rsaBits = keyLength;
        break;
      default:
        throw Error(`Invalid key type ${keyType}`);
    }

    const {
      privateKeyArmored,
      revocationCertificate
    } = await PgpJS.generateKey(options);

    const key = (await PgpJS.key.readArmored(privateKeyArmored)).keys[0];


    EnigmailLog.DEBUG(`pgpjs-keys.jsm: generateKey: key created\n`);
    return {
      privateKey: privateKeyArmored,
      revocationCertificate: revocationCertificate,
      key: key
    };
  },

  /**
   * Extract a photo ID from a key, store it as file and return the file object.
   *
   * @param {Object} key:         OpenPGP.js key object
   * @param {Number} photoNumber: number of the photo on the key, starting with 0
   *
   * @return {nsIFile} object or null in case no data / error.
   */

  getPhotoForKey: async function(key, photoNumber) {
    EnigmailLog.DEBUG(`pgpjs-keys.jsm: getPhotoForKey: (${key.getFingerprint()}, ${photoNumber})\n`);

    let currUat = 0;

    for (let i in key.users) {
      if (key.users[i].userAttribute !== null) {
        if (currUat < photoNumber) {
          ++currUat;
          continue;
        }

        if (key.users[i].userAttribute.attributes.length > 0) {
          return writeTempPhotoData(key.users[i].userAttribute.write());
        }
      }
    }

    return null;
  }
};


function displayMd5Error() {
  const EnigmailDialog = ChromeUtils.import("chrome://enigmail/content/modules/dialog.jsm").EnigmailDialog;

  EnigmailDialog.alert(null, EnigmailLocale.getString("decryptKey.md5Error"));
}

/**
 * Prompt for the password of an OpenPGP key
 *
 * @param {Object} key:     OpenPGP.js key
 * @param {Number} reason:  Reason code (EnigmailConstants.KEY_DECRYPT_REASON_xxx)
 * @param {Number} attempt: The number of attempts to decrypt the key
 */
function requestPassword(key, reason, attempt) {
  EnigmailLog.DEBUG(`pgpjs-keys.jsm: requestPassword(${key.getFingerprint()}, ${reason})\n`);

  const promptSvc = Cc["@mozilla.org/embedcomp/prompt-service;1"].getService(Ci.nsIPromptService);

  let passwdObj = {
      value: ""
    },
    checkedObj = {
      value: false
    },
    fpr = key.getFingerprint().toUpperCase(),
    created = EnigmailTime.getDateTime(key.getCreationTime().getTime() / 1000, true, false),
    uid = key.users[0].userId.userid;

  let reasonStr = "";
  switch (reason) {
    case EnigmailConstants.KEY_DECRYPT_REASON_ENCRYPTED_MSG:
      reasonStr = "decryptkey.reasonEncryptedMsg";
      break;
    case EnigmailConstants.KEY_DECRYPT_REASON_SIGN_MSG:
      reasonStr = "decryptkey.reasonSignMsg";
      break;
    case EnigmailConstants.KEY_DECRYPT_REASON_SIGNCRYPT_MSG:
      reasonStr = "decryptkey.reasonSignAndEncryptMsg";
      break;
    case EnigmailConstants.KEY_DECRYPT_REASON_MANIPULATE_KEY:
      reasonStr = "decryptkey.reasonKeyOp";
      break;
  }

  const passphraseDesc = EnigmailLocale.getString(reasonStr) + "\n\n" +
    EnigmailLocale.getString("decryptkey.keyDescription", [
      uid,
      fpr,
      created
    ]);

  let dlgTitle = EnigmailLocale.getString("decryptkey.dialogTitle");
  if (attempt > 1) {
    dlgTitle += " " + EnigmailLocale.getString("decryptkey.dialog.attempt", [attempt, MAX_PASSWD_ATTEMPT]);
  }

  let res = promptSvc.promptPassword(null, dlgTitle, passphraseDesc, passwdObj, EnigmailLocale.getString("decryptkey.storeInPasswdMgr"), checkedObj);

  if (res && passwdObj.value.length > 0) {
    if (checkedObj.value) {
      storePasswordInPasswdManager(fpr, passwdObj.value);
    }

    return passwdObj.value;
  }

  return null;
}


function storePasswordInPasswdManager(fpr, password) {
  EnigmailLog.DEBUG(`pgpjs-keys.jsm: storePasswordInPasswdManager(${fpr})\n`);

  const pm = Cc["@mozilla.org/login-manager;1"].getService(Ci.nsILoginManager);
  const queryString = ENIGMAIL_PASSWD_PREFIX + fpr;

  let logins = pm.getAllLogins();

  // Find user from returned array of nsILoginInfo objects
  for (let login of logins) {
    if (login.hostname === queryString && login.httpRealm === OPENPGPKEY_REALM) {
      pm.removeLogin(login);
      break;
    }
  }

  const nsLoginInfo = new Components.Constructor(
    "@mozilla.org/login-manager/loginInfo;1",
    Ci.nsILoginInfo,
    "init"
  );

  let loginInfo = new nsLoginInfo(queryString, null, OPENPGPKEY_REALM, "", password, "", "");
  pm.addLogin(loginInfo);
}


function writeTempPhotoData(photoData) {
  EnigmailLog.DEBUG(`pgpjs-keys.jsm: writeTempPhotoData(${photoData.length})\n`);

  const EnigmailRNG = ChromeUtils.import("chrome://enigmail/content/modules/rng.jsm").EnigmailRNG;

  try {
    const flags = NS_WRONLY | NS_CREATE_FILE | NS_TRUNCATE;
    const tempFile = EnigmailFiles.getTempDirObj();
    let photoStr = EnigmailData.arrayBufferToString(photoData);

    // Determine subpacket header length (RFC 4880, section 5.12.) that needs to be skipped
    let hdrLength = 0;
    let dataSize = 0;
    const firstByte = photoData[0];

    if (firstByte < 192) {
      hdrLength = 1;
      dataSize = firstByte;
    }
    else if (firstByte <= 223) {
      hdrLength = 2;
      dataSize = ((firstByte - 192) << 8) + (photoData[1]) + 192;
    }
    else if (firstByte === 255) {
      hdrLength = 5;
      dataSize = (photoData[1] << 24) | (photoData[2] << 16) | (photoData[3] << 8) | photoData[4];
    }
    else {
      // no valid length for a photo
      EnigmailLog.DEBUG(`pgpjs-keys.jsm: writeTempPhotoData: no valid subpacket length ${firstByte}\n`);
      return null;
    }

    const subPacketType = photoData[hdrLength];

    if (subPacketType !== 1) {
      EnigmailLog.DEBUG(`pgpjs-keys.jsm: writeTempPhotoData: subpacket type ${subPacketType} is not recognized\n`);
      return null;
    }

    const skipData = 16 + hdrLength + 1;
    photoStr = photoStr.substr(skipData, dataSize);

    tempFile.append(EnigmailRNG.generateRandomString(8) + ".jpg");
    tempFile.createUnique(tempFile.NORMAL_FILE_TYPE, STANDARD_FILE_PERMS);

    const fileStream = Cc[NS_LOCALFILEOUTPUTSTREAM_CONTRACTID].createInstance(Ci.nsIFileOutputStream);
    fileStream.init(tempFile, flags, STANDARD_FILE_PERMS, 0);
    if (fileStream.write(photoStr, photoStr.length) !== photoStr.length) {
      fileStream.close();
      throw Components.results.NS_ERROR_FAILURE;
    }

    fileStream.flush();
    fileStream.close();

    // delete picFile upon exit
    let extAppLauncher = Cc["@mozilla.org/mime;1"].getService(Ci.nsPIExternalAppLauncher);
    extAppLauncher.deleteTemporaryFileOnExit(tempFile);
    return tempFile;
  }
  catch (ex) {}

  return null;
}
