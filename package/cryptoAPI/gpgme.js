/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["getGpgMEApi"];

var Services = Components.utils.import("resource://gre/modules/Services.jsm").Services;

if (typeof CryptoAPI === "undefined") {
  Services.scriptloader.loadSubScript("chrome://enigmail/content/modules/cryptoAPI/interface.js",
    null, "UTF-8"); /* global CryptoAPI */
}

const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailExecution = ChromeUtils.import("chrome://enigmail/content/modules/execution.jsm").EnigmailExecution;
const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
const EnigmailTime = ChromeUtils.import("chrome://enigmail/content/modules/time.jsm").EnigmailTime;
const EnigmailData = ChromeUtils.import("chrome://enigmail/content/modules/data.jsm").EnigmailData;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
const EnigmailPassword = ChromeUtils.import("chrome://enigmail/content/modules/passwords.jsm").EnigmailPassword;
const EnigmailOS = ChromeUtils.import("chrome://enigmail/content/modules/os.jsm").EnigmailOS;
const EnigmailCore = ChromeUtils.import("chrome://enigmail/content/modules/core.jsm").EnigmailCore;

//const pgpjs_keys = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keys.jsm").pgpjs_keys;

const nsIWindowsRegKey = Ci.nsIWindowsRegKey;

const VALIDITY_SYMBOL = {
  ultimate: "u",
  unknown: "-",
  full: "f",
  marginal: "m",
  never: "n"
};

var inspector;

/**
 * GpgME-JSON implementation of CryptoAPI
 */

class GpgMECryptoAPI extends CryptoAPI {
  constructor() {
    super();
    this.api_name = "GpgME";
    this._gpgmePath = "";

    if (!inspector) {
      inspector = Cc["@mozilla.org/jsinspector;1"].createInstance(Ci.nsIJSInspector);
    }
  }

  /**
   * Initialize the tools/functions required to run the API
   *
   * @param {nsIWindow} parentWindow: parent window, may be NULL
   * @param {Object} esvc: Enigmail service object
   * @param {String } preferredPath: try to use specific path to locate tool (gpg)
   */
  initialize(parentWindow, esvc, preferredPath) {
    if (!esvc) {
      esvc = {
        environment: Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment)
      };
    }

    this._gpgmePath = resolvePath(esvc.environment);
  }

  /**
   * Close/shutdown anything related to the functionality
   */
  finalize() {
    return null;
  }


  /**
   * Obtain signatures for a given set of key IDs.
   *
   * @param {String}  fpr:            key fingerprint
   * @param {Boolean} ignoreUnknownUid: if true, filter out unknown signer's UIDs
   *
   * @return {Promise<Array of Object>}
   *     - {String} userId
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
  async getKeySignatures(fpr, ignoreUnknownUid = false) {
    return null;
  }

  /**
   * Export the minimum key for the public key object:
   * public key, user ID, newest encryption subkey
   *
   * @param {String} fpr  : a single FPR
   * @param {String} email: [optional] the email address of the desired user ID.
   *                        If the desired user ID cannot be found or is not valid, use the primary UID instead
   *
   * @return {Promise<Object>}:
   *    - exitCode (0 = success)
   *    - errorMsg (if exitCode != 0)
   *    - keyData: BASE64-encded string of key data
   */
  async getMinimalPubKey(fpr, email) {
    return {
      exitCode: -1,
      errorMsg: "",
      keyData: ""
    };
  }

  /**
   * Get a minimal stripped key containing only:
   * - The public key
   * - the primary UID + its self-signature
   * - the newest valild encryption key + its signature packet
   *
   * @param {String} armoredKey: Key data (in OpenPGP armored format)
   *
   * @return {Promise<Uint8Array, or null>}
   */

  async getStrippedKey(armoredKey) {
    return null;
  }

  /**
   * Get the list of all konwn keys (including their secret keys)
   * @param {Array of String} onlyKeys: [optional] only load data for specified key IDs
   *
   * @return {Promise<Array of Object>}
   */
  async getKeys(onlyKeys = null) {
    let keysObj = await this.execJsonCmd({
      "op": "keylist",
      "with-secret": true
    });

    let keyArr = [];
    if ("keys" in keysObj) {
      for (let key of keysObj.keys) {
        keyArr.push(createKeyObj(key));
      }
    }

    return keyArr;
  }

  /**
   * Return an array containing the aliases and the email addresses
   *
   * @return {Array<{alias,keylist}>} <{String,String}>
   */
  getGroups() {
    let cfg = this.sync(this.execJsonCmd({
      op: "config_opt",
      component: "gpg",
      option: "group"
    }));
    let groups = null;
    if ("option" in cfg) {
      groups = cfg.option.value;
    }

    if (!groups) return [];

    let groupList = [];
    for (let g of groups) {
      let parts = g.string.match(/^([^=]+)=(.+)$/);
      if (parts && parts.length > 2) {
        parts[1] = parts[1].toLowerCase();
        if (parts[1] in groupList) {
          groupList[parts[1]] += ` ${parts[2]}`;
        }
        else
          groupList[parts[1]] = parts[2];
      }
    }

    let ret = [];
    for (let g in groupList) {
      ret.push({
        alias: g,
        keylist: groupList[g]
      });
    }

    return ret;
  }

  /**
   * Get groups defined in gpg.conf in the same structure as KeyObject
   * [synchronous]
   *
   * @return {Array of KeyObject} with type = "grp"
   */
  getGroupList() {
    let groupList = this.getGroups();
    let retList = [];
    for (let grp of groupList) {

      let grpObj = {
        type: "grp",
        keyUseFor: "G",
        userIds: [],
        subKeys: [],
        keyTrust: "g",
        userId: grp.alias,
        keyId: grp.alias
      };

      let rcpt = grp.keylist.split(/[,; ]+/);
      for (let r of rcpt) {
        grpObj.userIds.push({
          userId: r,
          keyTrust: "q"
        });
      }

      retList.push(grpObj);
    }

    return retList;
  }

  /**
   * Extract a photo ID from a key, store it as file and return the file object.
   *
   * @param {String} keyId:       Key ID / fingerprint
   * @param {Number} photoNumber: number of the photo on the key, starting with 0
   *
   * @return {nsIFile} object or null in case no data / error.
   */
  async getPhotoFile(keyId, photoNumber) {
    return null;
  }

  /**
   * Import key(s) from a file
   *
   * @param {nsIFile} inputFile:  the file holding the keys
   *
   * @return {Object} or null in case no data / error:
   *   - {Number}          exitCode:        result code (0: OK)
   *   - {Array of String) importedKeys:    imported fingerprints
   *   - {Number}          importSum:       total number of processed keys
   *   - {Number}          importUnchanged: number of unchanged keys
   */

  async importKeyFromFile(inputFile) {
    const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;

    let fileData = EnigmailFiles.readBinaryFile(inputFile);
    return this.importKeyData(fileData, false, null);
  }

  /**
   * Import key(s) from a string
   *
   * @param {String} keyData:  the key data to be imported (ASCII armored)
   * @param {Boolean} minimizeKey: import the minimum key without any 3rd-party signatures
   * @param {Array of String} limitedUids: skip UIDs that were not specified
   *
   * @return {Object} or null in case no data / error:
   *   - {Number}          exitCode:        result code (0: OK)
   *   - {Array of String) importedKeys:    imported fingerprints
   *   - {Number}          importSum:       total number of processed keys
   *   - {Number}          importUnchanged: number of unchanged keys
   */

  async importKeyData(keyData, minimizeKey, limitedUids) {
    let res = await this.execJsonCmd({
      op: "import",
      data: keyData,
      protocol: "openpgp",
      base64: false
    });

    if ("result" in res) {
      EnigmailLog.DEBUG(`gpgme.js: importKeys: ${JSON.stringify(res)}`);
      let r = {
        exitCode: 0,
        importSum: res.result.considered,
        importedKeys: [],
        importUnchanged: res.result.unchanged
      };

      for (let k of res.result.imports) {
        r.importedKeys.push(k.fingerprint);
      }

      return r;
    }

    return null;
  }

  /**
   * Delete keys from keyring
   *
   * @param {Array<String>} fpr: fingerprint(s) to delete
   * @param {Boolean} deleteSecretKey: if true, also delete secret keys
   * @param {nsIWindow} parentWindow: parent window for displaying modal dialogs
   *
   * @return {Promise<Object>}:
   *      - {Number} exitCode: 0 if successful, other values indicate error
   *      - {String} errorMsg: error message if deletion not successful
   */
  async deleteKeys(fpr, deleteSecretKey, parentWindow) {
    return null;
  }

  /**
   * Export secret key(s) as ASCII armored data
   *
   * @param {String}  keyId       Specification by fingerprint or keyID, separate mutliple keys with spaces
   * @param {Boolean} minimalKey  if true, reduce key to minimum required
   *
   * @return {Object}:
   *   - {Number} exitCode:  result code (0: OK)
   *   - {String} keyData:   ASCII armored key data material
   *   - {String} errorMsg:  error message in case exitCode !== 0
   */

  async extractSecretKey(keyId, minimalKey) {
    return null;
  }

  /**
   * Export public key(s) as ASCII armored data
   *
   * @param {String}  keyId       Specification by fingerprint or keyID, separate mutliple keys with spaces
   * @param {Boolean} minimalKey  if true, reduce key to minimum required
   *
   * @return {Object}:
   *   - {Number} exitCode:  result code (0: OK)
   *   - {String} keyData:   ASCII armored key data material
   *   - {String} errorMsg:  error message in case exitCode !== 0
   */

  async extractPublicKey(keyId) {
    return null;
  }

  /**
   * Generate a new key pair
   *
   * @param {String} name:       name part of UID
   * @param {String} comment:    comment part of UID (brackets are added)
   * @param {String} email:      email part of UID (<> will be added)
   * @param {Number} expiryDate: Unix timestamp of key expiry date; 0 if no expiry
   * @param {Number} keyLength:  size of key in bytes (e.g 4096)
   * @param {String} keyType:    'RSA' or 'ECC'
   * @param {String} passphrase: password; use null if no password
   *
   * @return {Object}: Handle to key creation
   *    - {function} cancel(): abort key creation
   *    - {Promise<exitCode, generatedKeyId>} promise: resolved when key creation is complete
   *                 - {Number} exitCode:       result code (0: OK)
   *                 - {String} generatedKeyId: generated key ID
   */

  generateKey(name, comment, email, expiryDate, keyLength, keyType, passphrase) {
    return null;
  }


  /**
   * Determine the file name from OpenPGP data.
   *
   * @param {byte} byteData    The encrypted data
   *
   * @return {String} - the name of the attached file
   */

  async getFileName(byteData) {
    return null;
  }

  /**
   * Verify the detached signature of an attachment (or in other words,
   * check the signature of a file, given the file and the signature).
   *
   * @param {String} filePath    Path specification for the signed file
   * @param {String} sigPath     Path specification for the signature file
   *
   * @return {Promise<String>} - A message from the verification.
   *
   * Use Promise.catch to handle failed verifications.
   * The message will be an error message in this case.
   */

  async verifyAttachment(filePath, sigPath) {
    return null;
  }

  /**
   * Decrypt an attachment.
   *
   * @param {Bytes}  encrypted     The encrypted data
   *
   * @return {Promise<Object>} - Return object with decryptedData and
   * status information
   *
   * Use Promise.catch to handle failed decryption.
   * retObj.errorMsg will be an error message in this case.
   */

  async decryptAttachment(encrypted) {
    return null;
  }

  /**
   * Generic function to decrypt and/or verify an OpenPGP message.
   *
   * @param {String} encrypted     The encrypted data
   * @param {Object} options       Decryption options
   *
   * @return {Promise<Object>} - Return object with decryptedData and
   * status information
   *
   * Use Promise.catch to handle failed decryption.
   * retObj.errorMsg will be an error message in this case.
   */

  async decrypt(encrypted, options) {
    return null;
  }

  /**
   * Decrypt a PGP/MIME-encrypted message
   *
   * @param {String} encrypted     The encrypted data
   * @param {Object} options       Decryption options
   *      - logFile (the actual file)
   *      - keyserver
   *      - keyserverProxy
   *      - fromAddr
   *      - noOutput
   *      - verifyOnly
   *      - uiFlags
   *      - mimeSignatureFile
   *      - maxOutputLength
   *
   * @return {Promise<Object>} - Return object with decryptedData and status information:
   *     - {String} decryptedData
   *     - {Number} exitCode
   *     - {Number} statusFlags
   *     - {String} errorMsg
   *     - {String} blockSeparation
   *     - {String} userId: signature user Id
   *     - {String} keyId: signature key ID
   *     - {String} sigDetails: as printed by GnuPG for VALIDSIG pattern
    retStatusObj.encToDetails = encToDetails;
  *
   *
   * Use Promise.catch to handle failed decryption.
   * retObj.errorMsg will be an error message in this case.
   */

  async decryptMime(encrypted, options) {
    return null;
  }

  /**
   * Verify a PGP/MIME-signed message
   *
   * @param {String} signedData    The signed data
   * @param {String} signature     The signature data
   * @param {Object} options       Decryption options
   *
   * @return {Promise<Object>} - Return object with decryptedData and
   * status information
   *
   * Use Promise.catch to handle failed decryption.
   * retObj.errorMsg will be an error message in this case.
   */

  async verifyMime(signedData, signature, options) {
    return null;
  }

  /**
   * Get details (key ID, UID) of the data contained in a OpenPGP key block
   *
   * @param {String} keyBlockStr  String: the contents of one or more public keys
   *
   * @return {Promise<Array>}: array of objects with the following structure:
   *          - id (key ID)
   *          - fpr
   *          - name (the UID of the key)
   */

  async getKeyListFromKeyBlock(keyBlockStr) {
    return null;
  }

  /**
   * Export the ownertrust database
   * @param {String or nsIFile} outputFile: Output file name or Object - or NULL if trust data
   *                                        should be returned as string
   *
   * @return {Object}:
   *          - ownerTrustData {String}: if outputFile is NULL, the key block data; "" if a file is written
   *          - exitCode {Number}: exit code
   *          - errorMsg {String}: error message
   */
  async getOwnerTrust(outputFile) {
    return {
      exitCode: 0,
      ownerTrustData: "",
      errorMsg: ""
    };
  }


  /**
   * Import the ownertrust database
   *
   * @param {String or nsIFile} inputFile: input file name or Object
   *
   * @return {Object}:
   *         - exitCode {Number}: exit code
   *         - errorMsg {String}: error message
   */
  async importOwnerTrust(inputFile) {
    return {
      exitCode: 0,
      errorMsg: ""
    };
  }


  /**
   * Encrypt messages
   *
   * @param {String} from: keyID or email address of sender/signer
   * @param {String} recipients: keyIDs or email addresses of recipients, separated by spaces
   * @param {String} hiddenRecipients: keyIDs or email addresses of hidden recipients (bcc), separated by spaces
   * @param {Number} encryptionFlags: Flags for Signed/encrypted/PGP-MIME etc.
   * @param {String} plainText: data to encrypt
   * @param {String} hashAlgorithm: [OPTIONAL] hash algorithm
   * @param {nsIWindow} parentWindow: [OPTIONAL] window on top of which to display modal dialogs
   *
   * @return {Object}:
   *     - {Number} exitCode:    0 = success / other values: error
   *     - {String} data:        encrypted data
   *     - {String} errorMsg:    error message in case exitCode !== 0
   *     - {Number} statusFlags: Status flags for result
   */

  async encryptMessage(from, recipients, hiddenRecipients, encryptionFlags, plainText, hashAlgorithm = null, parentWindow = null) {
    return null;
  }

  /**
   * Encrypt Files
   *
   * @param {String} from: keyID or email address of sender/signer
   * @param {String} recipients: keyIDs or email addresses of recipients, separated by spaces
   * @param {String} hiddenRecipients: keyIDs or email addresses of hidden recipients (bcc), separated by spaces
   * @param {Number} encryptionFlags: Flags for Signed/encrypted/PGP-MIME etc.
   * @param {nsIFile} inputFile: source file to encrypt
   * @param {nsIFile} outputFile: target file containing encrypted data
   *
   * @return {Object}:
   *     - {Number} exitCode:    0 = success / other values: error
   *     - {String} data:        encrypted data
   *     - {String} errorMsg:    error message in case exitCode !== 0
   *     - {Number} statusFlags: Status flags for result
   */

  async encryptFile(from, recipients, hiddenRecipients, encryptionFlags, inputFile, outputFile, parentWindow = null) {
    return null;
  }

  /**
   * Clear any cached passwords
   *
   * @return {Boolean} true if successful, false otherwise
   */
  async clearPassphrase() {
    return null;
  }

  /***
   * Determine if a specific feature is available by the used toolset
   *
   * @param {String} featureName:  String; one of the following values:
   *    version-supported    - is the gpg version supported at all (true for gpg >= 2.0.10)
   *    supports-gpg-agent   - is gpg-agent is auto-started (true for gpg >= 2.0.16)
   *    keygen-passphrase    - can the passphrase be specified when generating keys (false for gpg 2.1 and 2.1.1)
   *    windows-photoid-bug  - is there a bug in gpg with the output of photoid on Windows (true for gpg < 2.0.16)
   *    genkey-no-protection - is "%no-protection" supported for generting keys (true for gpg >= 2.1)
   *    search-keys-cmd      - what command to use to terminate the --search-key operation. ("save" for gpg > 2.1; "quit" otherwise)
   *    socks-on-windows     - is SOCKS proxy supported on Windows (true for gpg >= 2.0.20)
   *    supports-dirmngr     - is dirmngr supported (true for gpg >= 2.1)
   *    supports-ecc-keys    - are ECC (elliptic curve) keys supported (true for gpg >= 2.1)
   *    supports-sender      - does gnupg understand the --sender argument (true for gpg >= 2.1.15)
   *    supports-wkd         - does gpg support wkd (web key directory) (true for gpg >= 2.1.19)
   *    export-result        - does gpg print EXPORTED when exporting keys (true for gpg >= 2.1.10)
   *    decryption-info      - does gpg print DECRYPTION_INFO (true for gpg >= 2.0.19)
   *    export-specific-uid  - does gpg support exporting a key with a specific UID (true for gpg >= 2.2.8)
   *    supports-show-only   - does gpg support --import-options show-only (true for gpg >= 2.1.14)
   *    handles-huge-keys    - can gpg deal with huge keys without aborting (true for gpg >= 2.2.17)
   *    smartcard            - does the library support smartcards
   *
   * @return: depending on featureName - Boolean unless specified differently:
   *    (true if feature is available / false otherwise)
   *   If the feature cannot be found, undefined is returned
   */
  supportsFeature(featureName) {
    return false;
  }


  /**
   *
   * @param {String} trustCode
   * @return {String}   Localized label
   */
  getTrustLabel(trustCode) {
    let keyTrust = trustCode;
    switch (trustCode) {
      case '-':
        keyTrust = EnigmailLocale.getString("keyValid.unknown");
        break;
      case 'i':
        keyTrust = EnigmailLocale.getString("keyValid.invalid");
        break;
      case 'd':
      case 'D':
        keyTrust = EnigmailLocale.getString("keyValid.disabled");
        break;
      case 'r':
        keyTrust = EnigmailLocale.getString("keyValid.revoked");
        break;
      case 'e':
        keyTrust = EnigmailLocale.getString("keyValid.expired");
        break;
      case 'n':
        keyTrust = EnigmailLocale.getString("keyTrust.untrusted");
        break;
      case 'm':
        keyTrust = EnigmailLocale.getString("keyTrust.marginal");
        break;
      case 'f':
        keyTrust = EnigmailLocale.getString("keyTrust.full");
        break;
      case 'u':
        keyTrust = EnigmailLocale.getString("keyTrust.ultimate");
        break;
      default:
        keyTrust = "";
    }

    return keyTrust;
  }

  /**
   * Return the key management functions (sub-API)
   */
  getKeyManagement() {

    function createError() {
      return {
        returnCode: 1,
        errorMsg: "Not implemented"
      };
    }

    return {
      /**
       * Generate a revocation certificate and save it as a file
       *
       * @param {nsIWindow} parent       parent window for displaying (modal) messages
       * @param {String}    keyId        fingerprint of the key to modify
       * @param {nsIFile}   outFile      handle file for saving the revocation certificate
       * @param {String}    reasonCode   revocation reason code as used by GnuPG "ask_revocation_reason.code"
       * @param {String}    reasonText   explanation for revocation reason
       * @return  {Promise<Object>}
       *               - retunCode {Number}   0 = success / other values = error
       *               - errorMsg  {String}   error message in case of error
       */
      genRevokeCert: async function(parent, keyId, outFile, reasonCode, reasonText) {
        return createError();
      },


      /**
       * set the expiration date of the chosen key and subkeys
       *
       * @param {nsIWindow} parent        parent window for displaying (modal) messages
       * @param {String}    keyId         fingerprint of the key to modify
       * @param {Array}     subKeys       List of Integer values, e.g. [0,1,3]
       *                                  "0" reflects the primary key and should always be set.
       * @param {Integer}   expiryValue   A number between 1 and 100
       * @param {Integer}   timeScale     1 or 30 or 365 meaning days, months, years
       * @param {Boolean}   noExpiry      True: never expire. False: use expiryLength.
       * @return {Promise<Object>}
       *               - retunCode {Number}   0 = success / other values = error
       *               - errorMsg  {String}   error message in case of error
       */
      setKeyExpiration: async function(parent, keyId, subKeys, expiryValue, timeScale, noExpiry) {
        return createError();
      },


      /**
       * Enable or disable a key
       *
       * @param {nsIWindow} parent        parent window for displaying (modal) messages
       * @param {String}    keyId         fingerprint of the key to modify
       * @param {Boolean}   disableKey    True: disable key / false: enable key
       * @return {Promise<Object>}
       *               - retunCode {Number}   0 = success / other values = error
       *               - errorMsg  {String}   error message in case of error
       */
      enableDisableKey: async function(parent, keyId, disableKey) {
        return createError();
      },


      /**
       * Initate the process (indlucing a dialog) to change the password of a key
       *
       * @param {nsIWindow} parent        parent window for displaying (modal) messages
       * @param {String}    keyId         fingerprint of the key to modify
       * @return {Promise<Object>}
       *               - retunCode {Number}   0 = success / other values = error
       *               - errorMsg  {String}   error message in case of error
       */
      initiateChangePassphrase: async function(parent, keyId) {
        return createError();
      },


      /**
       * Sign a key with another key
       *
       * @param {nsIWindow}     parent        parent window for displaying (modal) messages
       * @param {String}        signingKeyId  fingerprint of the key used for signing
       * @param {String}        keyIdToSign   fingerprint of the key to be signed
       * @param {Array<String>} signUids      userIDs to sign (must match 1:1)
       * @param {Boolean}       signLocally   true: create non-exportable signature / false: create exportable signature
       * @param {Number}        trustLevel    Signture Trust level as in GnuPG "sign_uid.class"
       * @return {Promise<Object>}
       *               - retunCode {Number}   0 = success / other values = error
       *               - errorMsg  {String}   error message in case of error
       */
      signKey: async function(parent, signingKeyId, keyIdToSign, signUids, signLocally, trustLevel) {
        return createError();
      },


      /**
       * Add a userID to a key
       *
       * @param {nsIWindow} parent        parent window for displaying (modal) messages
       * @param {String}    keyId         fingerprint of the key to modify
       * @param {String}    name          Display name of the UID (e.g. Bob Dylan)
       * @param {String}    email         Email address of the UID (e.g. bob.dylan@domain.invalid)
       * @param {String}    commment      Comment to be added in brackets
       * @return {Promise<Object>}
       *               - retunCode {Number}   0 = success / other values = error
       *               - errorMsg  {String}   error message in case of error
       */
      addUid: function(parent, keyId, name, email, comment) {
        return createError();
      },


      /**
       * Set the primary UID on the key
       *
       * @param {nsIWindow} parent        parent window for displaying (modal) messages
       * @param {String}    keyId         fingerprint of the key to modify
       * @param {Number}    idNumber      the number of the UID to be set to primary, starting with 1
       * @return {Promise<Object>}
       *               - retunCode {Number}   0 = success / other values = error
       *               - errorMsg  {String}   error message in case of error
       */
      setPrimaryUid: function(parent, keyId, idNumber) {
        return createError();
      },


      /**
       * Revoke a UID on a key
       *
       * @param {nsIWindow} parent        parent window for displaying (modal) messages
       * @param {String}    keyId         fingerprint of the key to modify
       * @param {Number}    idNumber      the number of the UID to be revoked, starting with 1
       * @return {Promise<Object>}
       *               - retunCode {Number}   0 = success / other values = error
       *               - errorMsg  {String}   error message in case of error
       */
      revokeUid: function(parent, keyId, idNumber) {
        return createError();
      },


      /**
       * Add a UAT to a key containing a JPEG picture
       *
       * @param {nsIWindow} parent     parent window for displaying (modal) messages
       * @param {String}    keyId      fingerprint of the key to modify
       * @param {nsIFile}   photoFile  File containing JPEG data
       * @return {Promise<Object>}
       *               - retunCode {Number}   0 = success / other values = error
       *               - errorMsg  {String}   error message in case of error
       */
      addPhoto: function(parent, keyId, photoFile) {
        return createError();
      }
    };

  }

  /**
   * Return the OpenPGP configuration directory (if any)
   *
   * @return {String}: config directory or null if none
   */
  getConfigDir() {
    return null;
  }

  // TODO: use gpgme-json as a daemon running as long as the mail app.
  async execJsonCmd(paramsObj) {
    let jsonStr = JSON.stringify(paramsObj);
    let n = jsonStr.length;
    EnigmailLog.DEBUG(`gpgHome: ${EnigmailCore.getEnvList().join(", ")}\n`);
    let result = await EnigmailExecution.execAsync(this._gpgmePath, [], convertNativeNumber(n) + jsonStr);

    try {
      if (!result.stdoutData) throw "no data";
      let retObj = JSON.parse(result.stdoutData.substr(4));
      return retObj;
    }
    catch (ex) {
      return {
        "error": result.stderrData
      };
    }
  }
}


function getGpgMEApi() {
  return new GpgMECryptoAPI();
}


/**
 * Determine the location of the GnuPG executable
 *
 * @param env: Object: nsIEnvironment to use
 *
 * @return Object: nsIFile pointing to gpg, or NULL
 */
function resolvePath(env) {
  EnigmailLog.DEBUG("gpgme.js: resolvePath()\n");

  let toolName = EnigmailOS.isDosLike ? "gpgme-json.exe" : "gpgme-json";

  // Resolve relative path using PATH environment variable
  const envPath = env.get("PATH");
  let toolPath = EnigmailFiles.resolvePath(toolName, envPath, EnigmailOS.isDosLike);

  if (!toolPath && EnigmailOS.isDosLike) {
    // DOS-like systems: search for GPG in c:\gnupg, c:\gnupg\bin, d:\gnupg, d:\gnupg\bin
    let gpgPath = "c:\\gnupg;c:\\gnupg\\bin;d:\\gnupg;d:\\gnupg\\bin";
    toolPath = EnigmailFiles.resolvePath(toolName, gpgPath, EnigmailOS.isDosLike);
  }

  if ((!toolPath) && EnigmailOS.isWin32) {
    // Look up in Windows Registry
    const installDir = ["Software\\Gpg4win"];

    try {
      for (let i = 0; i < installDir.length && !toolPath; i++) {
        let gpgPath = EnigmailOS.getWinRegistryString(installDir[i], "Install Directory", nsIWindowsRegKey.ROOT_KEY_LOCAL_MACHINE);

        toolPath = EnigmailFiles.resolvePath(toolName, gpgPath, EnigmailOS.isDosLike);
        if (!toolPath) {
          gpgPath += "\\bin";
          toolPath = EnigmailFiles.resolvePath(toolName, gpgPath, EnigmailOS.isDosLike);
        }
      }
    }
    catch (ex) {}

    if (!toolPath) {
      // try to determine the default PATH from the registry after the installation
      // if we could not get any information from the registry
      try {
        let winPath = EnigmailOS.getWinRegistryString("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "Path", nsIWindowsRegKey.ROOT_KEY_LOCAL_MACHINE);
        toolPath = EnigmailFiles.resolvePath(toolName, winPath, EnigmailOS.isDosLike);
      }
      catch (ex) {}
    }

    if (!toolPath) {
      // default for gpg4win 3.0
      let gpgPath = "C:\\Program Files\\GnuPG\\bin;C:\\Program Files (x86)\\GnuPG\\bin";
      toolPath = EnigmailFiles.resolvePath(toolName, gpgPath, EnigmailOS.isDosLike);
    }
  }

  if (!toolPath && !EnigmailOS.isDosLike) {
    // Unix-like systems: check /usr/bin and /usr/local/bin
    let gpgPath = "/usr/bin:/usr/local/bin";
    toolPath = EnigmailFiles.resolvePath(toolName, gpgPath, EnigmailOS.isDosLike);
  }

  if (!toolPath) {
    return null;
  }

  return toolPath.QueryInterface(Ci.nsIFile);
}


function createKeyObj(keyData) {
  if (!("validity" in keyData)) {
    keyData.validity = "u";
  }

  let keyObj = {
    keyId: keyData.keyid ? keyData.keyid : keyData.fingerprint.substr(-16),
    expiryTime: 0,
    created: "",
    keyCreated: 0,
    keyUseFor: (keyData.can_sign ? "s" : "") + (keyData.can_encrypt ? "e" : "") + (keyData.can_certify ? "c" : "") + (keyData.can_authenticate ? "a" : ""),
    ownerTrust: VALIDITY_SYMBOL[keyData.owner_trust],
    keySize: 0,
    secretAvailable: keyData.secret,
    userIds: [],
    subKeys: [],
    fpr: keyData.fingerprint,
    photoAvailable: false,
    type: "pub",
    keyTrust: keyData.disabled ? "d" : keyData.revoked ? "r" : keyData.expired ? "e" : keyData.invalid ? "i" : VALIDITY_SYMBOL[keyData.owner_trust]
  };

  if (keyData.subkeys.length > 0) {
    keyObj.created = EnigmailTime.getDateTime(keyData.subkeys[0].timestamp, true, false);
    keyObj.keyCreated = keyData.subkeys[0].timestamp;
    keyObj.expiryTime = keyData.subkeys[0].expires;
    keyObj.algoSym = keyData.subkeys[0].pubkey_algo_name;
    keyObj.keySize = keyData.subkeys[0].length;

    for (let i = 1; i < keyData.subkeys.length; i++) {
      let s = keyData.subkeys[i];
      keyObj.subKeys.push({
        keyId: s.keyid,
        expiry: EnigmailTime.getDateTime(s.expires, true, false),
        expiryTime: s.expires,
        keyTrust: s.revoked ? "r" : s.expired ? "e" : s.disabled ? "d" : s.invalid ? "i" : "f",
        keyUseFor: (s.can_sign ? "s" : "") + (s.can_encrypt ? "e" : "") + (s.can_certify ? "c" : "") + (s.can_authenticate ? "a" : ""),
        keySize: s.length,
        algoSym: s.pubkey_algo_name,
        created: EnigmailTime.getDateTime(s.timestamp, true, false),
        keyCreated: s.timestamp,
        type: "sub"
      });
    }
  }

  if (keyData.userids.length > 0) {
    keyObj.userId = keyData.userids[0].uid;

    for (let u of keyData.userids) {
      keyObj.userIds.push({
        userId: u.uid,
        keyTrust: VALIDITY_SYMBOL[u.validity],
        uidFpr: "0",
        type: "uid"
      });
    }
  }

  return keyObj;
}


function convertNativeNumber(num) {
  let s = String.fromCharCode(num & 0xFF) + String.fromCharCode((num >> 8) & 0xFF) + String.fromCharCode((num >> 16) & 0xFF) + String.fromCharCode((num >> 24) & 0xFF);
  return s;
}
