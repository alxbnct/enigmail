/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

"use strict";

/**
 * This module implents key storage for OpenPGP.js
 */

var EXPORTED_SYMBOLS = ["pgpjs_keyStore"];

const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailFuncs = ChromeUtils.import("chrome://enigmail/content/modules/funcs.jsm").EnigmailFuncs;
const EnigmailOpenPGP = ChromeUtils.import("chrome://enigmail/content/modules/openpgp.jsm").EnigmailOpenPGP;
const getOpenPGPLibrary = ChromeUtils.import("chrome://enigmail/content/modules/stdlib/openpgp-loader.jsm").getOpenPGPLibrary;
const EnigmailTimer = ChromeUtils.import("chrome://enigmail/content/modules/timer.jsm").EnigmailTimer;
const EnigmailOS = ChromeUtils.import("chrome://enigmail/content/modules/os.jsm").EnigmailOS;
const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;
const Sqlite = ChromeUtils.import("resource://gre/modules/Sqlite.jsm").Sqlite;
const EnigmailLazy = ChromeUtils.import("chrome://enigmail/content/modules/lazy.jsm").EnigmailLazy;
const getArmor = EnigmailLazy.loader("enigmail/armor.jsm", "EnigmailArmor");
const EnigmailTime = ChromeUtils.import("chrome://enigmail/content/modules/time.jsm").EnigmailTime;

const SIG_TYPE_REVOCATION = 0x20;

var pgpjs_keyStore = {
  /**
   * Write key(s) into the database.
   *
   * @param {String} keyData: armored or binary key data
   *
   * @return {Array<String>} Array of imported fpr
   */
  writeKey: async function(keyData) {
    EnigmailLog.DEBUG("pgpjs-keystore.jsm: writeKey()\n");

    const PgpJS = getOpenPGPLibrary();
    let keys = [];

    if (keyData.search(/-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----/) >= 0) {
      let blocks = getArmor().splitArmoredBlocks(keyData);

      for (let b of blocks) {
        let res = await PgpJS.key.readArmored(b);
        keys = keys.concat(res.keys);
      }
    }
    else {
      let data = stringToUint8Array(keyData);
      let res = await PgpJS.key.read(data);
      keys = res.keys;
    }

    let importedFpr = [];

    let conn = await keyStoreDatabase.openDatabase();
    for (let k of keys) {
      try {
        await keyStoreDatabase.writeKeyToDb(k, conn);
        importedFpr.push(k.getFingerprint().toUpperCase());
      }
      catch (x) {
        EnigmailLog.ERROR(`pgpjs-keystore.jsm: writeKey: error ${x.toString()} / ${x.stack}\n`);
      }
    }
    conn.close();
    return importedFpr;
  },

  getDatabasePath: function() {
    const DBName = "openpgpkeys.sqlite";
    let path = DBName;
    const env = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment);

    if (env.get("ENIGMAILKEYS").length > 0) {
      path = env.get("ENIGMAILKEYS") + (EnigmailOS.isWin32 ? "\\" : "/") + DBName;
    }
    else {
      if (EnigmailOS.isWin32) {
        path = env.get("APPDATA") + "\\Enigmail\\" + DBName;
      }
      else {
        path = env.get("HOME") + "/.enigmail/" + DBName;
      }
    }

    return path;
  },

  /**
   * Read one or more keys from the key store
   *
   * @param {Array<String>} keyArr: [optional] Array of Fingerprints. If not provided, all keys are returned
   *
   * @return {Array<Object>} found keys:
   *    fpr: fingerprint
   *    key: OpenPGP.js Key object
   */
  readKeys: async function(keyArr) {
    const PgpJS = getOpenPGPLibrary();

    let rows = await keyStoreDatabase.readKeysFromDb(keyArr);

    let foundKeys = [];
    for (let i in rows) {
      foundKeys.push({
        fpr: i,
        key: (await PgpJS.key.readArmored(rows[i].armoredKey)).keys[0]
      });
    }
    return foundKeys;
  },

  /**
   * Read one or more keys from the key store
   *
   * @param {Array<String>} keyArr: [optional] Array of Fingerprints. If not provided, all keys are returned
   *
   * @return {Array<Object>} found keys:
   *    object that suits as input for keyObj.contructor
   */
  readKeyMetadata: async function(keyArr) {
    const PgpJS = getOpenPGPLibrary();

    let rows = await keyStoreDatabase.readKeysFromDb(keyArr);

    let foundKeys = [];
    for (let i in rows) {
      foundKeys.push(JSON.parse(rows[i].metadata));
    }
    return foundKeys;
  },

  /**
   * Initialize module
   *
   * @return {Promise<Boolean>} true if successful
   */
  init: function() {
    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: init())\n`);
    return keyStoreDatabase.checkDatabaseStructure();
  }
};


const keyStoreDatabase = {
  openDatabase: function() {
    EnigmailLog.DEBUG("pgpjs-keystore.jsm: openDatabase()\n");
    return new Promise((resolve, reject) => {
      openDatabaseConn(resolve, reject, 100, Date.now() + 10000);
    });
  },

  checkDatabaseStructure: async function() {
    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: checkDatabaseStructure()\n`);
    let conn;
    try {
      conn = await this.openDatabase();
      await checkKeysTable(conn);
      conn.close();
      EnigmailLog.DEBUG(`pgpjs-keystore.jsm: checkDatabaseStructure - success\n`);
    }
    catch (ex) {
      EnigmailLog.ERROR(`pgpjs-keystore.jsm: checkDatabaseStructure: ERROR: ${ex}\n`);
      if (conn) {
        conn.close();
        return false;
      }
    }

    return true;
  },

  /**
   * Store a key in the database
   *
   * @param {Object} key: OpenPGP.js Key object
   * @param {Object} connection: [optional] database connection
   *
   * no return value
   */
  writeKeyToDb: async function(key, connection = null) {
    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: writeKeyToDb(${key})\n`);
    const fpr = key.getFingerprint().toUpperCase();
    const now = new Date().toJSON();
    const PgpJS = getOpenPGPLibrary();
    let conn;

    if (connection) {
      conn = connection;
    }
    else {
      conn = await this.openDatabase();
    }

    let rows = await this.readKeysFromDb([fpr], conn);

    if (fpr in rows) {
      // merge existing key with new key data
      let oldKey = await PgpJS.key.readArmored(rows[fpr].armoredKey);
      try {
        await key.update(oldKey.keys[0]);
      }
      catch(x) {
        // if the keys can't be merged, use only the new key
      }
      let metadata = await getKeyMetadata(key);

      let updObj = {
        fpr: fpr,
        now: now,
        metadata: JSON.stringify(metadata),
        data: await key.armor()
      };
      await conn.execute("update openpgpkey set keydata = :data, metadata = :metadata, datm = :now where fpr = :fpr;", updObj);
    }
    else {
      // new key
      let metadata = await getKeyMetadata(key);

      let insObj = {
        fpr: fpr,
        now: now,
        metadata: JSON.stringify(metadata),
        data: await key.armor()
      };
      await conn.execute("insert into openpgpkey (keydata, metadata, fpr, datm) values (:data, :metadata, :fpr, :now);", insObj);
    }

    if (!connection) {
      conn.close();
    }

    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: writeKeyToDb: wrote ${fpr}\n`);
  },

  /**
   * Read one or more keys from the database
   *
   * @param {Array<String>} keyArr: [optional] Array of Fingerprints. If not provided, all keys are returned
   * @param {Object} connection: [optional] database connection
   *
   * @return {Array<Key>} List of OpenPGP.js Key objects.
   */
  readKeysFromDb: async function(keyArr = null, connection = null) {
    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: readKeysFromDb(${keyArr})\n`);

    let conn;
    let searchStr = "";

    if (connection) {
      conn = connection;
    }
    else {
      conn = await this.openDatabase();
    }

    if (keyArr !== null) {
      searchStr = "where fpr in ('-' ";

      for (let i in keyArr) {
        // make sure search string only contains A-F and 0-9
        let s = keyArr[i].replace(/^0x/, "").replace(/[^A-Fa-f0-9]/g, "").toUpperCase();
        searchStr += `, '${s}'`;
      }
      searchStr += ")";
    }

    let rows = [];
    await conn.execute(`select fpr, keydata, metadata from openpgpkey ${searchStr};`, null,
      function _onRow(record) {
        rows[record.getResultByName("fpr")] = {
          armoredKey: record.getResultByName("keydata"),
          metadata: record.getResultByName("metadata")
        };
      });

    if (!connection) {
      conn.close();
    }

    return rows;
  }
};


/**
 * use a promise to open the openpgpkey database.
 *
 * it's possible that there will be an NS_ERROR_STORAGE_BUSY
 * so we're willing to retry for a little while.
 *
 * @param {function} resolve: function to call when promise succeeds
 * @param {function} reject:  function to call when promise fails
 * @param {Number}   waitms:  Integer - number of milliseconds to wait before trying again in case of NS_ERROR_STORAGE_BUSY
 * @param {Number}   maxtime: Integer - unix epoch (in milliseconds) of the point at which we should give up.
 */
async function openDatabaseConn(resolve, reject, waitms, maxtime) {
  EnigmailLog.DEBUG("pgpjs-keystore.jsm: openDatabaseConn()\n");

  let dbPath = pgpjs_keyStore.getDatabasePath();
  let dbPathObj = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
  EnigmailFiles.initPath(dbPathObj, dbPath);

  EnigmailLog.DEBUG(`pgpjs-keystore.jsm: openDatabaseConn: path=${dbPath}\n`);
  let r = EnigmailFiles.ensureWritableDirectory(dbPathObj.parent, 0o700);

  EnigmailLog.DEBUG(`pgpjs-keystore.jsm: openDatabaseConn: directory OK: ${r}\n`);

  if (r !== 0) {
    throw "Cannot write directory";
  }

  Sqlite.openConnection({
    path: dbPath,
    sharedMemoryCache: false
  }).
  then(connection => {
    resolve(connection);
  }).
  catch(error => {
    let now = Date.now();
    if (now > maxtime) {
      reject(error);
      return;
    }
    EnigmailTimer.setTimeout(function() {
      openDatabaseConn(resolve, reject, waitms, maxtime);
    }, waitms);
  });
}


/**
 * Ensure that the database structure matches the latest version
 * (table is available)
 *
 * @param connection: Object - SQLite connection
 *
 * @return {Promise<Boolean>}
 */
async function checkKeysTable(connection) {
  try {
    let exists = await connection.tableExists("openpgpkey");
    EnigmailLog.DEBUG("pgpjs-keystore.jsm: checkKeysTable - success\n");
    if (!exists) {
      await createKeysTable(connection);
    }
  }
  catch (error) {
    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: checkKeysTable - error ${error}\n`);
    throw error;
  }

  return true;
}


/**
 * Create the "autocrypt_keydata" table and the corresponding index
 *
 * @param connection: Object - SQLite connection
 *
 * @return {Promise}
 */
async function createKeysTable(connection) {
  EnigmailLog.DEBUG("pgpjs-keystore.jsm: createKeysTable()\n");

  await connection.execute("create table openpgpkey (" +
    "keydata text not null, " + // ASCII armored key
    "metadata text not null, " + // key metadata (JSON)
    "fpr text not null, " + // fingerprint of key
    "datm text not null " + // timestamp of last modification
    ");"
  );

  EnigmailLog.DEBUG("pgpjs-keystore.jsm: createKeysTable - index\n");
  await connection.execute("create unique index openpgpkey_i1 on openpgpkey(fpr)");

  return null;
}


/**
 * Read data from a stream and return a Uint8Array
 *
 * @param {ReadableStream} s: the stream from where to read data
 *
 * @return {Promise<Uint8Array>} the data
 */

function readFromStream(s) {
  return new Promise((resolve, reject) => {
    let result = new Uint8Array();

    function processText({
      done,
      value
    }) {
      // Result objects contain two properties:
      // done  - true if the stream has already given you all its data.
      // value - some data. Always undefined when done is true.
      if (done) {
        resolve(result);
        return null;
      }

      // value for fetching stream data is a Uint8Array

      let tmpArr = new Uint8Array(result.length + value.length);
      tmpArr.set(result);
      tmpArr.set(value, result.length);
      result = tmpArr;

      // Read some more, and call this function again
      return s.read().then(processText);
    }

    s.read().then(processText);
  });
}

function stringToUint8Array(str) {
  return Uint8Array.from(Array.from(str).map(x => {
    return x.charCodeAt(0);
  }));
}


/**
 * Create a keyObj object as specified in EnigmailKeyObj.constructor
 *
 * @param {Object} key: OpenPGP.js key
 *
 * @return {Promise<keyObj>}
 */
async function getKeyMetadata(key) {
  let keyObj = {};
  let uatNum = 0;
  const now = new Date().getTime() / 1000;

  keyObj.keyId = key.getKeyId().toHex().toUpperCase();
  keyObj.secretAvailable = key.isPrivate();

  try {
    keyObj.expiryTime = (await key.getExpirationTime()).getTime() / 1000;
  }
  catch (x) {
    keyObj.expiryTime = 0;
  }

  keyObj.keyCreated = key.getCreationTime().getTime() / 1000;
  keyObj.created = EnigmailTime.getDateTime(keyObj.keyCreated, true, false);
  keyObj.type = "pub";
  let keyStatusNum = await key.verifyPrimaryKey();

  keyObj.keyTrust = getKeyStatus(keyStatusNum, keyObj.secretAvailable);

  let sig = await key.getSigningKey();
  let enc = await key.getEncryptionKey();
  let prim = null;

  try {
    prim = (await key.getPrimaryUser()).user;
  }
  catch (ex) {
    if (key.users.length > 0) {
      prim = key.users[0];
    }
  }

  keyObj.keyUseFor = "C" + (sig ? "S" : "") + (enc ? "E" : "");
  keyObj.ownerTrust = (keyObj.secretAvailable ? "u" : "f");
  keyObj.algoSym = key.getAlgorithmInfo().algorithm.toUpperCase();
  keyObj.keySize = key.getAlgorithmInfo().bits;
  keyObj.fpr = key.getFingerprint().toUpperCase();
  keyObj.userId = prim ? prim.userId.userid : "n/a";
  keyObj.photoAvailable = false;

  keyObj.userIds = [];

  for (let i in key.users) {
    let trustLevel = "f";
    try {
      trustLevel = getKeyStatus(await key.users[i].verify());
    }
    catch(x) {}

    if (key.users[i].userAttribute !== null) {
      keyObj.photoAvailable = true;
      keyObj.userIds.push({
        userId: "JPEG",
        keyTrust: trustLevel,
        uidFpr: "",
        type: "uat",
        uatNum: uatNum
      });
      ++uatNum;
    }
    else {
      keyObj.userIds.push({
        userId: key.users[i].userId.userid,
        keyTrust: trustLevel,
        uidFpr: "",
        type: "uid"
      });
    }
  }

  keyObj.subKeys = [];

  let sk = key.getSubkeys();
  for (let i in sk) {
    let exp = 0;
    try {
      exp = (await sk[i].getExpirationTime()).getTime() / 1000;
    }
    catch (x) {}

    let keyTrust = "f";
    try {
      keyTrust = getKeyStatus(await sk[i].verify(), keyObj.secretAvailable);
    }
    catch(x) {}

    keyObj.subKeys.push({
      keyId: sk[i].getKeyId().toHex().toUpperCase(),
      expiry: EnigmailTime.getDateTime(exp, true, false),
      expiryTime: exp,
      keyTrust: keyTrust,
      keyUseFor: (sk[i].getAlgorithmInfo().algorithm.search(/sign/) ? "S" : "") +
        (sk[i].getAlgorithmInfo().algorithm.search(/encrypt/) ? "E" : ""),
      keySize: sk[i].getAlgorithmInfo().bits,
      algoSym: sk[i].getAlgorithmInfo().algorithm.toUpperCase(),
      created: EnigmailTime.getDateTime(sk[i].getCreationTime() / 1000, true, false),
      keyCreated: sk[i].getCreationTime() / 1000,
      type: "sub"
    });
  }

  return keyObj;
}


function getKeyStatus(statusId, isPrivateKey) {
  const PgpJS = getOpenPGPLibrary();

  for (let i in PgpJS.enums.keyStatus) {
    if (statusId === PgpJS.enums.keyStatus[i]) {
      switch(i) {
        case "invalid":
        case "no_self_cert":
          return "i";
        case "expired":
          return "e";
        case "revoked":
          return "r";
        case "valid":
          return (isPrivateKey ? "u" : "f");
      }
    }
  }

  return "?";
}
