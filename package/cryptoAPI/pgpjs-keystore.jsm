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

const SIG_TYPE_REVOCATION = 0x20;

var pgpjs_keyStore = {
  /**
   * Write key(s) into the database.
   *
   * @param {String} keyData: armored or binary key data
   */
  writeKey: async function(keyData) {
    EnigmailLog.DEBUG("pgpjs-keystore.jsm: writeKey()\n");

    const PgpJS = getOpenPGPLibrary();
    let data;

    if (keyData.search(/-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----/) >= 0) {
      let blocks = getArmor().splitArmoredBlocks(keyData);

      let dataArr = [];
      let totLen = 0;

      for (let b of blocks) {
        let m = await PgpJS.armor.decode(b);
        if (m && ("data" in m)) {
          let t = await readFromStream(m.data.getReader());
          totLen += t.length;
          dataArr.push(t);
        }
      }

      data = new Uint8Array(totLen);
      let idx = 0;
      for (let i in dataArr) {
        data.set(dataArr[i], idx);
        idx += dataArr[i].length;
      }
    }
    else {
      data = stringToUint8Array(keyData);
    }

    let res = await PgpJS.key.read(data);
    let importedFpr = [];

    let conn = await keyStoreDatabase.openDatabase();
    for (let k of res.keys) {
      try {
        await keyStoreDatabase.writeKeyToDb(k, conn);
        importedFpr.push(k.getFingerprint().toUpperCase());
      }
      catch (x) {}
    }
    conn.close();
    return importedFpr;
  },

  getDatabasePath: function() {
    const DBName = "openpgpkeys.sqlite";
    let path = DBName;
    const env = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment);

    if (env.get("ENIGMAILKEYS").length > 0) {
      path = env.get("ENIGMAILKEYS");
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
        key: await PgpJS.key.readArmored(rows[i])
      });
    }
    return foundKeys;
  },

  /**
   * Initialize module
   *
   * @return {Promise<Boolean>} true if successful
   */
  init: function() {
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
    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: writeKeyToDb()\n`);
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
      let oldKey = await PgpJS.key.readArmored(rows[fpr]);
      await key.update(oldKey.keys[0]);

      let updObj = {
        fpr: fpr,
        now: now,
        data: await key.armor()
      };
      await conn.execute("update openpgpkey set keydata = :data, datm = :now where fpr = :fpr;", updObj);
    }
    else {
      // new key
      let insObj = {
        fpr: fpr,
        now: now,
        data: await key.armor()
      };
      await conn.execute("insert into openpgpkey (keydata, fpr, datm) values (:data, :fpr, :now);", insObj);
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
    await conn.execute(`select fpr, keydata from openpgpkey ${searchStr};`, null,
      function _onRow(record) {
        rows[record.getResultByName("fpr")] = record.getResultByName("keydata");
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
  EnigmailFiles.ensureWritableDirectory(dbPathObj.parent, 0o700);

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
    "keydata text not null, " + // base64-encoded key
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
