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
const getOpenPGPLibrary = ChromeUtils.import("chrome://enigmail/content/modules/stdlib/openpgp-loader.jsm").getOpenPGPLibrary;
const EnigmailTimer = ChromeUtils.import("chrome://enigmail/content/modules/timer.jsm").EnigmailTimer;
const EnigmailOS = ChromeUtils.import("chrome://enigmail/content/modules/os.jsm").EnigmailOS;
const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;
const Sqlite = ChromeUtils.import("resource://gre/modules/Sqlite.jsm").Sqlite;
const EnigmailLazy = ChromeUtils.import("chrome://enigmail/content/modules/lazy.jsm").EnigmailLazy;
const getArmor = EnigmailLazy.loader("enigmail/armor.jsm", "EnigmailArmor");
const EnigmailTime = ChromeUtils.import("chrome://enigmail/content/modules/time.jsm").EnigmailTime;
const pgpjs_keys = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keys.jsm").pgpjs_keys;

var pgpjs_keyStore = {
  /**
   * Write key(s) into the database.
   *
   * @param {String} keyData: armored or binary key data
   *
   * @return {Promise<Array<String>>} Array of imported fpr
   */
  writeKey: async function(keyData) {
    EnigmailLog.DEBUG("pgpjs-keystore.jsm: writeKey()\n");

    const PgpJS = getOpenPGPLibrary();
    let keys = [];

    if (typeof keyData === "string") {
      if (keyData.search(/-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----/) >= 0) {
        let blocks = getArmor().splitArmoredBlocks(keyData);

        for (let b of blocks) {
          try {
            let res = await PgpJS.message.readArmored(b);
            if (res.packets.length > 0) {
              switch (res.packets[0].tag) {
                case PgpJS.enums.packet.publicKey:
                case PgpJS.enums.packet.secretKey:
                  res = await PgpJS.key.readArmored(b);
                  break;
                case PgpJS.enums.packet.signature:
                  if (res.packets[0].signatureType === PgpJS.enums.signature.key_revocation) {
                    res = await appendRevocationCert(res);
                  }
                  else {
                    res = {};
                  }
                  break;
              }
            }

            if ("keys" in res) keys = keys.concat(res.keys);
          }
          catch(x) {
            EnigmailLog.DEBUG(`pgpjs-keystore.jsm: writeKey: error while reading keys: ${x.toString()}\n`);
          }
        }
      }
      else {
        let data = stringToUint8Array(keyData);
        let res = await PgpJS.key.read(data);
        keys = res.keys;
      }
    }
    else {
      // we got a Uint8Array
      keys = (await PgpJS.key.read(keyData)).keys;
    }
    let importedFpr = [];

    let conn = await keyStoreDatabase.openDatabase();
    for (let k of keys) {
      try {
        await conn.executeTransaction(async function _trx() {
          await keyStoreDatabase.writeKeyToDb(k, conn);
        });
        importedFpr.push(k.getFingerprint().toUpperCase());
      }
      catch (x) {
        EnigmailLog.ERROR(`pgpjs-keystore.jsm: writeKey: error ${x.toString()} / ${x.stack}\n`);
      }
    }
    conn.close();
    return importedFpr;
  },

  /**
   * Modify the status of a key (enabled/disabled)
   *
   * @param {String} fpr: fingerprint of the key to change
   * @param {Boolean} enabled: if true, key status is set to "enabled", otherwise to "disabled"
   *
   * @return {Promise<Array<Object>>} found keys:
   *    object that suits as input for keyObj.contructor
   */
  setKeyStatus: async function(fpr, enabled) {
    let conn = await keyStoreDatabase.openDatabase();

    let updObj = {
      status: enabled ? 'enabled' : "disabled",
      fpr: fpr
    };

    await conn.execute("update openpgpkey set status = :status where fpr = :fpr;", updObj);
    conn.close();
  },

  /**
   * Determine the path where the key database is stored
   *
   * @return {String}: full path including file name
   */
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
   * @param {Array<String>} keyArr: [optional] Array of Fingerprints or keyIDs. If not provided, all keys are returned
   *
   * @return {Promise<Array<Object>>} found keys:
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
        status: rows[i].status,
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
   * @return {Promise<Array<Object>>} found keys:
   *    object that suits as input for keyObj.contructor
   */
  readKeyMetadata: async function(keyArr = null) {
    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: readKeyMetadata(${keyArr})\n`);

    const PgpJS = getOpenPGPLibrary();

    let rows = await keyStoreDatabase.readKeysFromDb(keyArr);

    let foundKeys = [];
    for (let i in rows) {
      let key = getKeyFromJSON(rows[i].metadata);
      if (rows[i].status === "disabled") {
        key.ownerTrust = 'd';
        key.keyTrust = 'd';
      }
      foundKeys.push(key);
    }
    return foundKeys;
  },

  readPublicKeys: async function(keyArr) {
    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: readPublicKeys(${keyArr})\n`);

    const PgpJS = getOpenPGPLibrary();

    let keyList = await this.readKeys(keyArr);
    let packets = new PgpJS.packet.List();

    for (let i in keyList) {
      let k = await keyList[i].key.toPublic();
      packets.concat(await k.toPacketlist());
    }

    return PgpJS.armor.encode(PgpJS.enums.armor.public_key, packets.write(), 0, 0);
  },


  readMinimalPubKey: async function(fpr, email) {
    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: readMinimalPubKey(${fpr})\n`);

    let keyList = await this.readKeys([fpr]);

    let ret = {
      exitCode: 0,
      keyData: "",
      errorMsg: ""
    };

    if (keyList.length > 0) {
      let k = await keyList[0].key.toPublic();
      k.toPacketlist();

      if (!email) {
        try {
          email = EnigmailFuncs.stripEmail((await k.getPrimaryUser()).user);
        }
        catch (ex) {}
      }

      let keyBlob = await pgpjs_keys.getStrippedKey(k, email);
      if (keyBlob) {
        ret.keyData = btoa(String.fromCharCode.apply(null, keyBlob));
      }
    }

    return ret;
  },

  /**
   * Export secret key(s) as ASCII armored data
   *
   * @param {String}  keyArr       Specification by fingerprint or keyID, separate mutliple keys with spaces
   * @param {Boolean} minimalKey  if true, reduce key to minimum required
   *
   * @return {Object}:
   *   - {Number} exitCode:  result code (0: OK)
   *   - {String} keyData:   ASCII armored key data material
   *   - {String} errorMsg:  error message in case exitCode !== 0
   */

  readSecretKeys: async function(keyArr, minimalKey) {
    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: readSecretKeys(${keyArr})\n`);

    const PgpJS = getOpenPGPLibrary();

    let keyList = await this.readKeys(keyArr);
    let packets = new PgpJS.packet.List();

    for (let k of keyList) {
      if (k.key.isPrivate()) {
        if (minimalKey) {
          packets.concat(await pgpjs_keys.getStrippedKey(k.key, null, true));
        }
        else {
          packets.concat(await k.key.toPacketlist());
        }
      }
    }

    return PgpJS.armor.encode(PgpJS.enums.armor.private_key, packets.write(), 0, 0);
  },

  /**
   * Delete one or more keys from the key store
   *
   * @param {Array<String>} keyArr: Array of Fingerprints
   *
   * @return undefined
   */
  deleteKeys: async function(keyArr) {
    let conn = await keyStoreDatabase.openDatabase();
    let error = null;

    try {
      await conn.executeTransaction(async function _trx() {
        return keyStoreDatabase.deleteKeysFromDb(keyArr, conn);
      });
    }
    catch (ex) {
      error = ex;
    }
    conn.close();

    if (error) throw error;
  },

  /**
   * Write a key to the database. Unlike writeKey(), this function does not merge
   * an existing key with the new key, but replaces an existing key entirely.
   *
   * @param {Object} keyObj: OpenPGP.js key object
   */
  replaceKey: async function(keyObj) {
    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: replaceKey(${keyObj.getFingerprint()})\n`);

    let error = null;
    let conn = await keyStoreDatabase.openDatabase();
    try {
      await conn.executeTransaction(async function _trx() {
        await keyStoreDatabase.deleteKeysFromDb([keyObj.getFingerprint().toUpperCase()], conn);
        await keyStoreDatabase.writeKeyToDb(keyObj, conn);
      });
    }
    catch (ex) {
      error = ex;
    }
    conn.close();

    if (error) throw error;
  },


  /**
   * Retrieve the OpenPGP.js key objects for a given set of keyIds.
   *
   * @param {Boolean} secretKeys:     if true, only return secret keys
   * @param {Array<String>} keyIdArr: keyIDs to look up. If null, then all
   *                                  secret or public keys are retrieved
   * @param {Boolean} includeDisabledPubkeys: if true, include disabled public keys (false by default)
   *                                  Note: secret keys are always returned
   *
   * @return {Array<Object>}: array of the found key objects
   */
  getKeysForKeyIds: async function(secretKeys, keyIdArr = null, includeDisabledPubkeys = false) {
    const PgpJS = getOpenPGPLibrary();
    let findKeyArr = [];

    if (secretKeys) {
      let keys = await pgpjs_keyStore.readKeyMetadata(keyIdArr);

      for (let k of keys) {
        if (k.secretAvailable) {
          findKeyArr.push(k.fpr);
        }
      }
    }
    else {
      findKeyArr = keyIdArr;
    }

    let returnArray = [];
    let keys = await pgpjs_keyStore.readKeys(findKeyArr);
    for (let k of keys) {
      if (!secretKeys) {
        if ((!includeDisabledPubkeys) && k.status === "disabled") {
          continue;
        }
        let pk = k.key.toPublic();
        pk._enigmailKeyStatus = k.status;
        returnArray.push(pk);
      }
      else {
        k.key._enigmailKeyStatus = k.status;
        returnArray.push(k.key);
      }
    }

    returnArray.toPacketlist = function() {
      let pktList = new PgpJS.packet.List();

      for (let i = 0; i < this.length; i++) {
        pktList.concat(this[i].toPacketlist());
      }

      return pktList;
    };

    return returnArray;
  },

  /**
   * Write a revocation certificate to its default location
   */
  storeRevocationCert: function(key, certificateData) {
    const fpr = key.getFingerprint().toUpperCase();

    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: storeRevocationCert(${fpr})\n`);
    let dbPathObj = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);

    let dbPath = pgpjs_keyStore.getDatabasePath();

    dbPathObj.initWithPath(dbPath);
    dbPathObj = dbPathObj.parent;
    dbPathObj.append("openpgp-revocs.d");

    EnigmailFiles.ensureWritableDirectory(dbPathObj, 0o700);
    const uid = key.users[0].userId.userid;
    dbPathObj.append(`${fpr}.rev`);

    const data = `This is a revocation certificate for the OpenPGP key:

Key ID:      ${fpr}
uid          ${uid}

A revocation certificate is a kind of "kill switch" to publicly
declare that a key shall not anymore be used.  It is not possible
to retract such a revocation certificate once it has been published.

Use it to revoke this key in case of a compromise or loss of
the secret key.

To avoid an accidental use of this file, a colon has been inserted
before the 5 dashes below.  Remove this colon with a text editor
before importing and publishing this revocation certificate.

:${certificateData}
`;

    EnigmailFiles.writeFileContents(dbPathObj, data);
  },

  /**
   * Determine the key status and return the corresponding code
   *
   * @param {Object} key: OpenPGP.js key object
   *
   * @return {String} status code
   */
  getKeyStatusCode: getKeyStatusCode,

  /**
   * Initialize module
   *
   * @return {Promise<Boolean>} true if successful
   */
  init: function() {
    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: init()\n`);
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
    let metadata;

    if (fpr in rows) {
      // merge existing key with new key data
      let oldKey = await PgpJS.key.readArmored(rows[fpr].armoredKey);
      try {
        await key.update(oldKey.keys[0]);
      }
      catch (x) {
        // if the keys can't be merged, try to update the old key with the new one
        try {
          await oldKey.keys[0].update(key);
          key = oldKey.keys[0];
        }
        catch (x) {
          // if we have a private key, keep it, otherwise use the new key
          if (oldKey.keys[0].isPrivate()) key = oldKey.keys[0];
        }
      }
      metadata = await getKeyMetadata(key);

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
      metadata = await getKeyMetadata(key);

      let insObj = {
        fpr: fpr,
        now: now,
        metadata: JSON.stringify(metadata),
        data: await key.armor()
      };
      await conn.execute("insert into openpgpkey (keydata, metadata, fpr, datm) values (:data, :metadata, :fpr, :now);", insObj);
    }

    await this.writeKeyIdsToDb(conn, metadata);

    if (!connection) {
      conn.close();
    }

    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: writeKeyToDb: wrote ${fpr}\n`);
  },

  /**
   * Read one or more keys from the database
   *
   * @param {Array<String>} keyArr: [optional] Array of Fingerprints or keyIDs. If not provided, all keys are returned
   * @param {Object} connection: [optional] database connection
   *
   * @return {Array<Key>} List of OpenPGP.js Key objects.
   */
  readKeysFromDb: async function(keyArr = null, connection = null) {
    EnigmailLog.DEBUG("pgpjs-keystore.jsm: readKeysFromDb(" + (keyArr ? keyArr.length : "null") + ")\n");

    let conn;
    let searchStr = "";

    if (connection) {
      conn = connection;
    }
    else {
      conn = await this.openDatabase();
    }

    if (keyArr !== null) {
      searchStr = "select o.fpr, o.keydata, o.metadata, o.status from openpgpkey o inner join keyid_lookup l on l.fpr = o.fpr " +
        "where l.keyid in ('-' ";

      for (let i in keyArr) {
        // make sure search string only contains A-F and 0-9
        let s = keyArr[i].replace(/^0x/, "").replace(/[^A-Fa-f0-9]/g, "").toUpperCase();
        searchStr += `, '${s}'`;
      }
      searchStr += ")";
    }
    else {
      searchStr = "select fpr, keydata, metadata, status from openpgpkey";
    }

    let rows = [];
    await conn.execute(searchStr, null,
      function _onRow(record) {
        rows[record.getResultByName("fpr")] = {
          armoredKey: record.getResultByName("keydata"),
          status: record.getResultByName("status"),
          metadata: record.getResultByName("metadata")
        };
      });

    if (!connection) {
      conn.close();
    }

    return rows;
  },

  /**
   * Fill the keyId lookup table for a given key
   *
   * @param {Object} conn: Database connection
   * @param {Object} keyMetadata: the metadata of the key that is stringified
   */
  writeKeyIdsToDb: async function(conn, keyMetadata) {
    try {
      let delObj = {
        fpr: keyMetadata.fpr
      };
      let keyIds = [];
      keyIds[keyMetadata.keyId] = 1;
      keyIds[keyMetadata.fpr] = 1;

      for (let k of keyMetadata.subKeys) {
        keyIds[k.keyId] = 1;
      }
      await conn.execute("delete from keyid_lookup where fpr = :fpr;", delObj);

      for (let k in keyIds) {
        let insObj = {
          fpr: keyMetadata.fpr,
          keyId: k
        };

        await conn.execute("insert into keyid_lookup (fpr, keyid) values(:fpr, :keyId);", insObj);
      }
    }
    catch (x) {
      EnigmailLog.DEBUG(`pgpjs-keystore.jsm: writeKeyIdsToDb: error with ${keyMetadata.fpr}: ${x.toString()}\n`);
    }
  },

  /*select o.fpr, keydata from keyid_lookup l inner join openpgpkey o on o.fpr = l.fpr
    where l.keyid = 'B6EF9CA3B9670465'; */

  /**
   * Delete one or more keys from the database
   *
   * @param {Array<String>} keyArr: Array of Fingerprints
   * @param {Object} connection: [optional] database connection
   */
  deleteKeysFromDb: async function(keyArr = [], connection = null) {
    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: deleteKeysFromDb(${keyArr})\n`);
    let conn;
    let searchStr = "";

    if (connection) {
      conn = connection;
    }
    else {
      conn = await this.openDatabase();
    }

    for (let i in keyArr) {
      // make sure search string only contains A-F and 0-9
      let s = keyArr[i].replace(/^0x/, "").replace(/[^A-Fa-f0-9]/g, "").toUpperCase();
      searchStr += `, '${s}'`;
    }

    await conn.execute(`delete from openpgpkey where fpr in ('-' ${searchStr});`, null);
    await conn.execute(`delete from keyid_lookup where fpr in ('-' ${searchStr});`, null);

    if (!connection) {
      conn.close();
    }
  },

  /**
   * Enable or disable Keys
   *
   * @param {Array<String>} keyArr: Array of Fingerprints
   * @param {Boolean} enable: true: enable key(s) / false: disable key(s)
   * @param {Object} connection: [optional] database connection
   */
  enableKeys: async function(keyArr, enable, connection = null) {
    EnigmailLog.DEBUG(`pgpjs-keystore.jsm: enableKeys(${keyArr})\n`);

    if (!keyArr || keyArr.length === 0) return;

    let conn;
    let searchStr = "";

    if (connection) {
      conn = connection;
    }
    else {
      conn = await this.openDatabase();
    }

    for (let i in keyArr) {
      // make sure search string only contains A-F and 0-9
      let s = keyArr[i].replace(/^0x/, "").replace(/[^A-Fa-f0-9]/g, "").toUpperCase();
      searchStr += `, '${s}'`;
    }

    let updateObj = {
      newStat: enable ? "enabled" : "disabled"
    };

    await conn.execute(`update openpgpkey set status = ':newStat' where fpr in ('-' ${searchStr});`, updateObj);

    if (!connection) {
      conn.close();
    }
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
  let dbPathObj = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);

  let dbPath = pgpjs_keyStore.getDatabasePath();
  EnigmailLog.DEBUG(`pgpjs-keystore.jsm: openDatabaseConn: path=${dbPath}\n`);

  dbPathObj.initWithPath(dbPath);
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

    exists = await connection.tableExists("keyid_lookup");
    EnigmailLog.DEBUG("pgpjs-keystore.jsm: keyid_lookup - success\n");
    if (!exists) {
      await createKeysIdsTable(connection);
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
    "datm text not null, " + // timestamp of last modification
    "status text not null default 'enabled'" + // status (enabled/disabled)
    ");"
  );

  EnigmailLog.DEBUG("pgpjs-keystore.jsm: createKeysTable - index\n");
  await connection.execute("create unique index openpgpkey_i1 on openpgpkey(fpr)");

  return null;
}

async function createKeysIdsTable(connection) {
  EnigmailLog.DEBUG("pgpjs-keystore.jsm: createKeysIdsTable()\n");

  await connection.execute("create table keyid_lookup (" +
    "fpr text not null, " + // fingerprint of key
    "keyid text not null " + // keyid for lokup
    ");"
  );

  EnigmailLog.DEBUG("pgpjs-keystore.jsm: createKeysTable - index\n");
  await connection.execute("create unique index keyid_i1 on keyid_lookup(keyid)");

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

  keyObj.keyTrust = await getKeyStatusCode(key);
  if (keyObj.keyTrust === "f" && keyObj.secretAvailable) keyObj.keyTrust = "u";

  let keyIsValid = (keyObj.keyTrust.search(/^[uf]$/) === 0);

  let prim = null;

  try {
    prim = (await key.getPrimaryUser()).user;
  }
  catch (ex) {
    if (key.users.length > 0) {
      prim = key.users[0];
    }
  }

  const keyUse = await getKeyFlags(key);
  keyObj.keyUseFor = (keyUse.cert ? "c" : "") +
    (keyUse.certValid ? "C" : "") +
    (keyUse.sign ? "s" : "") +
    (keyUse.signValid ? "S" : "") +
    (keyUse.enc ? "e" : "") +
    (keyUse.encValid ? "E" : "");

  keyObj.ownerTrust = (keyObj.secretAvailable ? "u" : "f");
  keyObj.algoSym = getAlgorithmDesc(key.getAlgorithmInfo().algorithm);
  keyObj.keySize = key.getAlgorithmInfo().bits;
  keyObj.fpr = key.getFingerprint().toUpperCase();
  keyObj.userId = prim ? prim.userId.userid : "n/a";
  keyObj.photoAvailable = false;

  keyObj.userIds = [];

  for (let i in key.users) {
    let trustLevel = "f";
    if (keyIsValid) {
      try {
        trustLevel = await getUserStatusCode(key.users[i], key.keyPacket);
      }
      catch (x) {}
    }
    else {
      trustLevel = keyObj.keyTrust;
    }

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
    if (keyIsValid) {
      try {
        keyTrust = await getSubKeyStatusCode(sk[i]);
        if (keyTrust === "f" && keyObj.secretAvailable) keyTrust = "u";
      }
      catch (x) {}
    }
    else {
      keyTrust = keyObj.keyTrust;
    }

    keyObj.subKeys.push({
      keyId: sk[i].getKeyId().toHex().toUpperCase(),
      expiry: EnigmailTime.getDateTime(exp, true, false),
      expiryTime: exp,
      keyTrust: keyTrust,
      // FIXME:
      keyUseFor: (sk[i].getAlgorithmInfo().algorithm.search(/sign/i) ? "s" : "") +
        (sk[i].getAlgorithmInfo().algorithm.search(/encrypt/i) ? "e" : ""),
      keySize: sk[i].getAlgorithmInfo().bits,
      algoSym: getAlgorithmDesc(sk[i].getAlgorithmInfo().algorithm),
      created: EnigmailTime.getDateTime(sk[i].getCreationTime() / 1000, true, false),
      keyCreated: sk[i].getCreationTime() / 1000,
      type: "sub"
    });
  }

  return keyObj;
}


/**
 * Parse a JSON string and create a key object. Additionally, determine if the key
 * or some subkey(s) have expired since the metadata were last updated.
 *
 * @param {String} jsonStr: JSON string to parse
 *
 * @return {Object} keyObj object
 */
function getKeyFromJSON(jsonStr) {
  let keyObj = JSON.parse(jsonStr);
  const now = new Date().getTime() / 1000;
  let keyIsValid = (keyObj.keyTrust.search(/^[uf]$/) === 0);

  if (keyIsValid) {
    // determine if key has expired
    if (keyObj.expiryTime > 0 && keyObj.expiryTime < now) {
      keyObj.keyTrust = "e";

      for (let i in keyObj.subKeys) {
        keyObj.subKeys[i].keyTrust = "e";
      }
      for (let i in keyObj.userIds) {
        keyObj.userIds[i].keyTrust = "e";
      }
    }
    else {
      // determine if a subkey has expired
      for (let i in keyObj.subKeys) {
        if (keyObj.subKeys[i].expiryTime > 0 && keyObj.subKeys[i].expiryTime < now) {
          keyObj.subKeys[i].keyTrust = "e";
        }
      }
    }
  }

  return keyObj;
}


async function appendRevocationCert(pgpMessage) {
  EnigmailLog.DEBUG("pgpjs-keystore.jsm: appendSignatureToKey()\n");

  let keyId = getFprFromArray(pgpMessage.packets[0].issuerFingerprint);

  if (!keyId) {
    keyId = pgpMessage.packets[0].issuerKeyId.toHex().toUpperCase();
  }

  let foundKeys = await pgpjs_keyStore.getKeysForKeyIds(false, [keyId]);

  if (foundKeys.length === 1) {
    return {
      keys: [await foundKeys[0].applyRevocationCertificate(pgpMessage.armor())]
    };
  }

  return null;

}


function getFprFromArray(arr) {
  const HEX_TABLE = "0123456789ABCDEF";

  if (!arr) return null;

  let hex = '';

  for (let j = 0; j < arr.length; j++) {
    hex += HEX_TABLE.charAt((arr[j] & 0xf0) >> 4) +
      HEX_TABLE.charAt((arr[j] & 0x0f));
  }

  return hex;
}


async function getKeyStatusCode(key) {
  let now = new Date();

  try {
    if (await key.isRevoked(null, null, now)) {
      return "r";
    }
    else if (!key.users.some(user => user.userId && user.selfCertifications.length)) {
      return "i";
    }
    else {
      const {
        user,
        selfCertification
      } = await key.getPrimaryUser(now, {}) || {};

      if (!user) return "i";

      // check for expiration time
      if (isDataExpired(key.keyPacket, selfCertification, now)) {
        return "e";
      }
    }
  }
  catch (x) {
    return "i";
  }

  return "f";
}

async function getUserStatusCode(user, keyPacket) {
  try {
    if (!user.selfCertifications.length) {
      return "i";
    }

    const dataToVerify = {
      userId: user.userId,
      userAttribute: user.userAttribute,
      key: keyPacket
    };

    const results = ["i"].concat(
      await Promise.all(user.selfCertifications.map(async function(selfCertification) {

        if (selfCertification.revoked || await user.isRevoked(keyPacket, selfCertification)) {
          return "r";
        }

        if (!(selfCertification.verified || await selfCertification.verify(keyPacket, dataToVerify))) {
          return "i";
        }

        if (selfCertification.isExpired()) {
          return "e";
        }

        return "f";
      })));

    return results.some(status => status === "f") ? "f" : results.pop();
  }
  catch (x) {}

  return "i";
}

async function getSubKeyStatusCode(key) {
  const dataToVerify = {
    key: null,
    bind: key.keyPacket
  };
  const now = new Date();

  // check subkey binding signatures
  const bindingSignature = getLatestSignature(key.bindingSignatures, now);

  // check binding signature is verified
  if (!(bindingSignature.verified || await bindingSignature.verify(key.keyPacket, dataToVerify))) {
    return "i";
  }

  // check binding signature is not revoked
  if (bindingSignature.revoked || await key.isRevoked(key.keyPacket, bindingSignature, null, now)) {
    return "r";
  }

  // check binding signature is not expired (ie, check for V4 expiration time)
  if (bindingSignature.isExpired(now)) {
    return "e";
  }

  return "f"; // binding signature passed all checks
}


function getLatestSignature(signatures, date = new Date()) {
  let signature = signatures[0];

  for (let i = 1; i < signatures.length; i++) {

    if (signatures[i].created >= signature.created &&
      (signatures[i].created <= date || date === null)) {
      signature = signatures[i];
    }
  }

  return signature;
}


function isDataExpired(keyPacket, signature, date = new Date()) {
  const normDate = normalizeDate(date);

  if (normDate !== null) {
    const expirationTime = getExpirationTime(keyPacket, signature);

    return !(keyPacket.created <= normDate && normDate < expirationTime) ||
      (signature && signature.isExpired(date));
  }

  return false;
}

function getExpirationTime(keyPacket, signature) {
  let expirationTime;

  // check V4 expiration time
  if (signature.keyNeverExpires === false) {
    expirationTime = keyPacket.created.getTime() + signature.keyExpirationTime * 1000;
  }

  return expirationTime ? new Date(expirationTime) : Infinity;
}

function normalizeDate(time = Date.now()) {
  return time === null ? time : new Date(Math.floor(Number(time) / 1000) * 1000);
}


async function getKeyFlags(key) {
  const PgpJS = getOpenPGPLibrary();

  const keyUse = {
    sign: 0,
    signValid: 0,
    enc: 0,
    encValid: 0,
    cert: 0,
    certValid: 0
  };

  function determineFlags(inputFlags, isVerified) {
    try {

      if (inputFlags & PgpJS.enums.keyFlags.certify_keys) ++keyUse.cert;
      if (inputFlags & PgpJS.enums.keyFlags.sign_data) ++keyUse.sign;
      if (inputFlags & PgpJS.enums.keyFlags.encrypt_communication) ++keyUse.enc;
      if (inputFlags & PgpJS.enums.keyFlags.encrypt_storage) ++keyUse.enc;
      if (isVerified) {
        if (inputFlags & PgpJS.enums.keyFlags.certify_keys) ++keyUse.certValid;
        if (inputFlags & PgpJS.enums.keyFlags.sign_data) ++keyUse.signValid;
        if (inputFlags & PgpJS.enums.keyFlags.encrypt_communication) ++keyUse.encValid;
        if (inputFlags & PgpJS.enums.keyFlags.encrypt_storage) ++keyUse.encValid;
      }
    }
    catch (x) {}
  }

  try {
    await key.verifyPrimaryKey();
    await key.verifyAllUsers();
  }
  catch (x) {}

  for (let sk of key.subKeys) {
    try {
      await sk.verify(key.primaryKey);
    }
    catch (x) {}

    for (let sig in sk.bindingSignatures) {
      for (let flg in sk.bindingSignatures[sig].keyFlags) {
        determineFlags(sk.bindingSignatures[sig].keyFlags[flg], sk.bindingSignatures[sig].verified);
      }
    }
  }

  for (let usr of key.users) {
    for (let sig in usr.selfCertifications) {
      for (let flg in usr.selfCertifications[sig].keyFlags) {
        determineFlags(usr.selfCertifications[sig].keyFlags[flg], usr.selfCertifications[sig].verified);
      }
    }
  }

  for (let sig in key.directSignatures) {
    for (let flg in key.directSignatures[sig].keyFlags) {
      determineFlags(key.directSignatures[sig].keyFlags[flg], key.directSignatures[sig].verified);
    }
  }

  return keyUse;
}


function getAlgorithmDesc(algorithm) {
  algorithm = algorithm.toUpperCase();

  if (algorithm.search(/^RSA/) === 0) {
    algorithm = "RSA";
  }

  return algorithm;
}
