/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false */
/*global do_test_pending: false, do_test_finished: false, withTestGpgHome: false, asyncTest: false */

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js");

testing("cryptoAPI/pgpjs-keymanipulation.jsm");
/*global pgpjs_keymanipulation: false, getOpenPGPLibrary: false, pgpjs_keyStore: false, EnigmailConstants: false,
    EnigmailFiles: false
 */

test(withTestGpgHome(asyncTest(async function testGenRevokeCert() {
  try {
    await pgpjs_keyStore.init();

    // set password to decrypt key
    const pm = Cc["@mozilla.org/login-manager;1"].getService(Ci.nsILoginManager);
    const queryString = 'enigmail://65537E212DC19025AD38EDB2781617319CE311C4';
    const passwd = "STRIKEfreedom@Qu1to";

    const nsLoginInfo = new Components.Constructor(
      "@mozilla.org/login-manager/loginInfo;1",
      Ci.nsILoginInfo,
      "init"
    );

    let loginInfo = new nsLoginInfo(queryString, null, "OpenPGPKey", "", passwd, "", "");
    try {
      pm.addLogin(loginInfo);
    }
    catch (ex) {}

    const pubKeyFile = do_get_file("resources/dev-strike.sec", false);
    let fileData = EnigmailFiles.readBinaryFile(pubKeyFile);

    let r = await pgpjs_keyStore.writeKey(fileData);
    Assert.equal(r.length, 1);

    let keys = await pgpjs_keyStore.readKeys(["0x65537E212DC19025AD38EDB2781617319CE311C4"]);
    Assert.ok(!(await keys[0].key.isRevoked()), "Key is not revoked");

    const revFile = EnigmailFiles.getTempDirObj();
    revFile.append("key.rev");
    revFile.createUnique(Ci.nsIFile.NORMAL_FILE_TYPE, 0o600);

    r = await pgpjs_keymanipulation.genRevokeCert(null, "0x65537E212DC19025AD38EDB2781617319CE311C4", revFile, "0", "");
    Assert.equal(r.resultCode, 0);

    let revCert = EnigmailFiles.readFile(revFile);
    Assert.ok(revCert.search(/^-----BEGIN PGP PUBLIC KEY BLOCK-----$/m) >= 0);
    r = await pgpjs_keyStore.writeKey(revCert);

    Assert.equal(r.length, 1);

    keys = await pgpjs_keyStore.readKeys(["0x65537E212DC19025AD38EDB2781617319CE311C4"]);
    Assert.ok(await keys[0].key.isRevoked(), "Key is revoked");
  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString());
  }
})));
