/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false */
/*global do_test_pending: false, do_test_finished: false, withTestGpgHome: false, asyncTest: false */

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js");

testing("cryptoAPI/pgpjs-decrypt.jsm");
/*global pgpjs_decrypt: false, getOpenPGPLibrary: false, pgpjs_keyStore: false, EnigmailConstants: false
 */

const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;
const EnigmailArmor = ChromeUtils.import("chrome://enigmail/content/modules/armor.jsm").EnigmailArmor;

test(withTestGpgHome(asyncTest(async function decryptMessage() {

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
    catch(ex) {}

    const encFile = do_get_file("resources/pgpMime-msg.eml", false);
    let fileData = EnigmailFiles.readFile(encFile);
    let pgpMsg = EnigmailArmor.splitArmoredBlocks(fileData)[0];

    let result = await pgpjs_decrypt.decrypt(pgpMsg, {});
    Assert.equal(result.statusFlags, EnigmailConstants.DECRYPTION_FAILED);

    const pubKeyFile = do_get_file("resources/dev-strike.sec", false);
    fileData = EnigmailFiles.readBinaryFile(pubKeyFile);

    let r = await pgpjs_keyStore.writeKey(fileData);
    Assert.equal(r.length, 1);

    result = await pgpjs_decrypt.decrypt(pgpMsg, {});
    Assert.equal(result.statusFlags, EnigmailConstants.DECRYPTION_OKAY | EnigmailConstants.GOOD_SIGNATURE);
    Assert.equal(result.exitCode, 0);
    Assert.equal(result.sigDetails, "65537E212DC19025AD38EDB2781617319CE311C4 2018-08-26 1535307422 0 4 0 1 8 00 65537E212DC19025AD38EDB2781617319CE311C4");
    Assert.equal(result.decryptedData, "This is a test\n");
    Assert.equal(result.keyId, "65537E212DC19025AD38EDB2781617319CE311C4");
    Assert.equal(result.userId, "anonymous strike <strike.devtest@gmail.com>");
  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString());
  }

})));
