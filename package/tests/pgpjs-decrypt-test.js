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

test(withTestGpgHome(asyncTest(async function testDecrypt() {
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

    const encFile = do_get_file("resources/pgpMime-msg.eml", false);
    let fileData = EnigmailFiles.readFile(encFile);
    let pgpMsg = EnigmailArmor.splitArmoredBlocks(fileData)[0];

    let result = await pgpjs_decrypt.decrypt(pgpMsg, {});
    Assert.equal(result.statusFlags, EnigmailConstants.DECRYPTION_FAILED | EnigmailConstants.NO_SECKEY);

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

    // this is a simple plain text wrapped such that it looks like a OpenPGP message
    const storedMsg = `-----BEGIN PGP MESSAGE-----

owE7rZbEEOfZI+yRmpOTr1CeX5SToscVkpFZrABEiQolqcUlCla6mlwA
=aAp2
-----END PGP MESSAGE-----`;

    result = await pgpjs_decrypt.decrypt(storedMsg, {});
    Assert.equal(result.statusFlags, 0);
    Assert.equal(result.exitCode, 0);
    Assert.equal(result.sigDetails, "");
    Assert.equal(result.decryptedData, "Hello world.\nThis is a test :-)\n");

    // this is a signed-only message
    const signedMsg = `-----BEGIN PGP MESSAGE-----

owEBbQKS/ZANAwAIAXgWFzGc4xHEAcsmYgBeSY3kSGVsbG8gd29ybGQuClRoaXMg
aXMgYSB0ZXN0IDotKQqJAjMEAAEIAB0WIQRlU34hLcGQJa047bJ4FhcxnOMRxAUC
XkmN5AAKCRB4FhcxnOMRxAicD/4jPSNH27H+G83beIyZW5UU0vzr51fHQgz+keXH
XYDpS0j7upZ2c4m5GAkc1hpdU2FMgUeksjCYhEXsIgh5RkCcacW01dr7Jw4ZgVCl
eCzuMXNWYANVE2dVt3EZb/E6G6by+T1gYn2SBfZSLnBrN6r552J9Ae65MgOKWOAV
nZ9679ys3N5BLX6cctfTc0+nE3sOmuNK3/C6cn5+FVvnTZXKBXU37Zxrs/BL46Jy
JKoxpx3yVobKw7Esef4GeAYxIEDn02mNIVXJsnr+g6YtP+gWdcuuHLyGjd/Oakuj
gbx4JmlUjUTZvoH/c40LEMtWCJ0qUUIeqEQLGYGWrfdpimc48Eli/nxxgTNrPbB3
KADtiAito4JNWoovqJA+F4MkV3qB5A6xLk5cCmZhw92PfwABoIEJY7WeoRSU8aws
2G/2QTFtOgKqwYdc15OhMP/+E4EB8sIHheaRAfhsyFq1mCMEMFFTqutu3XwaFFpp
ifNuTRIruL7nup/f5pmDD8afC2xNUe9as7L26IqRDBHuU8hwAq2t0hoo3eSLN1Ow
Av8j88klWOEH6vUiOi5gIlCNQH5CNsgBynMfz9IC8p35ExQLVnA3KxTGL3Uxmgvh
YjlIbvu0YmTlsQvYFW4JBIPNeNy+1r+7PCsSbnOtsSU32/4SnnQVN4khCM+gKTHD
j8bbyQ==
=fwVK
-----END PGP MESSAGE-----`;

    result = await pgpjs_decrypt.decrypt(signedMsg, {});
    Assert.equal(result.statusFlags, EnigmailConstants.GOOD_SIGNATURE);
    Assert.equal(result.exitCode, 0);
    Assert.equal(result.sigDetails, "65537E212DC19025AD38EDB2781617319CE311C4 2020-02-16 1581878756 0 4 0 1 8 00 65537E212DC19025AD38EDB2781617319CE311C4");
    Assert.equal(result.keyId, "65537E212DC19025AD38EDB2781617319CE311C4");
    Assert.equal(result.userId, "anonymous strike <strike.devtest@gmail.com>");
    Assert.equal(result.decryptedData, "Hello world.\nThis is a test :-)\n");

    const clearSigned = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Hello world.
This is a test :-)
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCAAdFiEEZVN+IS3BkCWtOO2yeBYXMZzjEcQFAl5JkHwACgkQeBYXMZzj
EcQbbA/9Eu9DhB+3rkRIswp+tOmyjyytlL3V++Lfla1hUpfeC3VNC9iY3Y8TwuBW
yvPzloXD1YvVoG8QZZEqGxWEli9PcLtGLUZecSmMSD5+sKm9Muj2ahxnDSM1qN0V
yOQ+IXBtfhjDM7Zz7Xxvtv8mcRkBgQ4DAkxHTXhnBjYxo0TpffDwpmqQ0YkZCjt2
PzzYy050uL7cJZU94P5ENHtKNUkjnKgfTWqefjCG15WSj19tfxG6EHOpEnPy8fwF
gW+RnnGFRP41GctKDJh3tJ2ydiGr+1XaGmOx/M5PM0RT69mmlSnjSVQC7+xnZdX4
9AL/jOyDwRK2AFOo+mCoMFTM9WhScQC5zcoDKn1uKb1WPsjH8nrWro43yJPq2w4I
Nlqhia3bNPadPzfK3/ec++pea8byjjAuLYVe7QskNUIsfdew+m8rlhy2zDzTPSlr
uB+5+AtxV8yXxh5ATmjXlU/RiK1YIKu7QzueGKNjKrAqLTX+YwVX0HH0v2SAQZoL
JGWYnspuCiOYm19OkQoZ6NQYbqadqqakvHzrbjODHrnmlq9XJzEZ5cbhf6oeO4FT
wJEP0gfdDZA1bEV78SRcjJDlfo5vuWX4W/ZlAlA9hy5OVq69DOdlcVdgj18+gy94
+SPb1y4WzJ3KARDpgsruHZ6FnAEU1clxc5pEjll/MIeYP5NW0JM=
=WyPS
-----END PGP SIGNATURE-----
`;

    result = await pgpjs_decrypt.verify(clearSigned, {});
    Assert.equal(result.statusFlags, EnigmailConstants.GOOD_SIGNATURE);
    Assert.equal(result.exitCode, 0);
    Assert.equal(result.sigDetails, "65537E212DC19025AD38EDB2781617319CE311C4 2020-02-16 1581879420 0 4 0 1 8 00 65537E212DC19025AD38EDB2781617319CE311C4");
    Assert.equal(result.keyId, "65537E212DC19025AD38EDB2781617319CE311C4");
    Assert.equal(result.userId, "anonymous strike <strike.devtest@gmail.com>");
    Assert.equal(result.decryptedData, "Hello world.\nThis is a test :-)");
  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString());
  }
})));