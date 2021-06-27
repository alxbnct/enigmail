/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false */
/*global component: false, withEnigmail: false  withTestGpgHome: false, JSUnit: false */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";


do_load_module("file://" + do_get_cwd().path + "/testHelper.js");

testing("mimeEncrypt.jsm");
/* global EnigmailMimeEncrypt: false, PgpMimeEncrypt: false
 EnigmailConstants: false, EnigmailKeyRing: false,
 EnigmailPrefs: false,
 MIME_SIGNED: false, MIME_ENCRYPTED: false */

const EnigmailFiles = component("enigmail/files.jsm").EnigmailFiles;

test(function testSignedMessage() {
  const e = new PgpMimeEncrypt(null);
  e.msgCompFields = [];
  e.hashAlgorithm = "SHA256";
  e.cryptoMode = MIME_SIGNED;
  e.sendFlags = EnigmailConstants.SEND_PGP_MIME | EnigmailConstants.SEND_SIGNED;
  e.startCryptoHeaders();

  Assert.equal(e.pipeQueue.search(/Content-Type: multipart\/mixed; boundary=\"[a-zA-Z0-9]+\"\r\n\r\n--[a-zA-Z0-9]+\r\n/), 0);
  Assert.equal(e.outQueue.search(/Content-Type: multipart\/signed; micalg=pgp-sha256;\r\n protocol=\"application\/pgp-signature\";\r\n boundary=\"[a-zA-Z0-9]+\"/), 0);
});


test(withTestGpgHome(withEnigmail(function testFinishCryptoEncapsulation() {
  const publicKey = do_get_file("resources/dev-strike.asc", false);
  const secretKey = do_get_file("resources/dev-strike.sec", false);
  const errorMsgObj = {};
  const importedKeysObj = {};
  EnigmailKeyRing.importKeyFromFile(publicKey, errorMsgObj, importedKeysObj);
  EnigmailKeyRing.importKeyFromFile(secretKey, errorMsgObj, importedKeysObj);
  const strikeAccount = "strike.devtest@gmail.com";

  const e = new PgpMimeEncrypt(null);
  e.msgCompFields = [];
  e.hashAlgorithm = "SHA256";
  e.useSmime = false;
  e.cryptoMode = MIME_ENCRYPTED;
  e.sendFlags = EnigmailConstants.SEND_PGP_MIME | EnigmailConstants.SEND_ENCRYPTED | EnigmailConstants.SEND_ALWAYS_TRUST;
  e.senderEmailAddr = strikeAccount;
  e.recipients = strikeAccount;
  e.bccRecipients = "";
  e.pipeQueue = "Hello World";
  e.win = JSUnit.createStubWindow();
  e.checkSMime = false;
  e.encapsulate = false;
  e.encHeader = null;
  e.flushOutput = function() {};

  e.finishCryptoEncapsulation(false, false);
  Assert.equal(e.encryptedData.substr(0, 27), "-----BEGIN PGP MESSAGE-----");

  Assert.ok(e.encryptedData.split(/[\r\n]+/).length >= 14);

  // test if we get an exception if encryption fails
  e.sendFlags = EnigmailConstants.SEND_PGP_MIME | EnigmailConstants.SEND_ENCRYPTED;
  try {
    e.finishCryptoEncapsulation(false, false);
    Assert.ok(false); // should not succeed because "always trust" is off
  }
  catch (ex) {
    Assert.ok(true);
  }

  // test signed message
  e.sendFlags = EnigmailConstants.SEND_PGP_MIME | EnigmailConstants.SEND_SIGNED;
  e.finishCryptoEncapsulation(false, false);
  Assert.equal(e.encryptedData.substr(0, 29), "-----BEGIN PGP SIGNATURE-----");
})));


test(withTestGpgHome(withEnigmail(function testBeginCryptoEncapsulation() {
  const secretKey = do_get_file("resources/dev-strike.sec", false);
  const errorMsgObj = {};
  const importedKeysObj = {};
  EnigmailKeyRing.importKeyFromFile(secretKey, errorMsgObj, importedKeysObj);
  const strikeAccount = "strike.devtest@gmail.com";

  const e = new PgpMimeEncrypt(null);
  e.msgCompFields = [];
  e.hashAlgorithm = "";
  e.useSmime = false;
  e.cryptoMode = MIME_ENCRYPTED;
  e.sendFlags = EnigmailConstants.SEND_PGP_MIME | EnigmailConstants.SEND_SIGNED;
  e.senderEmailAddr = strikeAccount;
  e.recipients = strikeAccount;
  e.bccRecipients = "";
  e.pipeQueue = "Hello World";
  e.win = JSUnit.createStubWindow();
  e.checkSMime = false;
  e.encapsulate = false;
  e.encHeader = null;

  e.beginCryptoEncapsulation({}, strikeAccount, {}, {}, false, false);

  Assert.ok(e.hashAlgorithm == "sha256" || e.hashAlgorithm == "sha512");
})));

test(function testWriteSecureHeaders() {
  const e = new PgpMimeEncrypt(null);
  const SUBJECT = "Some subject with umlauts like ä and é";
  e.msgCompFields = {
    from: "Sender <from@somewhere.invalid>",
    to: "Recipient <to@somewhere.invalid>"
  };
  e.getAutocryptGossip = function() {
    return "";
  };
  e.encHeader = null;
  e.cryptoMode = MIME_ENCRYPTED;
  e.originalSubject = SUBJECT;

  e.sendFlags = EnigmailConstants.SEND_PGP_MIME | EnigmailConstants.SEND_SIGNED;
  EnigmailPrefs.setPref("protectedHeadersLegacyPart", false);
  e.pipeQueue = "";
  e.writeSecureHeaders();
  Assert.equal(e.pipeQueue, `Content-Type: multipart/mixed; boundary="${e.encHeader}"\r\n\r\n--${e.encHeader}\r\n`);

  e.sendFlags = EnigmailConstants.SEND_PGP_MIME | EnigmailConstants.SEND_SIGNED;
  EnigmailPrefs.setPref("protectedHeadersLegacyPart", true);
  e.pipeQueue = "";
  e.writeSecureHeaders();
  Assert.equal(e.pipeQueue, `Content-Type: multipart/mixed; boundary="${e.encHeader}"\r\n\r\n--${e.encHeader}\r\n`);

  e.sendFlags = EnigmailConstants.SEND_PGP_MIME | EnigmailConstants.SEND_SIGNED | EnigmailConstants.ENCRYPT_HEADERS;
  EnigmailPrefs.setPref("protectedHeadersLegacyPart", false);
  e.pipeQueue = "";
  e.writeSecureHeaders();
  let expected = `Content-Type: multipart/mixed; boundary="${e.encHeader}";\r\n protected-headers="v1"\r\n` +
    `From: ${e.msgCompFields.from}\r\n` +
    `To: ${e.msgCompFields.to}\r\n` +
    `Subject: =?UTF-8?Q?Some_subject_with_umlauts_like_=c3=a4_and_=c3=a9?=\r\n\r\n` +
    `--${e.encHeader}\r\n`;
  Assert.equal(e.pipeQueue, expected);

  e.sendFlags = EnigmailConstants.SEND_PGP_MIME | EnigmailConstants.SEND_SIGNED | EnigmailConstants.ENCRYPT_HEADERS;
  EnigmailPrefs.setPref("protectedHeadersLegacyPart", true);
  e.pipeQueue = "";
  e.writeSecureHeaders();
  expected = `Content-Type: multipart/mixed; boundary="${e.encHeader}";\r\n protected-headers="v1"\r\n` +
    `From: ${e.msgCompFields.from}\r\n` +
    `To: ${e.msgCompFields.to}\r\n` +
    `Subject: =?UTF-8?Q?Some_subject_with_umlauts_like_=c3=a4_and_=c3=a9?=\r\n\r\n` +
    `--${e.encHeader}\r\n` +
    'Content-Type: text/plain; charset=utf-8; protected-headers="v1"\r\n' +
    'Content-Disposition: inline\r\n\r\n' +
    `Subject: Some subject with umlauts like Ã¤ and Ã©\r\n\r\n` +
    `--${e.encHeader}\r\n`;
  Assert.equal(e.pipeQueue, expected);

  e.originalSubject = null;
  e.sendFlags = EnigmailConstants.SEND_PGP_MIME | EnigmailConstants.SEND_SIGNED | EnigmailConstants.ENCRYPT_HEADERS;
  EnigmailPrefs.setPref("protectedHeadersLegacyPart", true);
  e.pipeQueue = "";
  e.writeSecureHeaders();
  expected = `Content-Type: multipart/mixed; boundary="${e.encHeader}";\r\n protected-headers="v1"\r\n` +
    `From: ${e.msgCompFields.from}\r\n` +
    `To: ${e.msgCompFields.to}\r\n\r\n` +
    `--${e.encHeader}\r\n`;
  Assert.equal(e.pipeQueue, expected);

  EnigmailPrefs.setPref("protectedHeadersLegacyPart", false);
});
