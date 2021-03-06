/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

var EXPORTED_SYMBOLS = ["EnigmailMsgRead"];

/**
 * Message-reading related functions
 */

const EnigmailPrefs = ChromeUtils.import("chrome://enigmail/content/modules/prefs.jsm").EnigmailPrefs;
const EnigmailApp = ChromeUtils.import("chrome://enigmail/content/modules/app.jsm").EnigmailApp;
const EnigmailVersioning = ChromeUtils.import("chrome://enigmail/content/modules/versioning.jsm").EnigmailVersioning;
const EnigmailKeyRing = ChromeUtils.import("chrome://enigmail/content/modules/keyRing.jsm").EnigmailKeyRing;
const EnigmailFuncs = ChromeUtils.import("chrome://enigmail/content/modules/funcs.jsm").EnigmailFuncs;
const EnigmailAutocrypt = ChromeUtils.import("chrome://enigmail/content/modules/autocrypt.jsm").EnigmailAutocrypt;
const EnigmailCompat = ChromeUtils.import("chrome://enigmail/content/modules/compat.jsm").EnigmailCompat;

const ExtraHeaders = ["autocrypt", "openpgp"];

var EnigmailMsgRead = {
  /**
   * Ensure that Thunderbird prepares certain headers during message reading
   */
  ensureExtraAddonHeaders: function() {
    let r = EnigmailPrefs.getPrefRoot();

    let isPlatform60 = EnigmailVersioning.greaterThanOrEqual(EnigmailApp.getPlatformVersion(), "60.0");
    let prefName = (isPlatform60 ? "mailnews.headers.extraAddonHeaders" : "mailnews.headers.extraExpandedHeaders");

    try {
      let hdr = r.getCharPref(prefName);

      if (hdr !== "*") { // do nothing if extraAddonHeaders is "*" (all headers)
        for (let h of ExtraHeaders) {
          let sr = new RegExp("\\b" + escapeRegex(h) + "\\b", "i");
          if (hdr.search(h) < 0) {
            if (hdr.length > 0) hdr += " ";
            hdr += h;
          }
        }

        r.setCharPref(prefName, hdr);
      }

      if (isPlatform60) {
        this.cleanupOldPref();
      }
    }
    catch (x) {}
  },

  /**
   * Clean up extraExpandedHeaders after upgrading to TB 59 and newer, or upon shutdown.
   */
  cleanupOldPref: function() {
    let r = EnigmailPrefs.getPrefRoot();

    let hdr = r.getCharPref("mailnews.headers.extraExpandedHeaders");
    for (let h of ExtraHeaders) {
      let sr = new RegExp("\\b" + escapeRegex(h) + "\\b", "i");
      if (hdr.search(h) >= 0) {
        hdr = hdr.replace(sr, " ");
      }
    }

    r.setCharPref("mailnews.headers.extraExpandedHeaders", hdr.trim());
  },

  /**
   * Get a mail URL from a uriSpec
   *
   * @param uriSpec: String - URI of the desired message
   *
   * @return Object: nsIURL or nsIMsgMailNewsUrl object
   */
  getUrlFromUriSpec: function(uriSpec) {
    return EnigmailCompat.getUrlFromUriSpec(uriSpec);
  },

  /**
   * Determine if an attachment is possibly signed
   */
  checkSignedAttachment: function(attachmentObj, index, currentAttachments) {
    var attachmentList;
    if (index !== null) {
      attachmentList = attachmentObj;
    }
    else {
      attachmentList = currentAttachments;
      for (let i = 0; i < attachmentList.length; i++) {
        if (attachmentList[i].url == attachmentObj.url) {
          index = i;
          break;
        }
      }
      if (index === null) return false;
    }

    var signed = false;
    var findFile;

    var attName = this.getAttachmentName(attachmentList[index]).toLowerCase().replace(/\+/g, "\\+");

    // check if filename is a signature
    if ((this.getAttachmentName(attachmentList[index]).search(/\.(sig|asc)$/i) > 0) ||
      (attachmentList[index].contentType.match(/^application\/pgp-signature/i))) {
      findFile = new RegExp(escapeRegex(attName.replace(/\.(sig|asc)$/, "")));
    }
    else if (attName.search(/\.pgp$/i) > 0) {
      findFile = new RegExp(escapeRegex(attName.replace(/\.pgp$/, "")) + "(\\.pgp)?\\.(sig|asc)$");
    }
    else {
      findFile = new RegExp(escapeRegex(attName) + "\\.(sig|asc)$");
    }

    for (let i in attachmentList) {
      if ((i != index) &&
        (this.getAttachmentName(attachmentList[i]).toLowerCase().search(findFile) === 0))
        signed = true;
    }

    return signed;
  },

  /**
   * Get the name of an attachment from the attachment object
   */
  getAttachmentName: function(attachment) {
    if ("name" in attachment) {
      // Thunderbird
      return attachment.name;
    }
    else
      // SeaMonkey
      return attachment.displayName;
  },


  /**
   * Escape text such that it can be used as HTML text
   */
  escapeTextForHTML: function(text, hyperlink) {
    // Escape special characters
    if (text.indexOf("&") > -1)
      text = text.replace(/&/g, "&amp;");

    if (text.indexOf("<") > -1)
      text = text.replace(/</g, "&lt;");

    if (text.indexOf(">") > -1)
      text = text.replace(/>/g, "&gt;");

    if (text.indexOf("\"") > -1)
      text = text.replace(/"/g, "&quot;");

    if (!hyperlink)
      return text;

    // Hyperlink email addresses (we accept at most 1024 characters before and after the @)
    var addrs = text.match(/\b[A-Za-z0-9_+.-]{1,1024}@[A-Za-z0-9.-]{1,1024}\b/g);

    var newText, offset, loc;
    if (addrs && addrs.length) {
      newText = "";
      offset = 0;

      for (var j = 0; j < addrs.length; j++) {
        var addr = addrs[j];

        loc = text.indexOf(addr, offset);
        if (loc < offset)
          break;

        if (loc > offset)
          newText += text.substr(offset, loc - offset);

        // Strip any period off the end of address
        addr = addr.replace(/[.]$/, "");

        if (!addr.length)
          continue;

        newText += "<a href=\"mailto:" + addr + "\">" + addr + "</a>";

        offset = loc + addr.length;
      }

      newText += text.substr(offset, text.length - offset);

      text = newText;
    }

    // Hyperlink URLs (we don't accept URLS or more than 1024 characters length)
    var urls = text.match(/\b(http|https|ftp):\S{1,1024}\s/g);

    if (urls && urls.length) {
      newText = "";
      offset = 0;

      for (var k = 0; k < urls.length; k++) {
        var url = urls[k];

        loc = text.indexOf(url, offset);
        if (loc < offset)
          break;

        if (loc > offset)
          newText += text.substr(offset, loc - offset);

        // Strip delimiters off the end of URL
        url = url.replace(/\s$/, "");
        url = url.replace(/([),.']|&gt;|&quot;)$/, "");

        if (!url.length)
          continue;

        newText += "<a href=\"" + url + "\">" + url + "</a>";

        offset = loc + url.length;
      }

      newText += text.substr(offset, text.length - offset);

      text = newText;
    }

    return text;
  },

  /**
   * Match the key to the sender's from address
   *
   * @param {String}  keyId:    signing key ID
   * @param {String}  fromAddr: sender's email address
   *
   * @return Promise<String>: matching email address
   */
  matchUidToSender: function(keyId, fromAddr) {
    if ((!fromAddr) || !keyId) {
      return null;
    }

    try {
      fromAddr = EnigmailFuncs.stripEmail(fromAddr).toLowerCase();
    }
    catch (ex) {}

    let keyObj = EnigmailKeyRing.getKeyById(keyId);
    if (!keyObj) return null;

    let userIdList = keyObj.userIds;

    try {
      for (let i = 0; i < userIdList.length; i++) {
        if (fromAddr == EnigmailFuncs.stripEmail(userIdList[i].userId).toLowerCase()) {
          return EnigmailFuncs.stripEmail(userIdList[i].userId);
        }
      }

      // // uid not found, try Autocrypt keystore
      // let acList = await EnigmailAutocrypt.getOpenPGPKeyForEmail([fromAddr]);
      // for (let i = 0; i < acList.length; i++) {
      //   if (acList[i].fpr == keyObj.fpr) {
      //     return fromAddr;
      //   }
      // }
    }
    catch (ex) {}
    return null;
  },

  searchQuotedPgp: function(node) {
    if (node.nodeName.toLowerCase() === "blockquote" &&
      node.textContent.indexOf("-----BEGIN PGP ") >= 0) {
      return true;
    }

    if (node.firstChild && this.searchQuotedPgp(node.firstChild)) {
      return true;
    }

    if (node.nextSibling && this.searchQuotedPgp(node.nextSibling)) {
      return true;
    }

    return false;
  },

  trimAllLines: function(txt) {
    return txt.replace(/^[ \t]+/mg, "");
  },

  onStartup: function() {
    this.ensureExtraAddonHeaders();
  },

  onShutdown: function() {
    this.cleanupOldPref();
  }
};

// Create a safe regexp from a string
function escapeRegex(str) {
  return str.replace(/[.*+\-?^${}()|[\]\\]/g, "\\$&"); // $& means the whole matched string
}
