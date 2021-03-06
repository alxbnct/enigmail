/* eslint no-invalid-this: 0 */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

var EXPORTED_SYMBOLS = ["InstallGnuPG"];

/* Usage:
  InstallGnuPG.start(progressListener).

  progressListener needs to implement the following methods:
  void    onError    (errorMessage)
  boolean onWarning  (message)
  void    onProgress (event)
  void    onLoaded   (event)   // fired when instllation complete
  void    onDownloaded ()      // fired when download complete, before installation
  void    onStart    (requestObj)

  requestObj:
    abort():  cancel download

  onWarning can return true if the warning should be ignored, false otherwise

*/

var Cu = Components.utils;

Components.utils.importGlobalProperties(["XMLHttpRequest"]);
const EnigmailCompat = ChromeUtils.import("chrome://enigmail/content/modules/compat.jsm").EnigmailCompat;
const subprocess = ChromeUtils.import("chrome://enigmail/content/modules/subprocess.jsm").subprocess;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailOS = ChromeUtils.import("chrome://enigmail/content/modules/os.jsm").EnigmailOS;
const EnigmailApp = ChromeUtils.import("chrome://enigmail/content/modules/app.jsm").EnigmailApp;
const PromiseUtils = ChromeUtils.import("resource://gre/modules/PromiseUtils.jsm").PromiseUtils;
const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;
const EnigmailExecution = ChromeUtils.import("chrome://enigmail/content/modules/execution.jsm").EnigmailExecution;
const EnigmailXhrUtils = ChromeUtils.import("chrome://enigmail/content/modules/xhrUtils.jsm").EnigmailXhrUtils;

const EXEC_FILE_PERMS = 0x1C0; // 0700


const NS_LOCALFILEOUTPUTSTREAM_CONTRACTID =
  "@mozilla.org/network/file-output-stream;1";
const DIR_SERV_CONTRACTID = "@mozilla.org/file/directory_service;1";
const NS_LOCAL_FILE_CONTRACTID = "@mozilla.org/file/local;1";
const XPCOM_APPINFO = "@mozilla.org/xre/app-info;1";

const GPG_QUERY_URL = "https://www.enigmail.net/service/getGnupgDownload.svc";

function toHexString(charCode) {
  return ("0" + charCode.toString(16)).slice(-2);
}

function sanitizeFileName(str) {
  // remove shell escape, #, ! and / from string
  return str.replace(/[`/#!]/g, "");
}

function sanitizeHash(str) {
  return str.replace(/[^a-hA-H0-9]/g, "");
}


function Installer(progressListener) {
  this.progressListener = progressListener;
}

Installer.prototype = {

  installMacOs: function(deferred) {
    EnigmailLog.DEBUG("installGnuPG.jsm: installMacOs\n");

    var exitCode = -1;
    var mountPath = Cc[NS_LOCAL_FILE_CONTRACTID].createInstance(Ci.nsIFile);
    mountPath.initWithPath("/Volumes/" + this.mount);
    if (mountPath.exists()) {
      let p = mountPath.path + " ";
      let i = 1;
      mountPath.initWithPath(p + i);
      while (mountPath.exists() && i < 10) {
        ++i;
        mountPath.initWithPath(p + i);
      }
      if (mountPath.exists()) {
        throw "Error - cannot mount package";
      }
    }

    this.mountPath = mountPath;
    EnigmailLog.DEBUG("installGnuPG.jsm: installMacOs - mount Package\n");

    var cmd = Cc[NS_LOCAL_FILE_CONTRACTID].createInstance(Ci.nsIFile);
    cmd.initWithPath("/usr/bin/open");

    var args = ["-W", this.installerFile.path];

    var proc = {
      command: cmd,
      arguments: args,
      charset: null,
      done: function(result) {
        exitCode = result.exitCode;
      }
    };

    try {
      EnigmailExecution.syncProc(subprocess.call(proc).promise);
      if (exitCode) throw "Installer failed with exit code " + exitCode;
    }
    catch (ex) {
      EnigmailLog.ERROR("installGnuPG.jsm: installMacOs: subprocess.call failed with '" + ex.toString() + "'\n");
      throw ex;
    }

    EnigmailLog.DEBUG("installGnuPG.jsm: installMacOs - run installer\n");

    args = ["-W", this.mountPath.path + "/" + this.command];

    proc = {
      command: cmd,
      arguments: args,
      charset: null,
      done: function(result) {
        if (result.exitCode !== 0) {
          deferred.reject("Installer failed with exit code " + result.exitCode);
        }
        else
          deferred.resolve();
      }
    };

    try {
      subprocess.call(proc);
    }
    catch (ex) {
      EnigmailLog.ERROR("installGnuPG.jsm: installMacOs: subprocess.call failed with '" + ex.toString() + "'\n");
      throw ex;
    }
  },

  cleanupMacOs: function() {
    EnigmailLog.DEBUG("installGnuPG.jsm.cleanupMacOs: unmount package\n");

    var cmd = Cc[NS_LOCAL_FILE_CONTRACTID].createInstance(Ci.nsIFile);
    cmd.initWithPath("/usr/sbin/diskutil");
    var args = ["eject", this.mountPath.path];
    var proc = {
      command: cmd,
      arguments: args,
      charset: null,
      done: function(result) {
        if (result.exitCode) EnigmailLog.ERROR("Installer failed with exit code " + result.exitCode);
      }
    };

    try {
      EnigmailExecution.syncProc(subprocess.call(proc).promise);
    }
    catch (ex) {
      EnigmailLog.ERROR("installGnuPG.jsm.cleanupMacOs: subprocess.call failed with '" + ex.toString() + "'\n");
    }

    EnigmailLog.DEBUG("installGnuPG.jsm: cleanupMacOs - remove package\n");
    this.installerFile.remove(false);
  },

  /**
   * Create the gpg4win installer config file
   * @return nsIFile - config object file
   */
  createGpg4WinCfgFile: function() {
    EnigmailLog.DEBUG("installGnuPG.jsm: createGpg4WinCfgFile\n");

    let tmpFile = EnigmailFiles.getTempDirObj().clone();
    tmpFile.append("gpg4win.ini");
    tmpFile.createUnique(tmpFile.NORMAL_FILE_TYPE, EXEC_FILE_PERMS);

    let dataStr = "[gpg4win]\r\n";

    let cfgKeys = [
      "inst_gpgol",
      "inst_gpgex",
      "inst_kleopatra",
      "inst_gpa",
      "inst_claws_mail",
      "inst_compendium",
      "inst_desktop",
      "inst_quick_launch_bar"
    ];

    // disable optional components by default
    for (let i of cfgKeys) {
      dataStr += "  " + i + " = false\r\n";
    }

    dataStr += "  inst_start_menu = true\r\n";

    if (EnigmailFiles.writeFileContents(tmpFile, dataStr)) {
      return tmpFile;
    }

    return null;
  },

  installWindows: function(deferred) {
    EnigmailLog.DEBUG("installGnuPG.jsm: installWindows\n");

    try {
      // use runwAsync in order to get UAC approval on Windows 7 / 8 if required

      var obs = {
        QueryInterface: EnigmailCompat.generateQI(["nsIObserver"]),

        observe: function(proc, aTopic, aData) {
          EnigmailLog.DEBUG("installGnuPG.jsm: installWindows.observe: topic='" + aTopic + "' \n");

          if (aTopic == "process-finished") {
            EnigmailLog.DEBUG("installGnuPG.jsm: installWindows finished\n");
            deferred.resolve();
          }
          else if (aTopic == "process-failed") {
            deferred.reject("Installer could not be started");
          }
        }
      };

      this.gpg4WinCfgFile = this.createGpg4WinCfgFile();

      let cfgFile = EnigmailFiles.getFilePath(this.gpg4WinCfgFile);
      let params = [];

      if (cfgFile) {
        if (cfgFile.indexOf('"') >= 0) cfgFile = '"' + cfgFile + '"';
        params.push('/C=' + cfgFile);
      }

      EnigmailLog.DEBUG("installGnuPG.jsm: installWindows: executing " + this.installerFile.path + " " + params.join(" ") + "\n");
      var proc = Cc["@mozilla.org/process/util;1"].createInstance(Ci.nsIProcess);
      proc.init(this.installerFile);
      proc.runwAsync(params, params.length, obs, false);
    }
    catch (ex) {
      deferred.reject("Installer could not be started");
    }

  },

  cleanupWindows: function() {
    EnigmailLog.DEBUG("installGnuPG.jsm: cleanupWindows - remove package\n");
    this.installerFile.remove(false);
    if (this.gpg4WinCfgFile) this.gpg4WinCfgFile.remove(false);
  },

  installUnix: function() {},

  /**
   * Chech the SHA256 hash sum of this.installerFile
   */
  checkHashSum: function() {
    EnigmailLog.DEBUG("installGnuPG.jsm: checkHashSum\n");
    var istream = Components.classes["@mozilla.org/network/file-input-stream;1"]
      .createInstance(Components.interfaces.nsIFileInputStream);
    // open for reading
    istream.init(this.installerFile, 0x01, 0o444, 0);

    var ch = Components.classes["@mozilla.org/security/hash;1"]
      .createInstance(Components.interfaces.nsICryptoHash);
    ch.init(ch.SHA256);
    const PR_UINT32_MAX = 0xffffffff; // read entire file
    ch.updateFromStream(istream, PR_UINT32_MAX);
    var gotHash = ch.finish(false);

    // convert the binary hash data to a hex string.
    var hashStr = "";

    for (let i in gotHash) {
      hashStr += toHexString(gotHash.charCodeAt(i));
    }

    if (this.hash != hashStr) {
      EnigmailLog.DEBUG("installGnuPG.jsm: checkHashSum - hash sums don't match: " + hashStr + "\n");
    }
    else
      EnigmailLog.DEBUG("installGnuPG.jsm: checkHashSum - hash sum OK\n");

    return this.hash == hashStr;
  },

  getDownloadUrl: function(on) {

    return new Promise((resolve, reject) => {

      function reqListener() {
        // "this" is set by the calling XMLHttpRequest
        if (typeof(this.responseXML) == "object") {
          EnigmailLog.DEBUG("installGnuPG.jsm: getDownloadUrl.reqListener: got: " + this.responseText + "\n");
          if (!this.responseText) {
            onError({
              type: "Network"
            });
            return;
          }

          if (typeof(this.responseText) == "string") {
            EnigmailLog.DEBUG("installGnuPG.jsm: getDownloadUrl.reqListener: got: " + this.responseText + "\n");

            try {
              let doc = JSON.parse(this.responseText);
              self.url = doc.url;
              self.hash = sanitizeHash(doc.hash);
              self.command = doc.command;
              self.mount = sanitizeFileName(doc.mountPath);
              self.gpgVersion = doc.gpgVersion;
              resolve();
            }
            catch (ex) {
              EnigmailLog.DEBUG("installGnuPG.jsm: getDownloadUrl.reqListener: exception: " + ex.toString() + "\n");

              onError({
                type: "Network"
              });
            }
          }
        }
      }

      function onError(error) {
        reject("error");
        if (self.progressListener) {
          return self.progressListener.onError(error);
        }

        return false;
      }


      EnigmailLog.DEBUG("installGnuPG.jsm: getDownloadUrl: start request\n");

      let queryUrl = GPG_QUERY_URL;

      // if ENIGMAIL_GPG_DOWNLOAD_URL env variable is set, use that instead of the
      // official URL (for testing)
      let env = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment);
      if (env.get("ENIGMAIL_GPG_DOWNLOAD_URL")) {
        queryUrl = env.get("ENIGMAIL_GPG_DOWNLOAD_URL");
      }

      var self = this;

      try {
        var xulRuntime = Cc[XPCOM_APPINFO].getService(Ci.nsIXULRuntime);
        var platform = xulRuntime.XPCOMABI.toLowerCase();
        var os = EnigmailOS.getOS().toLowerCase();

        var oReq = new XMLHttpRequest();
        oReq.onload = reqListener;
        oReq.addEventListener("error",
          function(e) {
            var error = EnigmailXhrUtils.createTCPErrorFromFailedXHR(oReq);
            onError(error);
          },
          false);

        oReq.open("get", queryUrl + "?vEnigmail=" + escape(EnigmailApp.getVersion()) + "&os=" + escape(os) + "&platform=" +
          escape(platform), true);
        oReq.send();
      }
      catch (ex) {
        reject(ex);
        EnigmailLog.writeException("installGnuPG.jsm", ex);

        if (self.progressListener)
          self.progressListener.onError("installGnuPG.downloadFailed");
      }
    });
  },

  getUrlObj: function() {
    let o = {
      url: this.url,
      hash: this.hash,
      comamnd: this.command,
      mount: this.mount,
      gpgVersion: this.gpgVersion
    };

    return o;
  },

  performDownload: function() {
    EnigmailLog.DEBUG("installGnuPG.jsm: performDownload: " + this.url + "\n");

    var self = this;
    var deferred = PromiseUtils.defer();

    function onProgress(event) {

      if (event.lengthComputable) {
        var percentComplete = event.loaded / event.total;
        EnigmailLog.DEBUG("installGnuPG.jsm: performDownload: " + percentComplete * 100 + "% loaded\n");
      }
      else {
        EnigmailLog.DEBUG("installGnuPG.jsm: performDownload: got " + event.loaded + "bytes\n");
      }

      if (self.progressListener)
        self.progressListener.onProgress(event);
    }

    function onError(error) {
      deferred.reject("error");
      if (self.progressListener)
        self.progressListener.onError(error);
    }

    function onLoaded(event) {
      EnigmailLog.DEBUG("installGnuPG.jsm: performDownload: downloaded " + event.loaded + "bytes\n");

      if (self.progressListener)
        self.progressListener.onDownloaded();

      try {
        // "this" is set by the calling XMLHttpRequest
        performInstall(this.response).then(function _f() {
          performCleanup();
        });
      }
      catch (ex) {
        EnigmailLog.writeException("installGnuPG.jsm", ex);

        if (self.progressListener)
          self.progressListener.onError("installGnuPG.installFailed");
      }
    }

    function performInstall(response) {
      var arraybuffer = response; // not responseText
      EnigmailLog.DEBUG("installGnuPG.jsm: performDownload: bytes " + arraybuffer.byteLength + "\n");

      try {
        var flags = 0x02 | 0x08 | 0x20;
        var fileOutStream = Cc[NS_LOCALFILEOUTPUTSTREAM_CONTRACTID].createInstance(Ci.nsIFileOutputStream);
        self.installerFile = EnigmailFiles.getTempDirObj().clone();

        switch (EnigmailOS.getOS()) {
          case "Darwin":
            self.installerFile.append("GnuPG-Installer.dmg");
            self.performCleanup = self.cleanupMacOs;
            break;
          case "WINNT":
            self.installerFile.append("gpg4win.exe");
            self.performCleanup = self.cleanupWindows;
            break;
          default:
            self.installerFile.append("gpg-installer.bin");
            self.performCleanup = null;
        }

        self.installerFile.createUnique(self.installerFile.NORMAL_FILE_TYPE, EXEC_FILE_PERMS);

        EnigmailLog.DEBUG("installGnuPG.jsm: performDownload: writing file to " + self.installerFile.path + "\n");

        fileOutStream.init(self.installerFile, flags, EXEC_FILE_PERMS, 0);

        var binStr = Cc["@mozilla.org/binaryoutputstream;1"].createInstance(Ci.nsIBinaryOutputStream);

        binStr.setOutputStream(fileOutStream.QueryInterface(Ci.nsIOutputStream));

        var buf = new Uint8Array(arraybuffer);
        binStr.writeByteArray(buf, buf.length);
        binStr.flush();
        binStr.close();
        fileOutStream.close();

        if (!self.checkHashSum()) {
          var cont = true;
          if (self.progressListener) {
            cont = self.progressListener.onWarning("hashSumMismatch");
          }

          if (!cont) {
            deferred.reject("Aborted due to hash sum error");
            return null;
          }

        }

        switch (EnigmailOS.getOS()) {
          case "Darwin":
            self.installMacOs(deferred);
            break;
          case "WINNT":
            self.installWindows(deferred);
            break;
          default:
            self.installUnix(deferred);
        }

      }
      catch (ex) {
        deferred.reject(ex);
        EnigmailLog.writeException("installGnuPG.jsm", ex);

        if (self.progressListener)
          self.progressListener.onError("installGnuPG.installFailed");
      }

      return deferred.promise;
    }

    function performCleanup() {
      EnigmailLog.DEBUG("installGnuPG.jsm: performCleanup:\n");
      try {
        if (self.performCleanup) self.performCleanup();
      }
      catch (ex) {}

      if (self.progressListener) {
        EnigmailLog.DEBUG("installGnuPG.jsm: performCleanup - onLoaded()\n");
        self.progressListener.onLoaded();
      }
    }

    try {
      // create a  XMLHttpRequest object
      var oReq = new XMLHttpRequest();

      oReq.addEventListener("load", onLoaded, false);
      oReq.addEventListener("error",
        function(e) {
          var error = EnigmailXhrUtils.createTCPErrorFromFailedXHR(oReq);
          onError(error);
        },
        false);

      oReq.addEventListener("progress", onProgress, false);
      oReq.open("get", this.url, true);
      oReq.responseType = "arraybuffer";
      if (self.progressListener)
        self.progressListener.onStart({
          abort: function() {
            oReq.abort();
          }
        });
      oReq.send();
    }
    catch (ex) {
      deferred.reject(ex);
      EnigmailLog.writeException("installGnuPG.jsm", ex);

      if (self.progressListener)
        self.progressListener.onError("installGnuPG.downloadFailed");
    }

  }
};


var InstallGnuPG = {

  // check if there is a downloadable item for the given platform
  // returns true if item available
  checkAvailability: function() {
    switch (EnigmailOS.getOS()) {
      case "Darwin":
      case "WINNT":
        return true;
    }

    return false;
  },

  startInstaller: function(progressListener) {

    var i = new Installer(progressListener);
    i.getDownloadUrl(i).
    then(function _dl() {
      i.performDownload();
    });
    return i;
  },

  getAvailableInstaller: async function() {
    if (!this.checkAvailability()) return null;

    let i = new Installer(null);
    await i.getDownloadUrl(i);

    return i.getUrlObj();
  }
};
