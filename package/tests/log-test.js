/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false, JSUnit: false, do_test_pending: false, do_get_tmp_dir: false, component: false */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js");

testing("log.jsm"); /*global EnigmailLog: false, EnigmailFiles: false */

test(function shouldCreateLogFile() {
  EnigmailLog.setLogDirectory(do_get_tmp_dir().path);
  EnigmailLog.setLogLevel(5);
  EnigmailLog.createLogFiles();
  const filePath = EnigmailLog.directory + "enigdbug.txt";
  const localFile = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
  EnigmailFiles.initPath(localFile, filePath);
  try {
    Assert.equal(localFile.exists(), true);
  } finally {
    EnigmailLog.onShutdown();
    if (localFile.exists()) {
      localFile.remove(false);
    }
    EnigmailLog.createLogFiles();
  }
});
