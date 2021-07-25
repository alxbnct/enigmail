/* global Assert: false, do_get_file: false, do_print: false, do_get_cwd: false */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */


/**
 * This file tests the implementation of subprocess.jsm
 */

const subprocess = ChromeUtils.import("chrome://enigmail/content/modules/subprocess.jsm").subprocess;

var gTestLines;
var gResultData;
var gResultStdErr;
var gInspector = Cc["@mozilla.org/jsinspector;1"].createInstance(Ci.nsIJSInspector);

function sync(promise) {
  let res = null,
    isError = false;
  promise.then(gotResult => {
    res = gotResult;
    gInspector.exitNestedEventLoop();
  }).catch(gotResult => {
    res = gotResult;
    isError = true;
    gInspector.exitNestedEventLoop();
  });

  gInspector.enterNestedEventLoop(0);

  if (isError) {
    throw res;
  }
  return res;
}

function run_test() {
  try {
    var isWindows = ("@mozilla.org/windows-registry-key;1" in Components.classes);
    var dataFile = do_get_file("ipc-data.txt", true);

    var env = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment);

    var plPath = env.get("PL_PATH");
    Assert.ok(plPath.length > 0, "PL_PATH length is > 0");
    if (plPath.length === 0) throw "perl path undefined";

    var pl = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
    pl.initWithPath(plPath);
    if (!pl.exists())
      throw "Could not locate the perl executable";

    var processDir = do_get_cwd();
    var cmd = processDir.clone();
    cmd.append("IpcCat.pl");


    if (!cmd.exists())
      throw "Could not locate the IpcCat.pl helper executable";

    var dirSvc = Cc["@mozilla.org/file/directory_service;1"].
    getService(Ci.nsIProperties).
    QueryInterface(Ci.nsIDirectoryService);
    var greDir = dirSvc.get("GreD", Ci.nsIFile);


    var envList = [
      "DYLD_LIBRARY_PATH=" + greDir.path, // for Mac
      "LD_LIBRARY_PATH=" + greDir.path // for Linux
    ];

    var eol = isWindows ? "\r\n" : "\n";
    gTestLines = ["Writing example data" + eol,
      "Writing something more" + eol,
      "And yet some more text" + eol
    ];


    /////////////////////////////////////////////////////////////////
    // Test standard scenario
    /////////////////////////////////////////////////////////////////

    do_print("Standard scenario");

    gResultData = "";
    gResultStdErr = "";
    var p = subprocess.call({
      command: pl,
      arguments: [cmd.path, 'dump'],
      environment: envList,
      stdin: function(pipe) {
        for (var i = 0; i < gTestLines.length; i++) {
          pipe.write(gTestLines[i]);
        }
        pipe.close();
        pipe.close(); // even if errorneous, this should simply succeed
      },
      stdout: function(data) {
        gResultData += data;
      },
      stderr: function(data) {
        gResultStdErr += data;
      },
      done: function(result) {
        if (result.exitCode === 255) result.exitCode = 0;
        Assert.equal(0, result.exitCode, "exit code");
      },
      mergeStderr: false
    });

    let r = sync(p.promise);
    Assert.ok(r === 0 || r === 255, "exit code");

    Assert.equal(
      gTestLines.join(""),
      gResultData,
      "result matching"
    );

    let len = gTestLines.join("").replace(/\r\n/g, "\n").length;
    Assert.equal(
      "Starting dump\nDumped " + len + " bytes\n",
      gResultStdErr.replace(/\r\n/g, "\n"),
      "stderr result matching"
    );


    /////////////////////////////////////////////////////////////////
    // Test mergeStderr=true & stdin as string
    /////////////////////////////////////////////////////////////////

    do_print("mergeStderr=true & stdin as string");

    gResultData = "";
    p = subprocess.call({
      command: pl,
      arguments: [cmd.path, 'dump'],
      environment: envList,
      stdin: gTestLines.join(""),
      stdout: function(data) {
        gResultData += data;
      },
      stderr: function(data) {
        Assert.ok(false, "Got unexpected data '" + data + "' on stderr\n");
      },
      done: function(result) {
        if (result.exitCode === 255) result.exitCode = 0;
        Assert.equal(0, result.exitCode, "exit code");
      },
      mergeStderr: true
    });

    sync(p.promise);
    Assert.equal(gTestLines.join("").replace(/\r\n/g, "\n").length + 30, gResultData.replace(/\r\n/g, "\n").length, "comparing result");


    /////////////////////////////////////////////////////////////////
    // Test with workdir & no stderr
    /////////////////////////////////////////////////////////////////

    do_print("workdir & no stderr");

    gResultData = "";
    p = subprocess.call({
      command: pl,
      arguments: [cmd.path, 'dump'],
      environment: envList,
      workdir: do_get_file(".", true).path,
      stdin: function(pipe) {
        for (var i = 0; i < gTestLines.length; i++) {
          pipe.write(gTestLines[i]);
        }
        pipe.close();
      },
      done: function(result) {
        gResultData = result.stdout;
        if (result.exitCode === 255) result.exitCode = 0;
        Assert.equal(0, result.exitCode, "exit code");
      },
      mergeStderr: false
    });

    sync(p.promise);

    Assert.equal(gTestLines.join(""), gResultData, "comparing result");

    /////////////////////////////////////////////////////////////////
    // Test exit code != 0
    /////////////////////////////////////////////////////////////////

    gResultData = "";
    gResultStdErr = "";
    p = subprocess.call({
      command: pl,
      arguments: [cmd.path, 'wrong', 'arguments'],
      environment: envList,
      stdin: "Dummy text",
      stdout: function(data) {
        gResultData += data;
      },
      stderr: function(data) {
        gResultStdErr += data;
      },
      done: function(result) {},
      mergeStderr: false
    });

    sync(p.promise);
    Assert.equal("", gResultData, "comapring result");
    gResultStdErr = gResultStdErr.replace(/\r\n/g, "\n");
    Assert.equal(18, gResultStdErr.length, "check error message");

    /////////////////////////////////////////////////////////////////
    // Test minimal scenario with stdout only
    /////////////////////////////////////////////////////////////////

    do_print("minimal scenario with stdin and stdout separately");

    gResultData = "";
    gResultStdErr = "";
    p = subprocess.call({
      command: pl,
      environment: envList,
      arguments: [cmd.path, 'write', dataFile.path],
      stdin: gTestLines.join("")
    });

    try {
      sync(p.promise);
    }
    catch (x) {}

    p = subprocess.call({
      command: pl,
      arguments: [cmd.path, 'read', dataFile.path],
      environment: envList,
      stdin: "",
      stdout: function(data) {
        gResultData += data;
      }
    });

    try {
      sync(p.promise);
    }
    catch (x) {}
    Assert.equal(gTestLines.join(""), gResultData, "read file");

    /////////////////////////////////////////////////////////////////
    // Test minimal scenario with done only
    /////////////////////////////////////////////////////////////////

    do_print("minimal scenario with done only");

    gResultData = "";
    gResultData = "";
    p = subprocess.call({
      command: pl,
      charset: null,
      arguments: [cmd.path, 'read', dataFile.path],
      environment: envList,
      done: function(result) {
        gResultData = result.stdout;
        gResultStdErr = result.stderr.replace(/\r\n/g, "\n");

        if (result.exitCode === 255) result.exitCode = 0;
        Assert.equal(0, result.exitCode, "exit code");
        Assert.equal(gTestLines.join(""), gResultData, "stdout");
        Assert.equal(gResultStdErr.length, 28, "stderr");
      }
    });

    sync(p.promise);

    /////////////////////////////////////////////////////////////////
    // Test environment variables
    /////////////////////////////////////////////////////////////////

    do_print("environment variables");

    gTestLines = ["This is a test variable"];
    envList.push("TESTVAR=" + gTestLines[0]);

    gResultData = "";
    p = subprocess.call({
      command: pl.path,
      arguments: [cmd.path, 'getenv', 'TESTVAR'],
      workdir: do_get_file(".", true).path,
      environment: envList,
      done: function(result) {
        gResultData = result.stdout;
        if (result.exitCode === 255) result.exitCode = 0;
        Assert.equal(0, result.exitCode, "exit code");
      },
      mergeStderr: false
    });

    sync(p.promise);
    Assert.equal(gTestLines.join(""), gResultData, "variable comparison");

    /////////////////////////////////////////////////////////////////
    // Test caesar cipher
    /////////////////////////////////////////////////////////////////

    do_print("caesar cipher on stdin/stdout");

    gResultData = "";
    try {
      p = subprocess.call({
        command: pl.path,
        arguments: [cmd.path, 'caesar', '0', '1'],
        environment: envList,
        stdin: 'monkey',
        stdout: function(data) {
          gResultData += data;
        },
        done: function(result) {
          if (result.exitCode === 255) result.exitCode = 0;
          Assert.equal(0, result.exitCode, "exit code");
          Assert.equal("zbaxrl", gResultData, "transformed data");
        },
        mergeStderr: false
      });
    }
    catch (ex) {
      Assert.ok(false, "error: " + ex);
    }

    sync(p.promise);


    /////////////////////////////////////////////////////////////////
    // Test many subsequent runs
    /////////////////////////////////////////////////////////////////

    do_print("mass test");

    for (let i = 0; i < 1000; i++) {
      p = subprocess.call({
        command: pl.path,
        arguments: [cmd.path, 'quick'],
        environment: envList,
        done: function(result) {
          Assert.equal("Hello\n", result.stdout.replace(/\r\n/g, "\n"), "stdout text");
          if (result.exitCode === 255) result.exitCode = 0;
          Assert.equal(0, result.exitCode, "exit code");
        },
        mergeStderr: false
      });

      sync(p.promise);
    }

    dataFile.remove(false);
  }
  catch (ex) {
    Assert.ok(false, "Runtime Error: " + ex.message + "\n" + ex.stack);
  }
}
