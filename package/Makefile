# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


DEPTH		= ..

include $(DEPTH)/config/autoconf.mk

GENDIR = $(DIST)/chrome/content/modules

DIRS = cryptoAPI

PREFFILES = prefs/defaultPrefs.js

MODFILES = \
           app.jsm \
           armor.jsm \
           clipboard.jsm \
           constants.jsm \
           core.jsm \
           cryptoAPI.jsm \
           data.jsm \
           dialog.jsm \
           enigmailOverlays.jsm \
           errorHandling.jsm \
           execution.jsm \
           funcs.jsm \
           files.jsm \
           key.jsm \
           keyRing.jsm \
           keyObj.jsm \
           keyUsability.jsm \
           lazy.jsm \
           locale.jsm \
           localizeHtml.jsm \
           log.jsm \
           os.jsm \
           overlays.jsm \
           passwords.jsm \
           pipeConsole.jsm \
           prefs.jsm \
           searchCallback.jsm \
           singletons.jsm \
           streams.jsm \
           system.jsm \
           compat.jsm \
           time.jsm \
           timer.jsm \
           trust.jsm \
           versioning.jsm \
           windows.jsm

DATE_FMT = +%Y%m%d-%H%M
SOURCE_DATE_EPOCH ?= $(shell date +%s)

# first try GNU /bin/date syntax; if that doesn't work, try BSD
# /bin/date syntax.  If that still fails, ignore SOURCE_DATE_EPOCH
ENIG_BUILD_DATE=$(shell TZ=UTC date $(DATE_FMT) -d "@$(SOURCE_DATE_EPOCH)" 2>/dev/null || \
                        TZ=UTC date -r "$(SOURCE_DATE_EPOCH)" $(DATE_FMT) || \
                        TZ=UTC date $(DATE_FMT) )

GENFILES = $(addprefix $(GENDIR)/,$(MODFILES))

$(GENDIR)/%.jsm: %.jsm
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) $< $@

all: dirs build deploy

build: $(GENFILES)

deploy: $(PREFFILES)
	$(DEPTH)/util/install -m 644 $(DIST)/chrome/content/preferences $(PREFFILES)
	echo '"use strict";' > $(DIST)/chrome/content/modules/buildDate.jsm
	echo 'var EXPORTED_SYMBOLS = ["EnigmailBuildDate"];' >> $(DIST)/chrome/content/modules/buildDate.jsm
	echo 'var EnigmailBuildDate = { built: "$(ENIG_BUILD_DATE)" };' >> $(DIST)/chrome/content/modules/buildDate.jsm
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) webextension.js $(DIST)/webextension.js
	$(DEPTH)/util/prepPackage $(XPI_MODULE_VERS) $(DIST)


clean:
	$(DEPTH)/util/install -u $(DIST)/chrome/content/preferences $(PREFFILES)
	$(DEPTH)/util/install -u $(DIST)/chrome/content/modules $(MODFILES)
	$(DEPTH)/util/install -u $(DIST) bootstrap.js manifest.json schema.json install.rdf chrome.manifest

.PHONY: dirs $(DIRS)

dirs: $(DIRS)

$(DIRS):
	$(MAKE) -C $@
