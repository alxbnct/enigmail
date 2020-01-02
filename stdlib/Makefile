# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


DEPTH		= ..

include $(DEPTH)/config/autoconf.mk

GENDIR = $(DIST)/chrome/content/modules/stdlib

MODFILES = \
           compose.jsm \
           misc.jsm \
           msgHdrUtils.jsm \
           openpgp-loader.jsm \
           openpgp-lib.js \
           openpgp.worker.js \
           web-streams.jsm

GENFILES = $(addprefix $(GENDIR)/,$(MODFILES))

$(GENDIR)/%.jsm: %.jsm
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) $< $@

$(GENDIR)/%.js: %.js
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) $< $@

all: deploy

deploy: $(GENFILES)

clean:
	$(DEPTH)/util/install -u $(DIST)/chrome/content/modules/stdlib $(MODFILES)
