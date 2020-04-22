# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

DEPTH  = ../..

include $(DEPTH)/config/autoconf.mk

GENDIR = $(DIST)/chrome/content/ui

UIFILES = \
	enigmailCommon.js \
	aboutEnigmail.html \
	aboutEnigmail.js \
	enigmailMessengerOverlay.xhtml \
	enigmailMessengerOverlay.js \
	enigmailKeySelection.xhtml \
	enigmailKeySelection.js \
	enigmailMsgBox.js \
	enigmailMsgBox.xhtml \
	setupWizard2.js \
	setupWizard2.xhtml \
	upgradeInfo.html \
	upgradeInfo.js

GENFILES = $(addprefix $(GENDIR)/,$(UIFILES))

$(GENDIR)/%.js: %.js
	$(DEPTH)/util/prepPostbox -c $(TARGET_TOOL) $< $@

$(GENDIR)/%.xul: %.xul
	$(PERL) $(DEPTH)/util/plpp.pl -i $(INCLUDE) -o $@ $<

$(GENDIR)/%.xhtml: %.xhtml
	$(PERL) $(DEPTH)/util/plpp.pl -i $(INCLUDE) -o $@ $<

$(GENDIR)/%.htm: %.htm
	$(DEPTH)/util/install -m 644 $(DIST)/chrome/content/ui $<

$(GENDIR)/%.html: %.html
	$(DEPTH)/util/install -m 644 $(DIST)/chrome/content/ui $<

all: build

build: $(GENFILES)
	
clean:
	$(DEPTH)/util/install -u $(DIST)/chrome/content/ui $(UIFILES)
