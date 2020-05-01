# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

DEPTH  = ../..

include $(DEPTH)/config/autoconf.mk

UIFILES = \
	images/check0.png \
	images/check1.png \
	images/check2.png

SKIN = \
	common/enigmail.css \
	common/enigmail-common.css \
	common/enigmail-html.css \
	images/enigmail-logo.png \
	images/ok-sign.svg \
	images/spinning-wheel.png


all: deploy

deploy: $(UIFILES) $(SKIN) 
	$(DEPTH)/util/install -m 644 $(DIST)/chrome/content/ui $(UIFILES)
	$(DEPTH)/util/install -m 644 $(DIST)/chrome/content/skin $(SKIN)
