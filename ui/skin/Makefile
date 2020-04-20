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
	tb-aero/enigmail.css \
	common/enigmail-common.css \
	common/enigmail-pEp.css \
	common/enigmail-html.css \
	images/enigmail-about.svg \
	images/enigmail-logo.png \
	images/ok-sign.svg \
	tb-windows/images/enigEncInactive.png \
	tb-windows/images/enigEncNotOk.png \
	tb-windows/images/enigEncOk.png \
	tb-windows/images/enigSignInactive.png \
	tb-windows/images/enigSignNotOk.png \
	tb-windows/images/enigSignOk.png \
	tb-windows/images/enigSignUnkown.png \
	images/importSuccess.png \
	images/twisty-open.png \
	images/twisty-clsd.png \
	images/spinning-wheel.png \
	tb-windows/images/col-encrypted-signed.png \
	tb-windows/images/enigSignActiveNone.png \
	tb-windows/images/enigSignActivePlus.png \
	tb-windows/images/enigSignActiveMinus.png \
	tb-windows/images/enigSignActiveConflict.png \
	tb-windows/images/enigSignInactiveNone.png \
	tb-windows/images/enigSignInactivePlus.png \
	tb-windows/images/enigSignInactiveMinus.png \
	tb-windows/images/enigSignInactiveConflict.png \
	tb-windows/images/enigSignForceYes.png \
	tb-windows/images/enigSignForceNo.png \
	tb-windows/images/enigEncActiveNone.png \
	tb-windows/images/enigEncActivePlus.png \
	tb-windows/images/enigEncActiveMinus.png \
	tb-windows/images/enigEncActiveConflict.png \
	tb-windows/images/enigEncInactiveNone.png \
	tb-windows/images/enigEncInactivePlus.png \
	tb-windows/images/enigEncInactiveMinus.png \
	tb-windows/images/enigEncInactiveConflict.png \
	tb-windows/images/enigEncForceYes.png \
	tb-windows/images/enigEncForceNo.png \
	images/decrypt-inactive-18.svg \
	images/decrypt-active-18.svg \
	images/encrypt-inactive-18.svg \
	images/encrypt-active-18.svg \
	images/encrypt-disabled-18.svg \
	images/sign-active-18.svg \
	images/sign-disabled-18.svg \
	images/sign-inactive-18.svg \
	images/attach-active-18.svg \
	images/attach-disabled-18.svg \
	images/attach-inactive-18.svg \
	images/password-error.svg \
	images/warning-16.png \
	images/col-pEpGreen.svg \
	images/col-pEpYellow.svg \
	images/col-pEpRed.svg \
	images/pEpGreen.svg \
	images/pEpGrey.svg \
	images/pEpYellow.svg \
	images/pEpRed.svg \
	images/pEpEncryptActive.svg \
	images/pEpEncryptInactive.svg \
	images/pEpLogo.svg \
	images/headerProtected-18.svg \
	images/headerUnprotected-18.svg


all: deploy

deploy: $(UIFILES) $(SKIN) 
	$(DEPTH)/util/install -m 644 $(DIST)/chrome/content/ui $(UIFILES)
	$(DEPTH)/util/install -m 644 $(DIST)/chrome/content/skin $(SKIN)
