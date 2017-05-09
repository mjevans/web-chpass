#
# Part of the "web-chpass" package.
# https://github.com/chip-rosenthal/web-chpass
#
# Additional Changes / Tweaks
# github.com/mjevans
#
#
# Chip Rosenthal
# <chip@unicom.com>
#

##############################################################################
#
# The following defintions MUST be adjusted for your installation.
#

USR = /usr/local

#
# Minimum UID settings, to protect system accounts.  nipasswd will refuse to
# authorize or change accounts with UIDs below these thresholds.
#
# -1 to disable check (presently check is for any negative number, but -1 for forward compat)

# Minimum/Maximum user ID to authorize account (-a auth only)
AUTH_MIN_UID = -1
AUTH_MAX_UID = -1

# Minimum/Maximum user ID of account to //effect// (change password)
CHANGE_MIN_UID = -1
CHANGE_MAX_UID = -1

# : separated list of group name/IDs to allow auth / change within, : to disable

AUTH_GROUP_REQ = :
CHANGE_GROUP_REQ = :


#
# The GID your web server uses when running CGIs.  For security reasons, the
# privileged "nipasswd" will be installed with use restricted to this group.
# Debian systems use "www-data". Red Hat systems use "apache".
#
CGI_GROUP = www-data
#CGI_GROUP = apache

#
# The web-chpass support files installed in this directory.  If the
# directory does not exist, it will be created.
#
DIR_LIB = $(USR)/lib/web-chpass

#
# The chpass.cgi script installed in this directory.
#
DIR_CGI = $(USR)/lib/cgi-bin

#
# Extension (if any) to place on script installed in DIR_CGI.
#
#CGIEXT = .cgi
CGIEXT =

#
# Directory where administrative manpages go.  The nipasswd(8) man page
# will be put here.
#
DIR_MAN8 = $(USR)/man/man8

#
# PAM modules configuration directory.
#
DIR_PAMD = /etc/pam.d

#
# end of configuration settings
#
##############################################################################


CC = gcc
OPTIM = -O2 -Wall
DEFS = -DAUTH_MIN_UID=$(AUTH_MIN_UID) -DAUTH_MAX_UID=$(AUTH_MAX_UID) -DCHANGE_MIN_UID=$(CHANGE_MIN_UID) -DCHANGE_MAX_UID=$(CHANGE_MAX_UID) -D AUTH_GROUP_REQ=$(AUTH_GROUP_REQ) -DCHANGE_GROUP_REQ=$(CHANGE_GROUP_REQ)
CFLAGS = $(OPTIM) $(DEFS)
LIBS = -lpam -ldl

INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m 555
INSTALL_DATA	= $(INSTALL) -m 444

INSTALL_ALL = \
	$(DIR_LIB) \
	$(DIR_LIB)/nipasswd \
	$(DIR_LIB)/NiPasswd.pm \
	$(DIR_LIB)/chpass-cgi.pl \
	$(DIR_LIB)/chpass.tmpl \
	$(DIR_CGI)/chpass$(CGIEXT) \
	$(DIR_MAN8)/nipasswd.8 \
	$(DIR_PAMD)/nipasswd

ALL = nipasswd chpass.cgi

FILES = \
	README.md \
	CHANGES \
	INSTALL.md \
	Makefile \
	NiPasswd.pm \
	chpass-cgi.pl \
	chpass.cgi.in \
	chpass.tmpl \
	nipasswd.8 \
	nipasswd.c


all : $(FILES) $(ALL)

OBJS = nipasswd.o

nipasswd : $(OBJS)
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(LIBS)

chpass.cgi : chpass.cgi.in Makefile
	sed -e 's!%LIBDIR%!$(DIR_LIB)!g' $< >$@

clean :
	rm -f $(ALL) $(OBJS)


install : $(INSTALL_ALL)

$(DIR_LIB) :
	mkdir $@

$(DIR_LIB)/nipasswd : nipasswd
	$(INSTALL) -m 4110 -o root -g $(CGI_GROUP) $< $@

$(DIR_LIB)/NiPasswd.pm : NiPasswd.pm
	$(INSTALL_DATA) $< $@

$(DIR_LIB)/chpass.tmpl : chpass.tmpl
	@if [ -f $@ ] ; then echo "***** Preserving existing $@" ; \
	else ( set -v ; $(INSTALL_DATA) $< $@ ) ; \
	fi

$(DIR_LIB)/chpass-cgi.pl : chpass-cgi.pl
	$(INSTALL_PROG) $< $@

$(DIR_CGI)/chpass$(CGIEXT) : chpass.cgi
	$(INSTALL_PROG) $< $@

$(DIR_MAN8)/nipasswd.8 : nipasswd.8
	$(INSTALL_DATA) $< $@

#
# The "nipasswd" PAM module probably should look the same as what's used
# for "passwd".
#
$(DIR_PAMD)/nipasswd : $(DIR_PAMD)/passwd
	$(INSTALL_DATA) $< $@


