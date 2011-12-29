#
#       System: Structured text retrieval tool sgrep.
#       Module: Makefile
#       Author: Pekka Kilpeläinen & Jani Jaakkola
#       Description: Makefile for building & installing sgrep
#       Version history: Original version February 1995 by JJ & PK
#       Copyright: University of Helsinki, Dept. of Computer Science

EXTRA_DIST = sgrep.1 sgrep.lsm sample.sgreprc

DOC_DIST = README AUTHORS COPYING ChangeLog INSTALL NEWS

EDITOR_FILES = $(SOURCES) Makefile.am configure.in ChangeLog NEWS README \
	acconfig.in

# Sgrep needs to know its share directory
INCLUDES = -DDATADIR="\"${datadir}\""

bin_PROGRAMS = sgrep
libsgrep_SOURCES = main.c preproc.c common.c parser.c optimize.c pmatch.c \
	sgml.c eval.c output.c index.c sysdeps.c sgrep.h sysdeps.h
sgrep_SOURCES =  $(libsgrep_SOURCES) index_main.c
	
data_DATA=sample.sgreprc
man_MANS=sgrep.1

# The rest of this file is my private stuff

BIN_DIST = $(DOC_DIST) $(EXTRA_DIST)
WIN_BINS = sgrep.exe cygwinb19.dll m4.exe
BUILD_SYSTEMS = hydra sirppi karhu pneuma

# Some cool rules, which you really should not try at home

windist:
	rm -f sgrep-$(VERSION).zip
	zip -l sgrep-$(VERSION).zip $(BIN_DIST)
	cd win32; zip ../sgrep-$(VERSION).zip $(WIN_BINS)
	chmod a+r sgrep-$(VERSION).zip

bindist: $(bin_PROGRAMS)
	-rm -rf $(distdir)
	mkdir $(distdir)
	-chmod 777 $(distdir)
	for file in $(BIN_DIST); do \
		d=$(srcdir); \
		test -f $(distdir)/$$file \
		|| ln $$d/$$file $(distdir)/$$file 2> /dev/null \
		|| cp -p $$d/$$file $(distdir)/$$file; \
	done
	for file  in $(bin_PROGRAMS); do \
		d=$(top_builddir); \
		test -f $(distdir)/$$file \
		|| ln $$d/$$file $(distdir)/$$file 2> /dev/null \
		|| cp -p $$d/$$file $(distdir)/$$file; \
	done
	$(TAR) cf - $(distdir) | gzip > $(distdir)-`uname -m | sed 's/\//-/g'`-`uname -s`.tar.gz
	-chmod a+r $(distdir)-`uname -m | sed 's/\//-/g'`-`uname -s`.tar.gz
	-rm -rf $(distdir)

update-build-directory: dist
	cat $(distdir).tar.gz | ssh melkki "tee $(distdir).tar.gz | tar zvxf -"

CONFIGURE_OPTIONS = CC=cc; CFLAGS=-O2; export CC; export CFLAGS

build-all-binaries: 
	for i in $(BUILD_SYSTEMS); do \
		( ssh $$i "cd $(distdir) && mkdir $$i; cd $$i && \
		sh -c '$(CONFIGURE_OPTIONS); ../configure' && \
		make" ) & \
		done; for i in $(BUILD_SYSTEMS); do wait; done

clean-all-binaries:
	ssh melkki "for i in $(BUILD_SYSTEMS);do rm -rf $(distdir)/"'$$i'"; done"

RELEASE_DIR= /home/ftp/pub/Software/Local/Sgrep

release: dist
	scp $(distdir).tar.gz melkki:$(RELEASE_DIR)

release-binary: bindist
	scp $(distdir)-`uname -m | sed 's/\//-/g'`-`uname -s`.tar.gz melkki.cs:$(RELEASE_DIR)

release-winbinary: windist
	scp $(distdir).zip melkki:$(RELEASE_DIR)

release-all-binaries:
	for i in $(BUILD_SYSTEMS); do \
		ssh $$i "cd $(distdir)/$$i && make bindist"; \
	done
	for i in $(BUILD_SYSTEMS); do \
		ssh melkki.cs "cp $(distdir)/$$i/sgrep-*.tar.gz $(RELEASE_DIR)"; \
	done

edit:
	xemacs $(EDITOR_FILES) &

# Sometimes while editing and compiling Win32-version of sgrep, the
# files get littered by unintentional and ugly carriage returns.
unixify:
	for i in $(DISTFILES); do sed `printf "s/\r//g"` < $$i > tmpfile; mv tmpfile $$i; done

# These hook exists for building the commercial part of sgrep, 
# the sgrep-library. It is not distributed under GPL and is not
# available for downloading.

libdist: Makefile.lib
	$(MAKE) -f Makefile.lib VERSION="$(VERSION)" dist

libclean: Makefile.lib
	$(MAKE) -f Makefile.lib clean

library: $(SGREP_OBJECTS)
	@if test -f $(srcdir)/Makefile.lib ; then $(MAKE) -f $(srcdir)/Makefile.lib DEFS='$(DEFS)'; fi

all-local: #library

clean-local:
	@if test -f $(srcdir)/Makefile.lib ; then $(MAKE) -f $(srcdir)/Makefile.lib clean; fi

distclean-local: clean-local
maintainer-clean-local: clean-local

