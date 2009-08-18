#
# $Id: Makefile.am 1194 2009-06-19 12:54:48Z vtschopp $
#

#SUBDIRS = src test
SUBDIRS = src
EXTRA_DIST = autotools.sh 

docdir = $(datadir)/doc/$(PACKAGE)
doc_DATA = AUTHORS CHANGELOG LICENSE etc/gsi-authz.conf etc/gsi-pep-callout.conf

# Generate doxygen doc
doxygen: doc/Doxyfile
	$(DOXYGEN) doc/Doxyfile

html-local: doxygen

# Install doxygen doc in $(prefix)/share/doc/glite-authz-pep-gsi-callout/api
htmldir = $(docdir)/api
#install-data-local: install-html

uninstall-local: uninstall-html

install-html: 
	[ -d "$(htmldir)" ] || $(mkinstalldirs) $(htmldir)
	if [ -d "doc/html" ] ; then \
	for file in doc/html/* ; do \
		[ -f "$$file" ] && $(INSTALL_DATA) $$file $(htmldir)/`basename $$file`; \
	done \
	fi

uninstall-html:
	$(RM) -fr $(htmldir) 

distclean-local:
	$(RM) -fr doc/html doc/man
