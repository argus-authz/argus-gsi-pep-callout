#
# Copyright (c) 2008 Members of the EGEE Collaboration.
# See http://www.eu-egee.org/partners for details on the copyright holders. 
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# $Id: Makefile.am 1194 2009-06-19 12:54:48Z vtschopp $
#

#SUBDIRS = src test
SUBDIRS = src
EXTRA_DIST = autotools.sh ChangeLog COPYING LICENSE etc 

docdir = $(datadir)/doc/$(PACKAGE_NAME)-$(PACKAGE_VERSION)
doc_DATA = README ChangeLog COPYING LICENSE etc/gsi-authz.conf etc/gsi-pep-callout.conf

# Generate doxygen doc
doxygen: doc/Doxyfile
	$(DOXYGEN) doc/Doxyfile

html-local: doxygen

# Install doxygen doc in $(prefix)/share/doc/argus-pep-gsi-callout/api
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


