#
# crmsh
#
# Copyright (C) 2015 Kristoffer Gronlund
# Copyright (C) 2008 Andrew Beekhof
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure

# in .spec, set --sysconfdir=/etc

# Documentation
doc_DATA = AUTHORS COPYING README.md ChangeLog $(generated_docs)
crmconfdir=$(sysconfdir)/crm
crmconf_DATA = etc/crm.conf etc/profiles.yml
contribdir      = $(docdir)/contrib
contrib_DATA	= contrib/pcmk.vim  contrib/README.vimsyntax
helpdir     = $(datadir)/$(PACKAGE)
asciiman	= doc/crm.8.adoc doc/crmsh_crm_report.8.adoc doc/profiles.adoc
help_DATA	= doc/crm.8.adoc

generated_docs	=
generated_mans	=
if BUILD_ASCIIDOC
generated_docs	+= $(ascii:%.adoc=%.html) $(asciiman:%.adoc=%.html)
generated_mans	+= $(asciiman:%.8.adoc=%.8)
$(generated_mans): $(asciiman)
man8_MANS	= $(generated_mans)
endif

%.html: %.adoc
	$(ASCIIDOC) --unsafe --backend=xhtml11 $<

%.8: %.8.adoc
	a2x -f manpage $<

# Shared data files
install-data-hook:
	mkdir -p $(DESTDIR)$(datadir)/@PACKAGE@/; \
	for d in $$(cat data-manifest); do \
	install -D -m $$(test -x $$d && echo 0755 || echo 0644) $$d $(DESTDIR)$(datadir)/@PACKAGE@/$$d; done; \
	mv $(DESTDIR)$(datadir)/@PACKAGE@/test $(DESTDIR)$(datadir)/@PACKAGE@/tests; \
	cp test/testcases/xmlonly.sh $(DESTDIR)$(datadir)/@PACKAGE@/tests/testcases/configbasic-xml.filter

# Python module installation
all-local:
	cd $(srcdir); python3 -m build --outdir $(shell readlink -f $(builddir))/dist --wheel --sdist --verbose

python_prefix = --prefix=$(prefix)

install-exec-local:
	$(INSTALL) -d -m 770 $(DESTDIR)/${localstatedir}/log/crmsh
	python3 -m pip install --prefix=$(prefix) $(shell readlink -f $(builddir))/dist/*.whl
	$(INSTALL) -d -m 770 $(DESTDIR)$(CRM_CACHE_DIR)

uninstall-local:
	rm -rf $(crmconfdir)
	rm -rf $(docdir)
	rm -rf $(DESTDIR)$(CRM_CACHE_DIR)
	rm -rf $(DESTDIR)/${localstatedir}/log/crmsh
	rm -rf $(DESTDIR)$(pkgpythondir)

uninstall-hook:
	@echo "Removing installed data files..."
	rm -rf $(DESTDIR)$(datadir)/@PACKAGE@
	@echo "Uninstallation complete."

clean-local:
	@echo "Removing intermediate python build files..."
	rm -rf $(builddir)/dist
	rm -rf $(builddir)/build
	@echo "Removing complete."

dist-clean-local: clean-local
	rm -f autoconf automake autoheader
