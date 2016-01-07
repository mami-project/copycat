SUBDIRS = src
dist_doc_DATA = README.md
EXTRA_DIST = udptun.cfg

if HAVE_DOXYGEN
doc:
	$(DOXYGEN) doc/Doxyfile
.PHONY: doc
endif 
