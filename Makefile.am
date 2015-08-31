# Copyright (C) 2006-2013 Free Software Foundation, Inc.
# This Makefile.am is free software; the Free Software Foundation
# gives unlimited permission to copy, distribute and modify it.

SUBDIRS = src
dist_doc_DATA = README.md

if HAVE_DOXYGEN
doc:
	$(DOXYGEN) doc/Doxyfile
.PHONY: doc
endif 
