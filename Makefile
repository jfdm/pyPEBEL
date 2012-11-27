## ---------------------------------------------- [ Makefile for Python Checks ]

# Simple Makefile used during development to check compliance with
# pep8 and to generate documentation

SRC=pebel
NAME=pebel

.PHONY: usage pep8 apidocs clean

usage: # Print Targets
	@grep '^[^#[:space:]].*:' Makefile

pep8: # Check for PEP8 compliance
	pep8 --first ${SRC}

apidocs: ${SRC} # Build API Documentation
	pydoctor --project-name=pebel --make-html ${SRC}

clean: # Clean Project
	rm -rf apidocs *~ *.html
