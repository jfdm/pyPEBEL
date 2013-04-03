## ---------------------------------------------- [ Makefile for Python Checks ]

# Simple Makefile used during development to check compliance with
# pep8 and to generate documentation

SRC=pebel
NAME=pebel

.PHONY: usage pep8 apidocs clean pylint install

usage: # Print Targets
	@grep '^[^#[:space:]].*:' Makefile

dist:

pep8: # Check for PEP8 compliance
	pep8 --first ${SRC}

install: # Install
	python3 distribute_setup.py check build install

pylint: # Analyse Source
	pylint -f html --files-output=y

apidocs: ${SRC} # Build API Documentation
	pydoctor --project-name=pebel --make-html ${SRC}

clean: # Clean Project
	rm -rf apidocs *~ *.html
