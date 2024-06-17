##
# Local targets, meant to be run on the host machine
##

.PHONY: help
help:
	@echo "The following commands are meant to be run locally (i.e. not in a container):"
	@echo
	@echo "  make clean - Remove virtualenv, node_modules, cache and other temporary files"
	@echo

.PHONY: clean
clean:
	rm -rf var/venv var/cache var/*.sha1
	find . -type d -name node_modules | xargs rm -rf
