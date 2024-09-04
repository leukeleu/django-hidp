.PHONY: help
help:
	@echo "The following commands are meant to be run inside the python container:"
	@echo
	@echo "  make test - Run lint, django-checks, migrationtest and coveragetest"
	@echo "  make messages - Update the message catalog"
	@echo "  make compilemessages - Compile the message catalog"
	@echo "  make lint - Check syntax and style"
	@echo "  make lintfix - Automatically fix syntax and style issues"
	@echo "  make migrationtest - Check if there are any model changes without migrations"
	@echo "  make checkmessages - Check if the message catalog is up to date and compile it"
	@echo "  make unittests - Run unit tests with coverage"
	@echo "  make coveragetest - Generate coverage report"
	@echo "  make coverage - Generate test coverage html report"
	@echo "  make django-checks - Run Django system checks"
	@echo "  make checkmanifest - Check if all files are included in the sdist"
	@echo "  make checksetup - Check package metadata"
	@echo "  make build - Build the package"
	@echo

.PHONY: test
test: lint django-checks migrationtest checkmessages coveragetest checkmanifest checksetup

.PHONY: lint
lint:
	# Check syntax and style
	ruff check
	ruff format --check --diff

.PHONY: lintfix
lintfix:
	# Automatically fix syntax and style issues
	ruff check --fix-only
	ruff format

.PHONY: migrationtest
migrationtest:
	# Check if there are any model changes without migrations
	./manage.py makemigrations --dry-run --no-input --check --settings tests.test_settings

.PHONY: messages
messages:
	# Update the message catalog
	./manage.py makemessages

.PHONY: compilemessages
compilemessages:
	# Update and compile the message catalog
	./manage.py compilemessages

.PHONY: checkmessages
checkmessages: messages
	@./Makefile.tasks.sh check-locale-diff
	@./Makefile.tasks.sh check-fuzzy-translations

tests ?= tests
.PHONY: unittests
unittests:
	# Run unit tests with coverage
	coverage run runtests.py $(tests) --shuffle

.PHONY: coveragetest
coveragetest: unittests
	# Generate coverage report
	coverage report

.PHONY: coverage
coverage: unittests
	# Generate test coverage html report
	coverage html
	@echo "Coverage report is located at ../../var/htmlcov/index.html"

.PHONY: django-checks
django-checks:
	# Run Django system checks
	python manage.py check --fail-level WARNING

.PHONY: checkmanifest
checkmanifest:
	# Check if all files are included in the sdist
	check-manifest

.PHONY: checksetup
checksetup: build
	# Check metadata
	twine check ../../var/dist/*.whl

.PHONY: build
build: clean compilemessages
	# Build the package
	python -m build --installer uv --outdir ../../var/dist

.PHONY: clean
clean:
	# Clean up build files
	rm -rf ../../var/dist/*.whl ../../var/dist/*.tar.gz

##
# This target is used by GitHub actions
##

.PHONY: install-pipeline
install-pipeline: requirements = "../../var/requirements_frozen.txt"
install-pipeline:
	uv pip compile requirements.txt -q -o "${requirements}" --no-annotate --no-header
	@echo "===== PACKAGE DEPENDENCIES ====="
	@cat  "${requirements}" | sed 's/^/  /'
	@echo "================================"
	uv pip install -r "${requirements}" -r requirements_local.txt
	openssl genrsa -out '../../var/oidc.key' 4096
	echo "*:*:*:postgres:postgres" > "$${HOME}/.pgpass"
	chmod 600 "$${HOME}/.pgpass"
