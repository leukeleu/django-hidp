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

GITHUB_ACTIONS ?= false

# Helper function to define a GitHub Actions group
define group
	@if [ "$(GITHUB_ACTIONS)" = "true" ]; then \
		echo "::group::$1"; \
	fi
endef

# Helper function to end a GitHub Actions group
define endgroup
	@if [ "$(GITHUB_ACTIONS)" = "true" ]; then \
		echo "::endgroup::"; \
	fi
endef

.PHONY: test
test: lint django-checks migrationtest checkmessages coveragetest checkmanifest checksetup

.PHONY: lint
lint:
	# Check syntax and style
	$(call group,Checking syntax and style)
	ruff check
	ruff format --check --diff
	$(call endgroup)

.PHONY: lintfix
lintfix:
	# Automatically fix syntax and style issues
	ruff check --fix-only
	ruff format

.PHONY: migrationtest
migrationtest:
	# Check if there are any model changes without migrations
	$(call group,Checking for missing migrations)
	./manage.py makemigrations --dry-run --no-input --check --settings tests.test_settings
	$(call endgroup)

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
	$(call group,Checking message catalog)
	@./Makefile.tasks.sh check-locale-diff
	@./Makefile.tasks.sh check-fuzzy-translations
	$(call endgroup)

tests ?= tests
.PHONY: unittests
unittests:
	$(call group,Running unit tests)
	# Run unit tests with coverage
	coverage run runtests.py $(tests) --shuffle
	$(call endgroup)

.PHONY: coveragetest
coveragetest: unittests
	# Generate coverage report
ifneq ($(GITHUB_ACTIONS),true)
	coverage report
else
	@echo "### Package coverage" >> ${GITHUB_STEP_SUMMARY}
	@echo '```' >> ${GITHUB_STEP_SUMMARY}
	coverage report >> ${GITHUB_STEP_SUMMARY}
	@echo '```' >> ${GITHUB_STEP_SUMMARY}
endif

.PHONY: coverage
coverage: unittests
	# Generate test coverage html report
	coverage html
	@echo "Coverage report is located at ../../var/htmlcov/index.html"

.PHONY: django-checks
django-checks:
	# Run Django system checks
	$(call group,Running Django system checks)
	python manage.py check --fail-level WARNING
	$(call endgroup)

.PHONY: checkmanifest
checkmanifest:
	# Check if all files are included in the sdist
	$(call group,Checking manifest)
	check-manifest
	$(call endgroup)

.PHONY: checksetup
checksetup: build
	# Check metadata
	$(call group,Checking package metadata)
	twine check ../../var/dist/*.whl
	$(call endgroup)

.PHONY: build
build: clean compilemessages
	# Build the package
	$(call group,Building package)
	python -m build --installer uv --outdir ../../var/dist
	$(call endgroup)

.PHONY: clean
clean:
	# Clean up build files
	$(call group,Cleaning up)
	rm -rf ../../var/dist/*.whl ../../var/dist/*.tar.gz
	$(call endgroup)

##
# This target is used by GitHub actions
##

../../var/requirements_frozen.txt:
	uv pip compile pyproject.toml --extra oidc_provider -q -o "${@}" --no-annotate --no-header
	@echo "### Package dependencies :package:" >> ${GITHUB_STEP_SUMMARY}
	@echo '```' >> ${GITHUB_STEP_SUMMARY}
	@cat "${@}" >> ${GITHUB_STEP_SUMMARY}
	@echo '```' >> ${GITHUB_STEP_SUMMARY}

.PHONY: install-requirements
install-requirements: ../../var/requirements_frozen.txt
	$(call group,Installing dependencies)
	uv pip install -r '../../var/requirements_frozen.txt' -r requirements_local.txt
	$(call endgroup)

.PHONY: post-install
post-install:
	$(call group,Additional setup)
	openssl genrsa -out '../../var/oidc.key' 4096
	echo "*:*:*:postgres:postgres" > "$${HOME}/.pgpass"
	chmod 600 "$${HOME}/.pgpass"
	$(call endgroup)

.PHONY: install-pipeline
install-pipeline: install-requirements post-install
