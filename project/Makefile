.PHONY: help
help:
	@echo "The following commands are meant to be run inside the python container:"
	@echo
	@echo "  make test - Run lint, django-checks, migrationtest and coveragetest"
	@echo "  make lint - Check syntax and style"
	@echo "  make lintfix - Automatically fix syntax and style issues"
	@echo "  make migrationtest - Check if there are any model changes without migrations"
	@echo "  make unittests - Run unit tests with coverage"
	@echo "  make coveragetest - Generate coverage report"
	@echo "  make coverage - Generate test coverage html report"
	@echo "  make django-checks - Run Django system checks"
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
test: lint django-checks migrationtest coveragetest

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
	@echo "### Project coverage" >> ${GITHUB_STEP_SUMMARY}
	@echo '```' >> ${GITHUB_STEP_SUMMARY}
	coverage report >> ${GITHUB_STEP_SUMMARY}
	@echo '```' >> ${GITHUB_STEP_SUMMARY}
endif

.PHONY: coverage
coverage: unittests
	# Generate test coverage html report
	coverage html
	@echo "Coverage report is located at ../var/htmlcov/index.html"

.PHONY: django-checks
django-checks:
	# Run Django system checks
	$(call group,Running Django system checks)
	python manage.py check --fail-level WARNING
	$(call endgroup)

##
# This target is used by GitHub actions
##

../var/requirements_frozen.txt:
	# Pin Django directly to LTS version provided by the test matrix
	echo 'Django~=${DJANGO_VERSION}.0' >> requirements.txt
	uv pip compile requirements.txt -q -o "${@}" --no-annotate --no-header
	@echo "### Project dependencies :package:" >> ${GITHUB_STEP_SUMMARY}
	@echo '```' >> ${GITHUB_STEP_SUMMARY}
	@cat "${@}" >> ${GITHUB_STEP_SUMMARY}
	@echo '```' >> ${GITHUB_STEP_SUMMARY}

.PHONY: install-requirements
install-requirements: ../var/requirements_frozen.txt
	$(call group,Installing dependencies)
	uv pip install -r '../var/requirements_frozen.txt' -r requirements_local.txt
	$(call endgroup)

.PHONE: post-install
post-install:
	$(call group,Additional setup)
	openssl genrsa -out '../var/oidc.key' 4096
	ln -s local.example.ini hidp_sandbox/local.ini
	echo "*:*:*:postgres:postgres" > "$${HOME}/.pgpass"
	chmod 600 "$${HOME}/.pgpass"
	./manage.py collectstatic --link --settings=tests.test_settings
	$(call endgroup)

.PHONY: install-pipeline
install-pipeline: install-requirements post-install
