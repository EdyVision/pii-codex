# PII Codex Makefile
# Used from GitHub workflow and locally
default: install test lint

test: lint test.all
test.cov: test.coverage

install:
	@poetry install
	$(MAKE) install.extras
	$(MAKE) install.pre_commit

install.pre_commit:
	@poetry run pre-commit install

install.extras:
	@poetry install --extras="detections"

install_spacy_en_core_web_lg:
	@python3 -m spacy download en_core_web_lg

jupyter.attach.venv:
	@python3 -m ipykernel install --user --name=venv

test.all:
	@pytest tests

test.coverage:
	@poetry run coverage run -m pytest -vv tests && poetry run coverage report -m --omit="*/test*,config/*.conf" --fail-under=95

lint:
	@poetry run pylint pii_codex tests

typecheck:
	@poetry run mypy pii_codex tests

format.check:
	@black . --check

format.fix:
	@black .

bump.citation.date:
	./scripts/update_citation.sh

version.bump.patch:
	@poetry version patch
	$(MAKE) bump.citation.date

version.bump.minor:
	@poetry version minor
	$(MAKE) bump.citation.date

version.bump.major:
	@poetry version major
	$(MAKE) bump.citation.date

package:
	@poetry build
