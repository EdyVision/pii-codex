# PII Codex Makefile
# Used from GitHub workflow and locally
default: install test lint

test: lint test.all
test.cov: test.coverage

install:
	@uv sync
	@uv sync --all-extras
	@uv sync --extra dev 
	$(MAKE) install.pre_commit
	@echo "Installation complete!"

install.pre_commit:
	@uv run pre-commit install || (echo "Warning: pre-commit installation failed. You may need to run 'uv sync --extra dev' first." && exit 1)

install.extras:
	@echo "Installing detection dependencies (spaCy, Presidio, etc.)..."
	@uv sync --extra detections

install_spacy_en_core_web_lg:
	@python3 -m spacy download en_core_web_lg

jupyter.attach.venv:
	@python3 -m ipykernel install --user --name=venv

test.all:
	@pytest tests

test.coverage:
	@uv run coverage run -m pytest -vv tests && uv run coverage report -m --omit="*/test*,config/*.conf" --fail-under=95
	@uv run coverage xml

lint:
	@uv run pylint pii_codex tests

typecheck:
	@uv run mypy pii_codex tests

format.check:
	@black . --check

format.fix:
	@black .

bump.citation.date:
	./scripts/update_citation.sh

docs:
	@pdoc --html pii_codex --force -o ./docs/dev

version.bump.patch:
	@uv run bumpver update --patch
	# $(MAKE) bump.citation.date

version.bump.minor:
	@uv run bumpver update --minor
	$(MAKE) bump.citation.date

version.bump.major:
	@uv run bumpver update --major
	$(MAKE) bump.citation.date

package:
	@uv build
