.PHONY: test lint demo

test:
	python3 -m unittest discover -s tests

lint:
	claude plugin validate ./plugin --strict
	claude plugin validate . --strict

# lint exits 1 on findings, and the example settings have findings on purpose.
demo:
	python3 plugin/scripts/permwhy.py --settings examples/settings.json explain 'git status && npm test'
	python3 plugin/scripts/permwhy.py --settings examples/settings.json lint || test $$? -eq 1
