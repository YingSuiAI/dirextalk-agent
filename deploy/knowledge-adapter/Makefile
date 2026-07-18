.PHONY: test test-python test-go build compileall release-golden verify

test: test-python test-go

test-python:
	python3.12 -I -S -B -m unittest discover -s tests -p 'test_*.py'

test-go:
	go test ../../internal/knowledgeinstaller

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags='-buildid=' -o /tmp/dirextalk-knowledge-installer ../../cmd/dirextalk-knowledge-installer

compileall:
	python3.12 -I -S -B -X pycache_prefix=/tmp/dirextalk-knowledge-adapter-pyc -m compileall -q adapter scripts tests

release-golden:
	python3.12 -I -S -B adapter/release_golden.py

verify: test build compileall
