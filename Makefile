SHELL := /bin/bash

.PHONY: setup dev build start test service-test check

setup:
	cd web && npm install

dev:
	cd web && npm run dev

build:
	cd web && npm run build

start:
	cd web && npm run start

test:
	cd web && npm test

service-test:
	PYTHONPATH=service python3 -m unittest discover -s service/tests -p 'test_*.py' -v

check: test service-test build
