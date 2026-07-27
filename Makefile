SHELL := /bin/bash

.PHONY: setup dev build start service-run test service-test check

setup:
	cd web && npm install

dev:
	cd web && npm run dev

build:
	cd web && npm run build

start:
	cd web && npm run start

service-run:
	PYTHONPATH=service uvicorn detlab.api:app --host 127.0.0.1 --port 8000

test:
	cd web && npm test

service-test:
	PYTHONPATH=service python3 -m unittest discover -s service/tests -p 'test_*.py' -v

check: test service-test build
