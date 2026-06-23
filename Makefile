SHELL := /bin/bash

.PHONY: setup dev build start test check

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

check: test build
