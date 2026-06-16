SHELL := /bin/bash

.PHONY: up down restart logs ps test api-test web-build

up:
	docker compose up -d --build


down:
	docker compose down


restart: down up


logs:
	docker compose logs -f api web


ps:
	docker compose ps


test:
	python3 -m pytest -q


api-test:
	curl -sS http://localhost:3000/api/health && echo
	curl -sS http://localhost:3000/api/dashboard | python3 -m json.tool >/dev/null


web-build:
	cd web && npm run build
