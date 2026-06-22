SHELL := /bin/bash

.PHONY: up down restart logs ps test api-test web-build

up:
	./scripts/start.sh

down:
	./scripts/stop.sh

restart: down up

logs:
	@mkdir -p .detlab-run
	tail -f .detlab-run/api.log .detlab-run/web.log

ps:
	@bash -lc 'for svc in api web; do pidfile=.detlab-run/$$svc.pid; if [[ -f $$pidfile ]] && kill -0 $$(cat $$pidfile) >/dev/null 2>&1; then echo "$$svc: running (PID $$(cat $$pidfile))"; else echo "$$svc: stopped"; fi; done'

test:
	uv run pytest

api-test:
	curl -sS http://127.0.0.1:8000/health && echo
	curl -sS http://127.0.0.1:8000/dashboard | python3 -m json.tool >/dev/null

web-build:
	cd web && npm run build
