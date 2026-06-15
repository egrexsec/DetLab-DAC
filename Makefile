up:
	docker compose up --build -d

 down:
	docker compose down

logs:
	docker compose logs -f

reset:
	docker compose down -v
	docker compose up --build -d

demo:
	./scripts/seed-demo-data.sh
