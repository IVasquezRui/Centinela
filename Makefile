# Atajos de un solo comando para el Sprint 1 (ver docs/SPRINT-1.md).
# En Windows sin `make`, usar los equivalentes en scripts/*.ps1.

.PHONY: up down demo reset-db test

up:
	docker compose up --build -d
	docker compose ps

down:
	docker compose down

demo:
	docker compose --profile demo run --rm attacker-sim --total 1000 --malicious-ratio 0.3

reset-db:
	docker compose exec -T centinela-db psql -U $${POSTGRES_USER:-centinela} -d $${POSTGRES_DB:-centinela} \
		-c "TRUNCATE audit_log, event RESTART IDENTITY CASCADE;"

test:
	cd centinela-core && pytest
