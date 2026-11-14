# Atajos de un solo comando para el Sprint 1 (ver docs/SPRINT-1.md).
# En Windows sin `make`, usar los equivalentes en scripts/*.ps1.

.PHONY: up down demo reset-db test secrets

# Genera secrets/*.txt (permisos 600, fuera de git) si aún no existen.
secrets:
	./scripts/gen-secrets.sh

up: secrets
	docker compose up --build -d
	docker compose ps

down:
	docker compose down

demo:
	docker compose --profile demo run --build --rm attacker-sim --total 1000 --malicious-ratio 0.3

reset-db:
	# Las variables se expanden DENTRO del contenedor: en el host ya no existen
	# credenciales (viven en secrets/) y antes el comando caía silenciosamente a
	# los valores por defecto aunque POSTGRES_USER/POSTGRES_DB fueran otros.
	docker compose exec -T centinela-db sh -c 'psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" -c "TRUNCATE audit_log, event RESTART IDENTITY CASCADE;"'
	# Reinicia el core para vaciar la cuarentena en memoria del IPS y la cola.
	docker compose restart centinela-core
	@i=0; until [ "$$(docker inspect -f '{{.State.Health.Status}}' centinela_core)" = "healthy" ] || [ $$i -ge 60 ]; do i=$$((i+1)); sleep 1; done
	@echo "Reset listo: event/audit_log vacíos, cadena en GENESIS, core $$(docker inspect -f '{{.State.Health.Status}}' centinela_core)."

test:
	cd centinela-core && pytest
