from functools import lru_cache
import hashlib
import ipaddress
import logging
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

logger = logging.getLogger("centinela.config")

# Rol de mínimos privilegios creado por db/init/03_grants.sh. No es
# configurable: el nombre está hardcodeado también en ese script (los GRANT
# apuntan literalmente a "centinela_app"), así que hacerlo variable aquí sin
# tocar el SQL solo generaría una desincronización silenciosa.
APP_DB_ROLE = "centinela_app"


def derive_app_db_password(admin_password: str) -> str:
    """Reproduce la derivación de db/init/03_grants.sh.

    El rol centinela_app nunca comparte contraseña literal con el
    superusuario de Postgres ni necesita un secreto propio: su password es
    sha256("centinela_app:" + POSTGRES_PASSWORD), documentado en
    secrets/README.md. Si esta fórmula cambia, debe cambiar en los dos
    lados a la vez (este archivo y 03_grants.sh).
    """
    return hashlib.sha256(f"{APP_DB_ROLE}:{admin_password}".encode("utf-8")).hexdigest()


def read_secret(file_path: str | None) -> str:
    """Devuelve el contenido de un secreto montado por Docker (convención *_FILE).

    Los secretos llegan como archivo en /run/secrets/<nombre>, de modo que la
    credencial no viaja en variables de entorno (visibles en `docker inspect`)
    ni en el repositorio. Cualquier error de lectura se degrada a cadena vacía
    para que el servicio arranque y falle de forma explícita al usarlo.
    """
    if not file_path:
        return ""
    path = Path(file_path)
    try:
        if path.is_file():
            return path.read_text(encoding="utf-8").strip()
    except OSError:
        logger.exception("No se pudo leer el secreto %s", file_path)
    return ""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = f"postgresql+asyncpg://{APP_DB_ROLE}@localhost:5432/centinela"
    # Apunta al MISMO secreto que POSTGRES_PASSWORD_FILE del superusuario
    # (ver docker-compose.yml): la contraseña real del rol de aplicación se
    # deriva de ahí con derive_app_db_password(), nunca se distribuye un
    # segundo secreto para centinela_app.
    database_password_file: str = ""

    target_gov_pago_url: str = "http://gov-pago:80"
    target_tickets_url: str = "http://tickets:4000"

    deepseek_api_key: str = ""
    deepseek_api_key_file: str = ""
    deepseek_api_base: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"
    ai_timeout_seconds: float = 3.0

    blocklist_threshold: int = 3
    blocklist_window_seconds: int = 60
    blocklist_quarantine_seconds: int = 300

    queue_batch_size: int = 50
    queue_flush_interval_seconds: float = 0.5

    # CIDR de proxies de confianza (separados por coma). Vacío = no se acepta
    # X-Forwarded-For de nadie, porque cualquiera puede falsificarlo y elegir
    # la IP con la que el IPS decide la cuarentena.
    trusted_proxies: str = ""

    # API del SOC: llave opcional para proteger /api/events, /api/stats,
    # /api/blocklist y /api/audit/verify. Vacía => acceso sin llave (solo
    # demo local). En producción se define y el panel envía X-API-Key.
    api_key: str = ""
    # Orígenes permitidos por CORS (separados por coma).
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    @model_validator(mode="after")
    def _inject_secrets_from_files(self) -> "Settings":
        admin_password = read_secret(self.database_password_file)
        if admin_password:
            app_password = derive_app_db_password(admin_password)
            self.database_url = (
                make_url(self.database_url)
                .set(username=APP_DB_ROLE, password=app_password)
                .render_as_string(hide_password=False)
            )
        if not self.deepseek_api_key:
            self.deepseek_api_key = read_secret(self.deepseek_api_key_file)
        return self

    @property
    def trusted_proxy_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for item in self.trusted_proxies.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                logger.warning("TRUSTED_PROXIES contiene un CIDR inválido: %r", item)
        return networks

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
