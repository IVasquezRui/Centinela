from functools import lru_cache
import ipaddress
import logging
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

logger = logging.getLogger("centinela.config")


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

    database_url: str = "postgresql+asyncpg://centinela@localhost:5432/centinela"
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

    @model_validator(mode="after")
    def _inject_secrets_from_files(self) -> "Settings":
        password = read_secret(self.database_password_file)
        if password:
            self.database_url = (
                make_url(self.database_url)
                .set(password=password)
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
