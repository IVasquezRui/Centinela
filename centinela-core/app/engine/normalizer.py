"""Normaliza una petición entrante antes de evaluarla contra las reglas.

El objetivo es que un atacante no pueda esquivar una regla simplemente
cambiando mayúsculas/minúsculas o codificando dos veces el payload
(doble URL-encoding), un truco clásico de evasión de WAF.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from urllib.parse import unquote

# Tope del texto inspeccionable por petición. Ninguna regla opera sobre una
# entrada arbitrariamente grande: evita que un query/body enorme haga lento el
# motor o consuma memoria (defensa en profundidad contra ReDoS).
MAX_INSPECTABLE_CHARS = 64 * 1024


@dataclass
class NormalizedRequest:
    method: str
    path: str
    query_string: str
    headers: dict[str, str]
    body: str
    src_ip: str
    inspectable_text: str = field(init=False)

    def __post_init__(self) -> None:
        # Todo lo que puede llevar un payload inyectado, concatenado en un
        # solo texto para que las reglas solo necesiten mirar un lugar.
        #
        # Se incluye además una variante con '+' convertido en espacio: en
        # application/x-www-form-urlencoded '+' significa espacio, pero
        # urllib.unquote() no lo traduce. Sin esto, "1+union+select+..." esquiva
        # cualquier regla que busque espacios (evasión trivial de WAF).
        parts = [self.path, self.query_string, self.body]
        parts.extend(
            variant.replace("+", " ") for variant in (self.query_string, self.body)
        )
        # Tope de seguridad: el texto inspeccionado se trunca para que
        # ninguna regla evalúe más de MAX_INSPECTABLE_CHARS por petición.
        self.inspectable_text = "\n".join(parts)[:MAX_INSPECTABLE_CHARS]


_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _decode_unicode_escapes(value: str) -> str:
    """Convierte escapes JSON \\uXXXX (p. ej. \\u0027 -> ') a su carácter.

    Evita que un payload codificado como JSON evada las reglas; los puntos de
    código sustitutos se conservan tal cual para no generar chr() inválidos.
    """
    def repl(match: "re.Match[str]") -> str:
        code = int(match.group(1), 16)
        if 0x20 <= code < 0xD800 or 0xE000 <= code < 0x110000:
            return chr(code)
        return match.group(0)
    return _UNICODE_ESCAPE.sub(repl, value)


def _decode_fully(value: str, max_passes: int = 3) -> str:
    """Decodifica URL-encoding de forma repetida hasta que ya no cambie.

    Cubre el caso de doble codificación (%2527 -> %27 -> ') sin entrar en
    un bucle infinito si el payload es adversarial. También neutraliza
    separadores invertidos (\\ -> /) y caracteres nulos (\x00 / %00) que
    se usan típicamente para evadir WAFs o truncar extensiones de archivo.
    """
    decoded = value
    for _ in range(max_passes):
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded

    # Decodifica escapes JSON \uXXXX (p. ej. \u0027 -> '): un payload
    # codificado como JSON no debe evadir las reglas.
    decoded = _decode_unicode_escapes(decoded)

    # Elimina terminadores nulos (\x00) para evitar truncamiento malicioso
    # y estandariza barras invertidas a barras normales para path traversal.
    sanitized = decoded.replace("\x00", "").replace("\\", "/")
    return sanitized


def normalize(
    *,
    method: str,
    path: str,
    query_string: str,
    headers: dict[str, str],
    body: bytes,
    src_ip: str,
) -> NormalizedRequest:
    decoded_path = _decode_fully(path)
    decoded_query = _decode_fully(query_string)
    try:
        decoded_body = _decode_fully(body.decode("utf-8", errors="ignore"))
    except Exception:
        decoded_body = ""

    return NormalizedRequest(
        method=method.upper(),
        path=decoded_path,
        query_string=decoded_query,
        headers={k.lower(): v for k, v in headers.items()},
        body=decoded_body,
        src_ip=src_ip,
    )
