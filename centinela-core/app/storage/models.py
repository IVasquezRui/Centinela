"""Modelos SQLAlchemy que reflejan el esquema de db/init/01_schema.sql.

El esquema SQL (versionado en db/init/) es la fuente de verdad; estos
modelos existen para que la API y el worker de IA puedan leer/escribir con
tipado en Python sin repetir SQL a mano en cada endpoint.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Float, ForeignKey, Integer, SmallInteger, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "event"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    src_ip: Mapped[str] = mapped_column(String(64))
    method: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(Text)
    target: Mapped[str] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(String(16))
    rule_id: Mapped[str | None] = mapped_column(String(32), ForeignKey("rule.id"), nullable=True)
    category: Mapped[str | None] = mapped_column(String(32), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    technique_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    engine_us: Mapped[int] = mapped_column(Integer)
    payload_sample: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_status: Mapped[str] = mapped_column(String(16), default="pending")

    __table_args__ = (
        CheckConstraint("verdict IN ('block', 'allow')", name="ck_event_verdict"),
        CheckConstraint("ai_status IN ('pending', 'done', 'failed')", name="ck_event_ai_status"),
        CheckConstraint("severity IN ('baja', 'media', 'alta', 'critica') OR severity IS NULL", name="ck_event_severity"),
    )


class Rule(Base):
    __tablename__ = "rule"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    technique_id: Mapped[str] = mapped_column(String(16), ForeignKey("attack_technique.technique_id"))
    description: Mapped[str] = mapped_column(Text)
    pattern: Mapped[str] = mapped_column(Text)


class AttackTechnique(Base):
    __tablename__ = "attack_technique"

    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    tactic: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    event_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    action: Mapped[str] = mapped_column(String(32))
    payload: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class AuditAnchor(Base):
    __tablename__ = "audit_anchor"

    # Fila única (id=1) que guarda el último eslabón de la cadena de auditoría
    # para detectar borrados del final (truncamiento) que el hash encadenado
    # por sí solo no puede ver.
    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    last_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.timezone.utc))
