from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Database URL – SQLite file in the project root.
#
# Decisión explícita (2026-07-05, rename SIAM -> SIEM): el archivo físico se
# queda llamado `siam.db` a propósito -- José prefirió no renombrarlo para no
# arriesgar los datos reales (tickets, incidents, campaigns...) con un mv/cp
# manual. Solo cambió el nombre del paquete Python (`siam/` -> `siem/`), no
# el nombre del archivo de base de datos. No hace falta ningún paso manual
# con el .db: sigue siendo el mismo archivo de siempre.
SQLALCHEMY_DATABASE_URL = f"sqlite:///{os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'siam.db'))}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def run_light_migrations(bind_engine=None) -> None:
    """Añade columnas nuevas a tablas ya existentes en el siam.db real.

    `Base.metadata.create_all` (llamado desde el lifespan de siem/main.py)
    SOLO crea tablas que no existen -- no añade columnas nuevas a una tabla
    que ya existía antes de ese cambio de modelo. El siam.db real de José
    lleva semanas de datos reales (eventos, incidentes...) en las tablas
    `events`/`incidents`, así que añadir `threat_ids` en
    siem/db_models.py (2026-07-05, detección de amenazas) se quedaría corto:
    sin esto, cualquier INSERT/SELECT sobre esas tablas fallaría con "no
    such column: threat_ids" en cuanto se tocara una fila existente.

    ALTER TABLE ... ADD COLUMN es seguro en SQLite para columnas nuevas
    (no reescribe la tabla), así que se ejecuta en cada arranque -- es
    idempotente: si la columna ya existe, se captura el error y no se hace
    nada. Deliberadamente NO se usa un framework de migraciones (Alembic)
    para un cambio tan pequeño; si el esquema sigue creciendo, sí valdría la
    pena introducirlo.
    """
    from sqlalchemy import text

    bind_engine = bind_engine or engine
    statements = [
        "ALTER TABLE events ADD COLUMN threat_ids JSON DEFAULT '[]'",
        "ALTER TABLE incidents ADD COLUMN threat_ids JSON DEFAULT '[]'",
        # 2026-07-16, tiempo de resolución en el dashboard.
        "ALTER TABLE incidents ADD COLUMN resolved_at DATETIME",
        # Backfill de los incidentes ya resueltos antes de esta columna:
        # updated_at es la mejor aproximación disponible (el último cambio de
        # un incidente resuelto suele ser justo el paso a resuelto). Para los
        # resueltos a partir de ahora, el PATCH pone el valor exacto, así que
        # este UPDATE queda en no-op en arranques siguientes.
        "UPDATE incidents SET resolved_at = updated_at WHERE status = 'resuelto' AND resolved_at IS NULL",
    ]
    with bind_engine.connect() as conn:
        for statement in statements:
            try:
                conn.execute(text(statement))
                conn.commit()
            except Exception:
                # Columna ya existente (o tabla que create_all creará desde
                # cero con la columna incluida, p.ej. en tests con SQLite en
                # memoria) -- no es un error real, se ignora.
                conn.rollback()
