"""Entorno de Alembic. La URL la pone `vs.model.migrate.config()`; aquí no hay ninguna."""

from alembic import context
from sqlalchemy import engine_from_config, pool

from vs.model.schema import metadata

config = context.config
target_metadata = metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _migrate(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # `vs.model.migrate` pasa la conexión ya abierta (patrón del cookbook de Alembic): así la
    # migración usa el mismo motor que el resto, con el token de Entra en Azure.
    connection = config.attributes.get("connection")
    if connection is not None:
        _migrate(connection)
        return
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        _migrate(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
