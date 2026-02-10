from __future__ import annotations

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import Connection

from alembic import context

config = context.config

if config.config_file_name:
    fileConfig(config.config_file_name)

target_metadata = None


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}) or {},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        _configure_context(connection)

        with context.begin_transaction():
            context.run_migrations()


def _configure_context(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
