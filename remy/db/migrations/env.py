"""Run using the operator-owned connection supplied by remy.db.migrate."""

from alembic import context

context.configure(connection=context.config.attributes["connection"])
with context.begin_transaction():
    context.run_migrations()
