import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

from remy.db.migrate import upgrade


@pytest.fixture(
    params=["sqlite", "postgresql"] if os.environ.get("REMY_TEST_POSTGRES_URL") else ["sqlite"]
)
def database_url(tmp_path, request):
    if request.param == "postgresql":
        # The caller supplies a disposable test database. Each case owns only its new schema.
        base = make_url(os.environ["REMY_TEST_POSTGRES_URL"])
        schema = "remy_test_" + uuid4().hex
        admin = create_engine(base, connect_args={"connect_timeout": 5})
        with admin.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        url = base.update_query_dict({"options": f"-csearch_path={schema}"}).render_as_string(
            hide_password=False
        )
        engine = create_engine(url)
        try:
            upgrade(engine)
            yield url
        finally:
            engine.dispose()
            with admin.begin() as connection:
                connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
            admin.dispose()
        return
    url = f"sqlite:///{tmp_path / 'reports.db'}"
    engine = create_engine(url)
    upgrade(engine)
    engine.dispose()
    yield url
