from alembic import context

from app import models  # noqa: F401
from app.config import get_settings
from app.db import Base, make_engine

config = context.config
url = config.get_main_option("sqlalchemy.url") or get_settings().database_url


def run() -> None:
    if context.is_offline_mode():
        context.configure(url=url, target_metadata=Base.metadata, literal_binds=True, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
        return
    with make_engine(url).connect() as conn:
        context.configure(connection=conn, target_metadata=Base.metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()


run()
