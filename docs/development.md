# Development

ASSP-NG targets Python 3.12 or newer and uses only Debian-packaged dependencies
(no pip, no virtualenv).

## Packages

Install as root on Debian trixie:

```
apt install python3-dnspython python3-redis python3-pymysql python3-sqlalchemy python3-alembic python3-systemd python3-cryptography python3-tomlkit python3-pytest python3-pytest-asyncio python3-hypothesis python3-pytest-cov python3-mypy python3-flake8 redis-server swaks shellcheck
```

## Running checks

Run everything from the repository root. Debian's `python3-flake8` and
`python3-mypy` provide modules but no `flake8` or `mypy` commands, so always
use `python3 -m`:

```
export PYTHONNOUSERSITE=1
python3 -m pytest tests/unit -v
python3 -m flake8
python3 -m mypy asspng
```

`PYTHONNOUSERSITE=1` makes Python ignore packages installed with `pip install --user` in
`~/.local/lib/python3.*/site-packages`. Other software sometimes puts its own copy of a
dependency there (for example an older `dnspython`). That copy would shadow the Debian package,
so local results would differ from CI, which uses the Debian versions only. The test suite stops
at once with a message naming the module if a dependency would be loaded from there.

## Database tests

The repository and migration tests always run against SQLite on a temporary file.
The MySQL/MariaDB variant is skipped unless `ASSPNG_TEST_DB_URL` is set to a SQLAlchemy
URL of a disposable test database. Every test drops all tables in that database first,
so never point it at real data. Create the database and user once (replace `PASSWORD`):

```
CREATE DATABASE asspng_test CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'asspng_test'@'localhost' IDENTIFIED BY 'PASSWORD';
GRANT ALL PRIVILEGES ON asspng_test.* TO 'asspng_test'@'localhost';
FLUSH PRIVILEGES;
```

Then run, for example:

```
ASSPNG_TEST_DB_URL=mysql+pymysql://asspng_test:PASSWORD@localhost/asspng_test \
    python3 -m pytest tests/integration/db -v
```
