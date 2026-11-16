# SPDX-License-Identifier: GPL-3.0-or-later
import asspng


def test_version_is_pep440_dev() -> None:
    assert asspng.__version__ == "0.1.0.dev0"
