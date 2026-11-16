# SPDX-License-Identifier: GPL-3.0-or-later
"""The production check list: which checks run, in which order (ruling R63).

The application and the session tests both build their engine from ``default_checks``, so
the tests exercise the same checks in the same order as production.
"""
from __future__ import annotations

from asspng.checks.base import Check
from asspng.checks.limits import (
    AuthLimitsCheck,
    ConnLimitsCheck,
    SessionLimitsCheck,
    UserRateCheck,
)
from asspng.checks.penalty_box import PenaltyBox, PenaltyBoxCheck


def default_checks(box: PenaltyBox) -> list[Check]:
    """The checks of subproject 1 in engine order.

    The penalty box comes first: a blocked network gets 421 Try again later (spec 5.5), and
    its refused connections neither use the rate counter nor add score.
    """
    return [PenaltyBoxCheck(box), ConnLimitsCheck(), SessionLimitsCheck(), AuthLimitsCheck(),
            UserRateCheck()]
