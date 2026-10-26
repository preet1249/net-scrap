"""Deterministic passive rules. ``analyze`` never raises for a single failing rule; it reports rule errors instead."""
from __future__ import annotations

from typing import Any

from ..logging_setup import get_logger
from ..models import Finding
from .base import RuleContext
from .cors import rule_cors
from .exposure import (rule_authz_candidates, rule_secrets, rule_sensitive_data, rule_server_errors, rule_sourcemaps_debug,
                       rule_third_parties)
from .headers import rule_cookies, rule_headers

log = get_logger("rules")

RULES = [rule_headers, rule_cookies, rule_cors, rule_secrets, rule_sourcemaps_debug, rule_sensitive_data, rule_third_parties,
         rule_authz_candidates, rule_server_errors]
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def analyze(ctx: RuleContext) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []
    for rule in RULES:
        try:
            findings.extend(rule(ctx))
        except Exception as exc:  # a rule bug must not hide other findings
            errors.append(f"{rule.__name__}: {exc!r}")
            log.exception("rule failed", extra={"ctx": {"rule": rule.__name__}})
    seen: set[str] = set()
    uniq = []
    for f in findings:
        if f.finding_id not in seen:
            seen.add(f.finding_id)
            uniq.append(f)
    uniq.sort(key=lambda f: (SEV_ORDER[f.severity], f.rule_id, f.finding_id))
    return uniq, errors
