"""Subnet-agnostic core orchestration for Kata.

This package holds the platform's King-of-the-Hill machinery that is driven through
the :class:`~kata.plugins.contract.SubnetPlugin` interface and shared by every subnet.
"""

from __future__ import annotations

from .round import RoundOutcome, ScoredVariant, run_plugin_round

__all__ = ["RoundOutcome", "ScoredVariant", "run_plugin_round"]
