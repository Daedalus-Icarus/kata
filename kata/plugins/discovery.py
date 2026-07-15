"""Discover and resolve the subnet plugin for a submission or lane.

The core dispatches by ``evaluator_id`` -- the same id the lane registry records -- and
never imports any subnet package by name. Subnet plugins are discovered via the
``kata.subnets`` entry-point group, so adding a subnet is installing a package that declares
the entry point (no code change here).
"""

from __future__ import annotations

from kata.plugins.contract import SubnetPlugin
from kata.plugins.registry import all_plugins, get_plugin_or_none, register_plugin


def load_builtin_plugins() -> None:
    """Discover and register every installed subnet plugin via entry points.

    Each subnet package advertises its ``SubnetPlugin`` singleton under the
    ``kata.subnets`` entry-point group; this loads all installed ones and registers them.
    Idempotent and cheap to call repeatedly (repairs a cleared registry, e.g. in tests).
    """
    from importlib.metadata import entry_points

    for entry_point in entry_points(group="kata.subnets"):
        plugin = entry_point.load()
        if get_plugin_or_none(plugin.evaluator_id) is None:
            register_plugin(plugin)


def plugin_for_evaluator(evaluator_id: str | None) -> SubnetPlugin | None:
    """Return the registered plugin for ``evaluator_id``, or ``None`` if there is none."""
    if not evaluator_id:
        return None
    load_builtin_plugins()
    return get_plugin_or_none(evaluator_id)


def plugin_for_pack(pack: str | None, mode: str) -> SubnetPlugin | None:
    """Return the registered plugin whose ``(pack, mode)`` matches, or ``None``.

    Resolves in-process from the plugin registry (no pack-registry file required), so a
    lane's subnet-specific screening works wherever its plugin is importable.
    """
    if not pack:
        return None
    load_builtin_plugins()
    for plugin in all_plugins():
        if plugin.pack == pack and plugin.mode == mode:
            return plugin
    return None
