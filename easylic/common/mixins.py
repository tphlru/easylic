"""
Mixins for common functionality.
"""

from __future__ import annotations

from typing import Any


class Configurable:
    """
    Mixin class for handling configuration overrides.

    Classes using this mixin should define a config attribute and can use
    apply_overrides to set attributes from override dict using config defaults.
    """

    def apply_overrides(
        self,
        overrides: dict[str, Any],
        config_obj: Any,
        attr_list: list[str] | None = None,
    ) -> None:
        """
        Apply overrides to the instance using the config object as defaults.

        Sets self.attr = overrides.get(attr, config_obj.ATTR) for each attr in attr_list.

        Args:
            overrides: Dictionary of override values
            config_obj: Configuration object with uppercase attribute names
            attr_list: List of attribute names to set
        """
        if attr_list is None:
            attr_list = []

        for attr in attr_list:
            config_attr = attr.upper()

            if hasattr(config_obj, config_attr):
                default_value = getattr(config_obj, config_attr)
                setattr(self, attr, overrides.get(attr, default_value))
            # If override provided but no config default, just set the override
            elif attr in overrides:
                setattr(self, attr, overrides[attr])
