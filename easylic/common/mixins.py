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
            # Handle special cases
            if attr == "rekey_after_renews":
                config_attr = "REKEY_AFTER_RENEWS_DEFAULT"
            elif attr == "max_start_attempts_per_minute":
                config_attr = "MAX_START_ATTEMPTS_PER_MINUTE"
            elif attr == "max_ciphertext_len":
                config_attr = "MAX_CIPHERTEXT_LEN"
            elif attr == "max_used_eph_pubs_per_license":
                config_attr = "MAX_USED_EPH_PUBS_PER_LICENSE"
            elif attr == "server_keys_dir":
                config_attr = "SERVER_KEYS_DIR"
            elif attr == "license_file_path":
                config_attr = "LICENSE_FILE_PATH"
            elif attr == "revoked_licenses_file_path":
                config_attr = "REVOKED_LICENSES_FILE_PATH"

            if hasattr(config_obj, config_attr):
                default_value = getattr(config_obj, config_attr)
                setattr(self, attr, overrides.get(attr, default_value))
            else:
                # If override provided but no config default, just set the override
                if attr in overrides:
                    setattr(self, attr, overrides[attr])
