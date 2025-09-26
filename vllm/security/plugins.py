# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

#from vllm.config.security import SecurityConfig
from vllm.logger import init_logger

logger = init_logger(__name__)


class SecurityPlugin(ABC):
    """Base class for all security plugins"""

    @abstractmethod
    def set_security_config(self, security_config) -> None:
        """Set the SecurityConfig on the plugin for it to have access to
        the SecurityPolicy."""
        pass

    @abstractmethod
    def model_signature_verification_needed(self, model_path: str) -> bool:
        """Have the plugin check whether it already has done signature
        verification on the given model_path."""
        return False

    @abstractmethod
    def maybe_verify_model_signature(self, model_path: str) -> None:
        pass

    @abstractmethod
    def maybe_verify_lora_signature(self, model_path: str) -> None:
        pass


@dataclass
class _SecurityPluginRegistry:
    plugins: dict[str, SecurityPlugin] = field(default_factory=dict)

    def register_plugin(self, plugin_name: str, plugin: SecurityPlugin):
        """Register a security plugin."""
        if plugin_name in self.plugins:
            logger.warning(
                "Security plugin %s is already registered, and will be "
                "overwritten by the new plugin %s.", plugin_name, plugin)

        self.plugins[plugin_name] = plugin

    def set_security_config(self, security_config):
        """Set the SecurityConfig on all registered plugins."""
        for plugin in self.plugins.values():
            plugin.set_security_config(security_config)

    def model_signature_verification_needed(self, model_path: str) -> bool:
        """Check whether signature verification was requested and was not
        done, yet. Returns False in case no signature verification was
        requested or the signature verification is already done. Returns
        True if signature verification was request but not done yet."""
        for plugin in self.plugins.values():
            if plugin.model_signature_verification_needed(model_path):
                return True
        return False

    def maybe_verify_model_signature(self, model_path: str) -> None:
        """Have all plugins verify the signature on the model at the given
        path. Any plugin that does not accept the signature will throw an
        exception."""
        for plugin in self.plugins.values():
            plugin.maybe_verify_model_signature(model_path)

    def maybe_verify_lora_signature(self, model_path: str) -> None:
        """Have all plugins verify the signature on the LoRA at the given
        path. Any plugin that does not accept the signature will throw an
        exception."""
        for plugin in self.plugins.values():
            plugin.maybe_verify_lora_signature(model_path)


SecurityPluginRegistry = _SecurityPluginRegistry()
