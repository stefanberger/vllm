# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project

from vllm.config.security import SecurityConfig
from vllm.logger import init_logger
from vllm.security.plugins import SecurityPlugin, SecurityPluginRegistry

logger = init_logger(__name__)


class SignatureEnforcement(SecurityPlugin):

    def set_security_config(self, security_config: SecurityConfig) -> None:
        self.security_config = security_config

    def model_signature_verification_needed(self, model_path: str) -> bool:
        security_policy = self.security_config.getSecurityPolicy()
        if not security_policy:
            return False
        return security_policy.model_signature_verification_needed(model_path)

    def maybe_verify_model_signature(self, model_path: str) -> None:
        security_policy = self.security_config.getSecurityPolicy()
        if security_policy:
            security_policy.maybe_verify_model_signature(model_path)

    def maybe_verify_lora_signature(self, model_path: str) -> None:
        security_policy = self.security_config.getSecurityPolicy()
        if security_policy:
            security_policy.maybe_verify_lora_signature(model_path)


def register_security_plugin():
    """Register the security plugin with vLLM"""
    signature_enforcement = SignatureEnforcement()
    SecurityPluginRegistry.register_plugin("Model Signature Enforcement",
                                           signature_enforcement)
