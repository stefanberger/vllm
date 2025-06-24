# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project

from typing import Optional

from vllm.config.security import SecurityConfig
from vllm.logger import init_logger
from vllm.validation.plugins import (ModelType, ModelValidationPlugin,
                                     ModelValidationPluginRegistry)

logger = init_logger(__name__)


class SignatureEnforcement(ModelValidationPlugin):

    def set_security_config(self, security_config: SecurityConfig) -> None:
        self.security_config = security_config

    def model_validation_needed(self, model_type: ModelType,
                                model_path: str) -> bool:
        security_policy = self.security_config.getSecurityPolicy()
        if not security_policy:
            return False
        if model_type == ModelType.MODEL_TYPE_AI_MODEL:
            return security_policy.model_signature_verification_needed(
                model_path)
        raise ValueError(f"Unsupported model_type: {model_type}")

    def validate_model(self,
                       model_type: ModelType,
                       model_path: str,
                       model: Optional[str] = None) -> None:
        security_policy = self.security_config.getSecurityPolicy()
        if security_policy:
            if model_type == ModelType.MODEL_TYPE_AI_MODEL:
                security_policy.maybe_verify_model_signature(model_path, model)
            elif model_type == ModelType.MODEL_TYPE_LORA:
                security_policy.maybe_verify_lora_signature(model_path)


def register_model_validation_plugin():
    """Register the security plugin with vLLM"""
    ModelValidationPluginRegistry.register_plugin(
        "Model Signature Enforcement", SignatureEnforcement())
