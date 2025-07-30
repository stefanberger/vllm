# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project

from typing import Optional

from pydantic import ConfigDict
from pydantic.dataclasses import dataclass

from vllm.config.utils import config
from vllm.plugins.validation.policy import SecurityPolicy


@config
@dataclass(config=ConfigDict(arbitrary_types_allowed=True))
class SecurityConfig:
    """vLLM Security Configuration"""
    security_policy: Optional[str] = None
    """Security policy file"""
    _security_policy: Optional[SecurityPolicy] = None
    """SecurityPolicy object create from security_policy"""

    def getSecurityPolicy(self) -> Optional[SecurityPolicy]:
        """Get the SecurityPolicy created from the security policy file,
        if available"""
        if self.security_policy and not self._security_policy:
            self._security_policy = SecurityPolicy.from_file(
                self.security_policy)
        return self._security_policy
