"""Global-only LLM gateway for joined clients."""

from __future__ import annotations

import os

from fastapi import HTTPException, status

from threat_intel.policy_engine import can_use_llm
from threat_intel.sharing_policy import load_sharing_policy


def investigate_with_llm(client_id: str, ioc: str, ioc_type: str) -> dict:
    if os.getenv("STINGAR_ENABLE_LLM", "false").lower() == "true":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="LLM access is disabled on local nodes. Use the central LLM gateway.",
        )

    policy = load_sharing_policy(client_id)
    if not can_use_llm(client_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "LLM access requires global_joined=true in the client sharing policy. "
                f"Current deployment_mode={policy.get('deployment_mode')}."
            ),
        )

    from main import run_threat_intel_agent

    analysis, tool_calls = run_threat_intel_agent(ioc, ioc_type)
    return {
        "client_id": client_id,
        "ioc": ioc,
        "ioc_type": ioc_type,
        "analysis": analysis,
        "tool_calls": tool_calls,
    }
