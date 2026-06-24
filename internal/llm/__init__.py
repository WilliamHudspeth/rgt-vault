"""__init__ for the llm router package."""

from .router import (
    TASK_CODE_REVIEW,
    TASK_DESIGN_REVIEW,
    TASK_FAST_QA,
    TASK_GENERAL,
    TASK_SECURITY_REVIEW,
    RouteConfig,
    Router,
)

__all__ = [
    "Router",
    "RouteConfig",
    "TASK_CODE_REVIEW",
    "TASK_DESIGN_REVIEW",
    "TASK_SECURITY_REVIEW",
    "TASK_FAST_QA",
    "TASK_GENERAL",
]
