"""__init__ for the llm router package."""
from .router import (
    Router,
    RouteConfig,
    TASK_CODE_REVIEW,
    TASK_DESIGN_REVIEW,
    TASK_SECURITY_REVIEW,
    TASK_FAST_QA,
    TASK_GENERAL,
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
