"""Composable boundaries for the isolated Free Camoufox registration chain.

The package is safe to import without Camoufox installed.  The historical
`free_camoufox_runtime` module remains the compatibility entry point while new
code can depend on these smaller contracts and services.
"""

from .contracts import (
    CamoufoxFlowCheckpoint,
    CamoufoxFlowContext,
    CamoufoxFlowState,
    CamoufoxPoolSnapshot,
    CamoufoxRegistrationRequest,
    CamoufoxRegistrationResult,
    normalize_flow_state,
)
from .errors import (
    browser_process_lost,
    is_transient_navigation_error,
    mark_recycle_required,
    navigation_diagnostic,
    navigation_failure_category,
    navigation_failure_reason,
)
from .browser_pool import BrowserPoolGateway
from .debug_artifacts import DebugArtifactService, DebugEventBuffer
from .runner import CamoufoxRunner
from .state_machine import (
    CamoufoxFlowCoordinator,
    CamoufoxStateMachine,
    FlowWaitResult,
    InvalidTransitionError,
    StateTransition,
)
from .transport import CamoufoxTransport, CamoufoxTransportError, PageTransportContract


def __getattr__(name: str):
    """Resolve compatibility classes without importing the legacy runtime eagerly."""

    if name == "CamoufoxRegistrationRunner":
        from . import runner
        return getattr(runner, name)
    if name == "CamoufoxBrowserPool":
        from . import browser_pool
        return getattr(browser_pool, name)
    if name in {"CamoufoxBrowserError", "CamoufoxDependencyError"}:
        from . import errors
        return getattr(errors, name)
    raise AttributeError(name)

__all__ = [
    "CamoufoxFlowCheckpoint",
    "CamoufoxFlowContext",
    "CamoufoxFlowState",
    "CamoufoxPoolSnapshot",
    "CamoufoxBrowserError",
    "CamoufoxBrowserPool",
    "CamoufoxDependencyError",
    "BrowserPoolGateway",
    "DebugArtifactService",
    "DebugEventBuffer",
    "CamoufoxRegistrationRequest",
    "CamoufoxRegistrationRunner",
    "CamoufoxRegistrationResult",
    "CamoufoxRunner",
    "CamoufoxStateMachine",
    "CamoufoxFlowCoordinator",
    "FlowWaitResult",
    "CamoufoxTransport",
    "CamoufoxTransportError",
    "InvalidTransitionError",
    "PageTransportContract",
    "StateTransition",
    "browser_process_lost",
    "is_transient_navigation_error",
    "mark_recycle_required",
    "navigation_diagnostic",
    "navigation_failure_category",
    "navigation_failure_reason",
    "normalize_flow_state",
]
