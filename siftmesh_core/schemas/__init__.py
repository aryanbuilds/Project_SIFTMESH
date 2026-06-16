"""Pydantic v2 schemas + JSON-Schema export (Epic C).

The typed contract layer: provenance (C1), the claim firewall (C2), task
contracts (C3), tool/critic/run types (C4), agent + workflow config (C5),
evidence manifest (C6), and custody events (C10). :func:`export_json_schemas`
emits a JSON Schema per model (C8) for docs + external-agent contract validation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from siftmesh_core.schemas._base import StrictModel
from siftmesh_core.schemas.agent_call import AgentCall, AgentCallStatus
from siftmesh_core.schemas.agent_profile import (
    AgentKind,
    AgentProfile,
    CostClass,
    ModelTier,
    OutputFormat,
)
from siftmesh_core.schemas.agent_token_usage import AgentTokenUsage
from siftmesh_core.schemas.audit import CriticVerdict, CriticVerdictType, ToolCall
from siftmesh_core.schemas.claim import Claim, ClaimStatus, validate_claim_evidence
from siftmesh_core.schemas.critic_records import (
    ConfidenceChange,
    ContradictionRecord,
    ContradictionRule,
    FollowupRecord,
    RetryRecord,
)
from siftmesh_core.schemas.custody import CustodyEvent, CustodyEventType
from siftmesh_core.schemas.decision import Decision, DecisionAction
from siftmesh_core.schemas.evidence import EvidenceFile, EvidenceManifest
from siftmesh_core.schemas.injection_alert import InjectionAlert
from siftmesh_core.schemas.plan import InvestigationPlan, PlanStep, PlanStepKind
from siftmesh_core.schemas.protocol_sift import CapabilityCheck, ProtocolSiftCapabilityMap
from siftmesh_core.schemas.run import (
    GateName,
    GateStatus,
    PerTaskState,
    RunMode,
    RunState,
    RunStateName,
)
from siftmesh_core.schemas.task import (
    ArtifactMode,
    ArtifactOrigin,
    InputArtifact,
    RetryPolicy,
    SafetyPolicy,
    TaskContract,
)
from siftmesh_core.schemas.task_result import TaskResult, TaskResultStatus
from siftmesh_core.schemas.tool_result import ToolResult, ToolStatus
from siftmesh_core.schemas.workflow import (
    StageName,
    Workflow,
    WorkflowLimits,
    WorkflowMode,
    WorkflowSafety,
)

# Every exportable model, keyed by class name (the external contract surface).
_EXPORTED_MODELS: tuple[type[StrictModel], ...] = (
    ToolResult,
    Claim,
    TaskContract,
    InputArtifact,
    RetryPolicy,
    SafetyPolicy,
    ToolCall,
    CriticVerdict,
    RunState,
    PerTaskState,
    AgentProfile,
    Workflow,
    WorkflowLimits,
    WorkflowSafety,
    EvidenceFile,
    EvidenceManifest,
    CustodyEvent,
    ProtocolSiftCapabilityMap,
    CapabilityCheck,
    InvestigationPlan,
    PlanStep,
    TaskResult,
    AgentCall,
    AgentTokenUsage,
    InjectionAlert,
    ContradictionRecord,
    ConfidenceChange,
    RetryRecord,
    FollowupRecord,
    Decision,
)


def export_json_schemas() -> dict[str, dict[str, Any]]:
    """Return ``{model_name: JSON Schema}`` for every Epic-C model (C8)."""
    return {model.__name__: model.model_json_schema() for model in _EXPORTED_MODELS}


def write_json_schemas(out_dir: Path | str) -> list[Path]:
    """Write one ``<Model>.schema.json`` per model into ``out_dir`` (docs export)."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, schema in export_json_schemas().items():
        target = directory / f"{name}.schema.json"
        target.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(target)
    return written


__all__ = [
    "AgentCall",
    "AgentCallStatus",
    "AgentKind",
    "AgentProfile",
    "AgentTokenUsage",
    "ArtifactMode",
    "ArtifactOrigin",
    "CapabilityCheck",
    "Claim",
    "ClaimStatus",
    "ConfidenceChange",
    "ContradictionRecord",
    "ContradictionRule",
    "CostClass",
    "CriticVerdict",
    "CriticVerdictType",
    "CustodyEvent",
    "CustodyEventType",
    "Decision",
    "DecisionAction",
    "EvidenceFile",
    "EvidenceManifest",
    "FollowupRecord",
    "GateName",
    "GateStatus",
    "InjectionAlert",
    "InputArtifact",
    "InvestigationPlan",
    "ModelTier",
    "OutputFormat",
    "PerTaskState",
    "PlanStep",
    "PlanStepKind",
    "ProtocolSiftCapabilityMap",
    "RetryPolicy",
    "RetryRecord",
    "RunMode",
    "RunState",
    "RunStateName",
    "SafetyPolicy",
    "StageName",
    "TaskContract",
    "TaskResult",
    "TaskResultStatus",
    "ToolCall",
    "ToolResult",
    "ToolStatus",
    "Workflow",
    "WorkflowLimits",
    "WorkflowMode",
    "WorkflowSafety",
    "export_json_schemas",
    "validate_claim_evidence",
    "write_json_schemas",
]
