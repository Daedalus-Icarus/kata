from __future__ import annotations

from kata import validator_system as _validator_system
from kata.promotion_system import LanePromotionResult
from kata.promotion_system import (
    find_evaluator_pack_entry as find_evaluator_pack_entry,
)
from kata.promotion_system import (
    promote_lane_king as promote_lane_king,
)
from kata.promotion_system import (
    resolve_sn60_king_artifact as resolve_sn60_king_artifact,
)
from kata.promotion_system import (
    resolve_sn60_lane_king_hash as resolve_sn60_lane_king_hash,
)
from kata.promotion_system import (
    validate_submission_lane as validate_submission_lane,
)
from kata.screening_system.rules import (
    find_bundle_symlink_paths as find_bundle_symlink_paths,
)
from kata.screening_system.rules import (
    hash_submission_bundle as hash_submission_bundle,
)
from kata.submission_system import (
    DEFAULT_AGENT_PLACEHOLDER,
    PR_ACTION_CLOSE_INVALID,
    PR_ACTION_CLOSE_LOSING,
    PR_ACTION_EVALUATE,
    PR_ACTION_MERGE,
    PR_ACTION_RERUN_STALE,
    SUBMISSION_AGENT_FILENAME,
    SUBMISSION_AGENT_MANIFEST_FILENAME,
    SUBMISSION_METADATA_FILENAME,
    SUBMISSION_SCHEMA_VERSION,
    SUPPORTED_SUBMISSION_MODES,
    PullRequestInspectionResult,
    SubmissionCandidateValidation,
    SubmissionDecisionResult,
    SubmissionMetadata,
    SubmissionValidationResult,
    SubmissionVerificationResult,
    agent_defines_required_entrypoint,
    default_submission_agent,
    default_submission_notes,
    default_submissions_root,
    infer_submission_dirs,
    load_submission_metadata,
    normalize_changed_paths,
    read_changed_paths_file,
    render_pull_request_inspection,
    render_submission_decision,
    render_submission_json,
    render_submission_validation,
    render_submission_verification,
    required_submission_entrypoint_reason,
    resolve_submission_descriptor,
    validate_changed_paths,
    validate_submission_candidate,
    validate_submission_metadata,
    validate_submission_mode,
    write_submission_metadata,
)
from kata.submission_system.workflow import (
    decide_submission_action,
    evaluate_submission,
    init_submission,
    inspect_pull_request,
    is_sn60_miner_metadata,
    promote_submission_result,
    sn60_lane_benchmark_is_current,
    validate_submission,
    validate_submission_target,
    verify_submission_result,
)

SN60_PROJECT_SAMPLE_SECRET_ENV = _validator_system.SN60_PROJECT_SAMPLE_SECRET_ENV
SN60_PROJECT_SAMPLE_SIZE_ENV = _validator_system.SN60_PROJECT_SAMPLE_SIZE_ENV
SN60_VALIDATOR_MODEL = _validator_system.SN60_VALIDATOR_MODEL
ChallengeSummary = _validator_system.ChallengeSummary
load_challenge_summary = _validator_system.load_challenge_summary
parse_sn60_project_keys_from_env = _validator_system.parse_sn60_project_keys_from_env
parse_sn60_project_sample_size_from_env = (
    _validator_system.parse_sn60_project_sample_size_from_env
)
resolve_sn60_project_keys = _validator_system.resolve_sn60_project_keys
run_sn60_challenge = _validator_system.run_sn60_challenge
sample_sn60_project_keys = _validator_system.sample_sn60_project_keys

__all__ = [
    "DEFAULT_AGENT_PLACEHOLDER",
    "PR_ACTION_CLOSE_INVALID",
    "PR_ACTION_CLOSE_LOSING",
    "PR_ACTION_EVALUATE",
    "PR_ACTION_MERGE",
    "PR_ACTION_RERUN_STALE",
    "SUBMISSION_AGENT_FILENAME",
    "SUBMISSION_AGENT_MANIFEST_FILENAME",
    "SUBMISSION_METADATA_FILENAME",
    "SUBMISSION_SCHEMA_VERSION",
    "SUPPORTED_SUBMISSION_MODES",
    "SN60_PROJECT_SAMPLE_SECRET_ENV",
    "SN60_PROJECT_SAMPLE_SIZE_ENV",
    "SN60_VALIDATOR_MODEL",
    "ChallengeSummary",
    "LanePromotionResult",
    "PullRequestInspectionResult",
    "SubmissionCandidateValidation",
    "SubmissionDecisionResult",
    "SubmissionMetadata",
    "SubmissionValidationResult",
    "SubmissionVerificationResult",
    "agent_defines_required_entrypoint",
    "decide_submission_action",
    "default_submission_agent",
    "default_submission_notes",
    "default_submissions_root",
    "evaluate_submission",
    "find_evaluator_pack_entry",
    "find_bundle_symlink_paths",
    "hash_submission_bundle",
    "infer_submission_dirs",
    "init_submission",
    "inspect_pull_request",
    "is_sn60_miner_metadata",
    "load_submission_metadata",
    "load_challenge_summary",
    "normalize_changed_paths",
    "parse_sn60_project_keys_from_env",
    "parse_sn60_project_sample_size_from_env",
    "promote_lane_king",
    "promote_submission_result",
    "read_changed_paths_file",
    "render_pull_request_inspection",
    "render_submission_decision",
    "render_submission_json",
    "render_submission_validation",
    "render_submission_verification",
    "required_submission_entrypoint_reason",
    "resolve_submission_descriptor",
    "resolve_sn60_king_artifact",
    "resolve_sn60_lane_king_hash",
    "resolve_sn60_project_keys",
    "run_sn60_challenge",
    "sample_sn60_project_keys",
    "sn60_lane_benchmark_is_current",
    "validate_changed_paths",
    "validate_submission",
    "validate_submission_candidate",
    "validate_submission_lane",
    "validate_submission_metadata",
    "validate_submission_mode",
    "validate_submission_target",
    "verify_submission_result",
    "write_submission_metadata",
]
