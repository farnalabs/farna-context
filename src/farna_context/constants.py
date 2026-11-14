"""Constants, exit codes, and enums for Farna Context."""

from enum import Enum, StrEnum


class ExitCode(int, Enum):
    """Stable command exit codes."""

    OK = 0
    INVALID_ARGS = 2
    CONFIG_ERROR = 2
    GIT_ERROR = 4
    REQUIRED_ISSUE = 10
    INPUT_CHANGED = 11
    SECRET_DETECTED = 12
    DESTINATION_ERROR = 13
    WRITE_ERROR = 14
    VERIFICATION_ERROR = 15
    RECEIPT_ERROR = 16
    REPO_NOT_FOUND = 10
    DIRTY_TREE = 11
    SCOPE_VIOLATION = 12
    MANIFEST_ERROR = 2
    COMPILATION_ERROR = 10


class RequestedBy(StrEnum):
    """Who requested the operation."""

    HUMAN = "human"
    AGENT = "agent"
    SCHEDULED = "scheduled"
    WEBHOOK = "webhook"


class MaterialisationMode(StrEnum):
    """How context is materialised."""

    FILES = "files"
    STDIN = "stdin"
    STDOUT = "stdout"
    API = "api"


class HarnessLoadMode(StrEnum):
    """Harness load mode."""

    IMPORT = "import"
    SUBPROCESS = "subprocess"
    CLI = "cli"
    MCP = "mcp"


class ModelUseMode(StrEnum):
    """Model use mode."""

    SYNC = "sync"
    ASYNC = "async"
    STREAM = "stream"
    BATCH = "batch"


class OutcomeStatus(StrEnum):
    """Outcome state."""

    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    CANCELLED = "cancelled"


class EvidenceOrigin(StrEnum):
    """Evidence provenance."""

    DIRECT = "direct"
    DERIVED = "derived"
    OBSERVED = "observed"
    SELF_REPORTED = "self_reported"
    REPORTED = "reported"
    UNOBSERVED = "unobserved"


HARNESS_FIXTURE = "opencode"
CONFIG_FILE = ".farna-context/config.json"
MANIFEST_FILE = "manifest.json"
CONTEXT_PACK_FILE = "pack.json"
RECEIPT_FILE = "receipt.json"
