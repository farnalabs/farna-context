"""Constants, exit codes, and enums for Farna Context."""

from enum import Enum, StrEnum


# Exit codes
class ExitCode(int, Enum):
    """Process exit codes."""

    OK = 0
    INVALID_ARGS = 2
    CONFIG_ERROR = 3
    GIT_ERROR = 4
    REPO_NOT_FOUND = 10
    DIRTY_TREE = 11
    SCOPE_VIOLATION = 12
    SECRET_DETECTED = 13
    MANIFEST_ERROR = 14
    COMPILATION_ERROR = 15
    VERIFICATION_ERROR = 16


# Receipt enums
class RequestedBy(StrEnum):
    """Who/what requested the operation."""

    HUMAN = "human"
    AGENT = "agent"
    SCHEDULED = "scheduled"
    WEBHOOK = "webhook"


class MaterialisationMode(StrEnum):
    """How the context was materialised."""

    FILES = "files"
    STDIN = "stdin"
    STDOUT = "stdout"
    API = "api"


class HarnessLoadMode(StrEnum):
    """How the harness was loaded."""

    IMPORT = "import"
    SUBPROCESS = "subprocess"
    CLI = "cli"
    MCP = "mcp"


class ModelUseMode(StrEnum):
    """How the model was used."""

    SYNC = "sync"
    ASYNC = "async"
    STREAM = "stream"
    BATCH = "batch"


class OutcomeStatus(StrEnum):
    """Outcome of the operation."""

    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    CANCELLED = "cancelled"


class EvidenceOrigin(StrEnum):
    """Origin of evidence in receipt."""

    DIRECT = "direct"
    DERIVED = "derived"
    OBSERVED = "observed"
    SELF_REPORTED = "self_reported"


# Fixture constants
HARNESS_FIXTURE = "opencode"


# File names
CONFIG_FILE = ".farna-context/config.json"
MANIFEST_FILE = "manifest.yaml"
CONTEXT_PACK_FILE = "context_pack.zip"
RECEIPT_FILE = "receipt.json"
