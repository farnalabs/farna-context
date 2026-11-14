"""Compilation exceptions."""


class CompilationError(ValueError):
    """Base error for invalid or unsafe compilation inputs."""


class InvalidManifestError(CompilationError):
    """Manifest does not satisfy the compiler contract."""


class InputChangedError(CompilationError):
    """A snapshotted input changed before finalisation."""


class SecretDetectedError(CompilationError):
    """A configured or named secret detector matched source material."""
