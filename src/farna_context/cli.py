"""CLI entry point for Farna Context."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from .audit import AuditContext, audit_sources, collect_audit_result, run_audit
from .compile import compile_manifest
from .config import LocalConfig, load_config, save_config
from .constants import CONFIG_FILE, ExitCode, OutcomeStatus, RequestedBy
from .exceptions import (
    CompilationError,
    InputChangedError,
    InvalidManifestError,
    RequiredSourceError,
    SecretDetectedError,
)
from .git import GitError, get_repo_root, get_revision
from .manifest import generate_manifest, run_manifest
from .materialise import materialise_files, materialise_to_stdout
from .receipt import generate_receipt
from .secrets import scan_sources
from .verify import verify_all

app = typer.Typer(
    name="farna-context",
    help="Farna Context - Context Pack compilation and verification",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


def _get_config_and_repo(config_path: Path | None = None) -> tuple[LocalConfig, Path]:
    """Load config and determine repo root."""
    if config_path is None:
        cwd = Path.cwd()
        for parent in [cwd] + list(cwd.parents):
            candidate = parent / CONFIG_FILE
            if candidate.exists():
                config_path = candidate
                break

    if config_path is None:
        config = LocalConfig()
        repo_root = get_repo_root(Path.cwd())
    else:
        config = load_config(config_path)
        repo_root = config.get_repo_root_path(config_path.parent)

    return config, repo_root


def _exit_with_error(exit_code: ExitCode) -> None:
    """Exit with the given error code."""
    raise typer.Exit(exit_code)


def _handle_git_error(e: GitError) -> None:
    """Handle GitError by printing and exiting."""
    console.print(f"[red]Git error: {e}[/red]")
    _exit_with_error(e.exit_code)


def _handle_generic_error(e: Exception, exit_code: ExitCode) -> None:
    """Handle generic exception by printing and exiting."""
    console.print(f"[red]Error: {e}[/red]")
    _exit_with_error(exit_code)


@app.command()
def init(
    repo_root: Annotated[
        Path | None, typer.Option("--repo-root", "-r", help="Repository root path")
    ] = None,
    force: Annotated[bool, typer.Option("--force", "-f", help="Overwrite existing config")] = False,
) -> None:
    """Initialize a new Farna Context configuration."""
    repo_root = Path.cwd() if repo_root is None else repo_root.resolve()

    config_path = repo_root / CONFIG_FILE

    if config_path.exists() and not force:
        console.print(
            f"[red]Config already exists at {config_path}. Use --force to overwrite.[/red]"
        )
        _exit_with_error(ExitCode.CONFIG_ERROR)

    config = LocalConfig(repo_root=".")
    config_path.parent.mkdir(parents=True, exist_ok=True)
    save_config(config, config_path)

    console.print(f"[green]Created config at {config_path}[/green]")


@app.command()
def audit(
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to config file")
    ] = None,
    out_path: Annotated[Path | None, typer.Option("--out", help="Path for audit.json")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output")] = False,
) -> None:
    """Audit source files and write audit.json."""
    del verbose
    resolved_config = config_path or (Path.cwd() / CONFIG_FILE)
    resolved_out = out_path or (resolved_config.parent / "audit.json")
    exit_code = run_audit(resolved_config, resolved_out)
    console.print(f"Audit output: {resolved_out}")
    if exit_code:
        _exit_with_error(
            ExitCode(exit_code) if exit_code in {0, 2, 10, 11} else ExitCode.CONFIG_ERROR
        )


@app.command()
def manifest(
    audit_path: Annotated[Path | None, typer.Option("--audit")] = None,
    output: Annotated[
        Path | None, typer.Option("--out", "--output", "-o", help="Output manifest path")
    ] = None,
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to config file")
    ] = None,
) -> None:
    """Generate a canonical JSON manifest from an audit JSON file."""
    try:
        exit_code = 0
        if audit_path is not None:
            output_path = output or Path(".farna-context/manifest.json")
            exit_code = run_manifest(audit_path, output_path)
            if exit_code == 0:
                console.print(f"[green]Manifest written to {output_path}[/green]")
            elif exit_code == int(ExitCode.REPO_NOT_FOUND):
                console.print("[red]Manifest blocked by source issues in audit[/red]")
            elif exit_code == int(ExitCode.DIRTY_TREE):
                console.print("[red]Audit input changed since it was recorded[/red]")
            else:
                console.print("[red]Invalid audit[/red]")
        if audit_path is not None:
            if exit_code:
                _exit_with_error(
                    ExitCode(exit_code) if exit_code in {0, 2, 10, 11} else ExitCode.MANIFEST_ERROR
                )
            return

        config, repo_root = _get_config_and_repo(config_path)
        revision = get_revision(repo_root)
        sources = audit_sources(config, repo_root)
        audit_result = collect_audit_result(
            AuditContext(
                config=config,
                repo_root=repo_root,
                revision=revision,
                sources=sources,
                task_brief_hash="",
                config_hash="",
            )
        )
        manifest_obj = generate_manifest(config, audit_result, repo_root, revision)
        output_path = output or Path(config.output_files.manifest)
        manifest_obj.save(output_path)
        console.print(f"[green]Manifest written to {output_path}[/green]")
    except GitError as e:
        _handle_git_error(e)
    except typer.Exit:
        raise
    except Exception as e:
        _handle_generic_error(e, ExitCode.MANIFEST_ERROR)


@app.command()
def compile(
    manifest_path: Annotated[
        Path, typer.Option("--manifest", help="Manifest JSON path", exists=True, readable=True)
    ],
    output: Annotated[Path, typer.Option("--out", "--output", "-o", help="Pack JSON path")],
    config_path: Annotated[
        Path, typer.Option("--config", "-c", help="Config JSON path", exists=True, readable=True)
    ],
) -> None:
    """Compile a deterministic Context Pack from a manifest."""
    try:
        pack = compile_manifest(manifest_path, output, config_path)
        console.print(f"Context pack written to {output}")
        console.print(f"Pack hash: {pack.pack_hash}")
    except InputChangedError as exc:
        console.print(str(exc))
        _exit_with_error(ExitCode.INPUT_CHANGED)
    except SecretDetectedError as exc:
        console.print(str(exc))
        _exit_with_error(ExitCode.SECRET_DETECTED)
    except InvalidManifestError as exc:
        console.print(f"Error: {exc}")
        _exit_with_error(ExitCode.INVALID_ARGS)
    except RequiredSourceError as exc:
        console.print(f"Error: {exc}")
        _exit_with_error(ExitCode.REQUIRED_ISSUE)
    except CompilationError as exc:
        console.print(f"Error: {exc}")
        _exit_with_error(ExitCode.REQUIRED_ISSUE)
    except OSError:
        console.print("Error: unable to write context pack")
        _exit_with_error(ExitCode.WRITE_ERROR)
    except Exception:
        console.print("Error: compilation failed")
        _exit_with_error(ExitCode.COMPILATION_ERROR)


@app.command()
def materialise(
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to config file")
    ] = None,
    output_dir: Annotated[
        Path | None, typer.Option("--output-dir", "-d", help="Output directory")
    ] = None,
    mode: Annotated[str, typer.Option("--mode", "-m", help="Materialisation mode")] = "files",
) -> None:
    """Materialise source files to output directory or stdout."""
    try:
        config, repo_root = _get_config_and_repo(config_path)
        revision = get_revision(repo_root)

        sources = audit_sources(config, repo_root)
        audit_context = AuditContext(
            config=config,
            repo_root=repo_root,
            revision=revision,
            sources=sources,
            task_brief_hash="",
            config_hash="",
        )
        audit_result = collect_audit_result(audit_context)

        if mode == "stdout":
            output = materialise_to_stdout(config, audit_result, repo_root)
            console.print(output)
        else:
            out_dir = output_dir or Path(config.staging_parent) / "materialised"
            result = materialise_files(config, audit_result, repo_root, out_dir, mode)

            msg = f"[green]Materialised {len(result.written_files)} files to {out_dir}[/green]"
            console.print(msg)

            if result.errors:
                console.print("[yellow]Errors:[/yellow]")
                for e in result.errors:
                    console.print(f"  {e}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        _exit_with_error(ExitCode.COMPILATION_ERROR)


@app.command()
def verify(
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to config file")
    ] = None,
) -> None:
    """Verify manifest and context pack integrity."""
    try:
        config, repo_root = _get_config_and_repo(config_path)
        revision = get_revision(repo_root)

        sources = audit_sources(config, repo_root)
        audit_context = AuditContext(
            config=config,
            repo_root=repo_root,
            revision=revision,
            sources=sources,
            task_brief_hash="",
            config_hash="",
        )
        audit_result = collect_audit_result(audit_context)
        result = verify_all(config, audit_result, repo_root, revision)

        if result.verified:
            console.print("[green]All verifications passed[/green]")
        else:
            console.print("[red]Verification failed[/red]")
            for m in result.mismatches:
                expected = m["expected_hash"][:16]
                actual = m["actual_hash"][:16]
                msg = f"  Mismatch: {m['file']} (expected: {expected}..., actual: {actual}...)"
                console.print(msg)
            for e in result.errors:
                console.print(f"  Error: {e}")
            _exit_with_error(ExitCode.VERIFICATION_ERROR)

    except GitError as e:
        _handle_git_error(e)
    except typer.Exit:
        raise
    except Exception as e:
        _handle_generic_error(e, ExitCode.VERIFICATION_ERROR)


@app.command()
def receipt(
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to config file")
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file path")] = None,
    requested_by: Annotated[
        str, typer.Option("--requested-by", help="Who requested the operation")
    ] = "human",
    outcome: Annotated[str, typer.Option("--outcome", help="Operation outcome")] = "success",
) -> None:
    """Generate operation receipt."""
    try:
        config, repo_root = _get_config_and_repo(config_path)
        revision = get_revision(repo_root)

        sources = audit_sources(config, repo_root)
        audit_context = AuditContext(
            config=config,
            repo_root=repo_root,
            revision=revision,
            sources=sources,
            task_brief_hash="",
            config_hash="",
        )
        audit_result = collect_audit_result(audit_context)
        manifest_obj = generate_manifest(config, audit_result, repo_root, revision)

        receipt_obj = generate_receipt(
            config=config,
            audit=audit_result,
            manifest=manifest_obj,
            revision=revision,
            requested_by=RequestedBy(requested_by),
            outcome=OutcomeStatus(outcome),
        )

        output_path = output or Path(config.output_files.receipt)
        receipt_obj.save(output_path)

        console.print(f"[green]Receipt written to {output_path}[/green]")

    except GitError as e:
        _handle_git_error(e)
    except Exception as e:
        _handle_generic_error(e, ExitCode.CONFIG_ERROR)


@app.command()
def secrets(
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to config file")
    ] = None,
) -> None:
    """Scan source files for secrets."""
    try:
        config, repo_root = _get_config_and_repo(config_path)
        revision = get_revision(repo_root)

        sources = audit_sources(config, repo_root)
        audit_context = AuditContext(
            config=config,
            repo_root=repo_root,
            revision=revision,
            sources=sources,
            task_brief_hash="",
            config_hash="",
        )
        audit_result = collect_audit_result(audit_context)
        source_bytes = [(str(path), path.read_bytes()) for path in audit_result.instruction_files]
        result = scan_sources(source_bytes, config.secret_patterns)

        if result.has_secrets():
            console.print(
                f"[red]Found {len(result.findings)} potential secret(s) in "
                f"{result.scanned_files} files[/red]"
            )
            for finding in result.findings:
                console.print(f"  {finding.path} - {finding.detector}")
            _exit_with_error(ExitCode.SECRET_DETECTED)

        console.print(f"[green]No secrets found in {result.scanned_files} files[/green]")

        if result.errors:
            console.print("[yellow]Scan errors:[/yellow]")
            for e in result.errors:
                console.print(f"  {e}")

    except typer.Exit:
        raise
    except Exception as e:
        _handle_generic_error(e, ExitCode.CONFIG_ERROR)


@app.callback()
def callback() -> None:
    """Farna Context - Context Pack compilation and verification."""
    pass


def main() -> None:
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
