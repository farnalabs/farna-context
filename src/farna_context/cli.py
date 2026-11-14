"""CLI entry point for Farna Context."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .audit import audit_sources
from .compile import compile_context_pack
from .config import LocalConfig, load_config, save_config
from .constants import CONFIG_FILE, ExitCode, OutcomeStatus, RequestedBy
from .git import GitError, get_repo_root, get_revision
from .manifest import generate_manifest
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
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output")] = False,
) -> None:
    """Audit source files based on configuration."""
    try:
        config, repo_root = _get_config_and_repo(config_path)

        console.print(f"[bold]Repository:[/bold] {repo_root}")
        console.print(f"[bold]Config:[/bold] {config_path or 'default'}")

        audit_result = audit_sources(config, repo_root)

        # Summary table
        table = Table(title="Audit Results")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="magenta")
        table.add_row("Instruction files", str(len(audit_result.instruction_files)))
        table.add_row("Explicit files", str(len(audit_result.explicit_files)))
        table.add_row("Skills files", str(len(audit_result.skills_files)))
        table.add_row("Scoped files", str(len(audit_result.scoped_files)))
        table.add_row("Missing required", str(len(audit_result.missing_required)))
        table.add_row("Errors", str(len(audit_result.errors)))
        console.print(table)

        if verbose:
            if audit_result.instruction_files:
                console.print("\n[bold]Instruction files:[/bold]")
                for f in audit_result.instruction_files:
                    console.print(f"  {f.relative_to(repo_root)}")

            if audit_result.missing_required:
                console.print("\n[bold red]Missing required:[/bold red]")
                for m in audit_result.missing_required:
                    console.print(f"  {m}")

            if audit_result.errors:
                console.print("\n[bold red]Errors:[/bold red]")
                for e in audit_result.errors:
                    console.print(f"  {e}")

    except GitError as e:
        _handle_git_error(e)
    except Exception as e:
        _handle_generic_error(e, ExitCode.CONFIG_ERROR)


@app.command()
def manifest(
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to config file")
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file path")] = None,
) -> None:
    """Generate manifest from audited sources."""
    try:
        config, repo_root = _get_config_and_repo(config_path)
        revision = get_revision(repo_root)

        audit_result = audit_sources(config, repo_root)
        manifest_obj = generate_manifest(config, audit_result, repo_root, revision)

        output_path = output or Path(config.output_files.manifest)
        manifest_obj.save(output_path)

        console.print(f"[green]Manifest written to {output_path}[/green]")

    except GitError as e:
        _handle_git_error(e)
    except Exception as e:
        _handle_generic_error(e, ExitCode.MANIFEST_ERROR)


@app.command()
def compile(
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to config file")
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file path")] = None,
) -> None:
    """Compile context pack from audited sources."""
    try:
        config, repo_root = _get_config_and_repo(config_path)
        revision = get_revision(repo_root)

        audit_result = audit_sources(config, repo_root)
        context_pack = compile_context_pack(config, audit_result, repo_root, revision)

        output_path = output or Path(config.output_files.context_pack)
        context_pack.create(output_path)

        console.print(f"[green]Context pack written to {output_path}[/green]")
        console.print(f"[bold]Size:[/bold] {context_pack.get_size()} bytes (approx)")

    except GitError as e:
        _handle_git_error(e)
    except Exception as e:
        _handle_generic_error(e, ExitCode.COMPILATION_ERROR)


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

        audit_result = audit_sources(config, repo_root)

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

        audit_result = audit_sources(config, repo_root)
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

        audit_result = audit_sources(config, repo_root)
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

        audit_result = audit_sources(config, repo_root)
        result = scan_sources(audit_result, config.secret_patterns, repo_root)

        if result.has_secrets():
            console.print(
                f"[red]Found {len(result.findings)} potential secret(s) in "
                f"{result.scanned_files} files[/red]"
            )
            for finding in result.findings:
                rel_path = finding.file_path.relative_to(repo_root)
                console.print(f"  {rel_path}:{finding.line_number} - {finding.matched_text[:80]}")
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
