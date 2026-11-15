"""CLI entry point for Farna Context."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from .audit import AuditContext, AuditResult, audit_sources, collect_audit_result, run_audit
from .compile import _load_json, compile_manifest
from .config import LocalConfig, SecretPatterns, load_config, save_config
from .constants import CONFIG_FILE, ExitCode, OutcomeStatus, RequestedBy
from .exceptions import (
    CompilationError,
    InputChangedError,
    InvalidManifestError,
    RequiredSourceError,
    SecretDetectedError,
)
from .git import GitError, check_dirty_tree, get_repo_root, get_revision
from .manifest import generate_manifest, run_manifest
from .materialise import (
    materialise_files,
    materialise_pack,
    materialise_to_stdout,
    materialise_typed_context,
)
from .receipt import generate_receipt, load_receipt_artefact
from .secrets import scan_sources
from .typed_context import (
    compile_typed_context,
    load_typed_context_manifest,
    preview_typed_context_data,
)
from .utils import atomic_write_bytes, canonical_json_bytes
from .verify import verify_all

app = typer.Typer(
    name="farna-context",
    help="Farna Context - Context Pack compilation and verification",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


def _find_config_path() -> Path | None:
    """Find the nearest project configuration from the current directory."""
    cwd = Path.cwd()
    for parent in [cwd] + list(cwd.parents):
        candidate = parent / CONFIG_FILE
        if candidate.exists():
            return candidate
    return None


def _config_repo_base(config_path: Path) -> Path:
    """Return the repository base used by config paths in every command."""
    config_dir = config_path.parent
    return config_dir.parent if config_dir.name == ".farna-context" else config_dir


def _get_config_and_repo(config_path: Path | None = None) -> tuple[LocalConfig, Path]:
    """Load config and determine repo root consistently for every command."""
    resolved_config = config_path or _find_config_path()
    if resolved_config is None:
        config = LocalConfig()
        repo_root = get_repo_root(Path.cwd())
    else:
        config = load_config(resolved_config)
        repo_root = config.get_repo_root_path(_config_repo_base(resolved_config))
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


def _raise_init_error(message: str) -> None:
    """Raise a validation error for init inputs."""
    raise ValueError(message)  # noqa: TRY003


@app.command()
def init(  # noqa: PLR0913, PLR0917
    repo: Annotated[
        Path | None, typer.Option("--repo", "--repo-root", "-r", help="Repository root path")
    ] = None,
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="Config file path")
    ] = None,
    task: Annotated[Path | None, typer.Option("--task", help="Task brief file path")] = None,
    staging_parent: Annotated[
        Path | None, typer.Option("--staging-parent", help="Staging parent directory")
    ] = None,
    out: Annotated[Path | None, typer.Option("--out", help="Init record output path")] = None,
    force: Annotated[bool, typer.Option("--force", "-f", help="Overwrite existing config")] = False,
) -> None:
    """Initialize Farna Context and write its init record."""
    try:
        if repo is None:
            repo = Path.cwd()
        repo_root = repo.resolve()
        if config_path is None:
            config_path = repo_root / CONFIG_FILE
        if task is None or staging_parent is None or out is None:
            if task is None and staging_parent is None and out is None:
                config_path.parent.mkdir(parents=True, exist_ok=True)
                if config_path.exists() and not force:
                    console.print(
                        f"[red]Config already exists at {config_path}. "
                        "Use --force to overwrite.[/red]"
                    )
                    _exit_with_error(ExitCode.CONFIG_ERROR)
                save_config(LocalConfig(repo_root="."), config_path)
                console.print(f"[green]Created config at {config_path}[/green]")
                return
            _raise_init_error("--task, --staging-parent, and --out must be provided together")
        assert config_path is not None
        assert task is not None
        assert staging_parent is not None
        assert out is not None
        config_path = config_path.resolve()
        task_path = task.resolve()
        staging_path = staging_parent.resolve()
        out = out.resolve()

        config = load_config(config_path)
        configured_repo = config.get_repo_root_path(_config_repo_base(config_path))
        if configured_repo != repo_root:
            _raise_init_error(
                f"Config repo_root {configured_repo} does not match --repo {repo_root}"
            )
        if not task_path.is_file():
            _raise_init_error(f"Task brief not found: {task_path}")
        staging_path.mkdir(parents=True, exist_ok=True)

        revision = get_revision(repo_root)
        dirty = bool(check_dirty_tree(repo_root))
        config_json = json.dumps(
            config.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )
        config_hash = hashlib.sha256(config_json.encode()).hexdigest()
        record = {
            "config_hash": config_hash,
            "repo_root": str(repo_root),
            "revision": revision,
            "task_brief_path": str(task_path),
            "staging_parent": str(staging_path),
            "dirty": dirty,
            "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "schema_version": "1.0",
        }
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        console.print(f"[green]Init record written to {out}[/green]")
    except GitError as e:
        _handle_git_error(e)
    except typer.Exit:
        raise
    except Exception as e:
        _handle_generic_error(e, ExitCode.CONFIG_ERROR)


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


@app.command("context-preview")
def context_preview(  # noqa: PLR0913, PLR0917
    input_path: Annotated[Path, typer.Option("--input", "-i", exists=True, readable=True)],
    repo_root: Annotated[
        Path | None, typer.Option("--repo-root", help="Trusted repository root")
    ] = None,
    policy_path: Annotated[
        Path | None, typer.Option("--policy", help="Secret policy/config JSON")
    ] = None,
    out: Annotated[Path | None, typer.Option("--out", help="Optional preview JSON path")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON output")] = False,
) -> None:
    """Preview typed context selection without writing source content."""
    try:
        manifest = load_typed_context_manifest(input_path)
        root = repo_root.resolve() if repo_root is not None else None
        patterns = _load_secret_patterns(policy_path)
        preview = preview_typed_context_data(manifest, repo_root=root, secret_patterns=patterns)
        if out is not None:
            atomic_write_bytes(out, canonical_json_bytes(preview))
        if as_json:
            console.print_json(json.dumps(preview))
        else:
            for decision in preview["decisions"]:
                console.print(
                    f"{decision['item_id']}: {decision['decision']} ({decision['reason']})"
                )
            if out is not None:
                console.print(f"Preview written to {out}")
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        console.print(f"Error: {exc}")
        _exit_with_error(ExitCode.INVALID_ARGS)


@app.command("context-compile")
def context_compile(  # noqa: PLR0913, PLR0917
    input_path: Annotated[Path, typer.Option("--input", "-i", exists=True, readable=True)],
    output: Annotated[Path, typer.Option("--out", "-o", help="Canonical typed pack JSON path")],
    config_path: Annotated[
        Path | None, typer.Option("--config", "--policy", exists=True, readable=True)
    ] = None,
    repo_root: Annotated[
        Path | None, typer.Option("--repo-root", help="Trusted repository root")
    ] = None,
    task: Annotated[Path | None, typer.Option("--task", exists=True, readable=True)] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON summary")] = False,
) -> None:
    """Compile typed context into an atomic canonical pack."""
    del repo_root, task
    try:
        pack = compile_typed_context(input_path, output, config_path=config_path)
        summary = {
            "pack_hash": pack.pack_hash,
            "out": str(output),
            "selected": len(pack.payload.get("items", [])),
            "omitted": len(pack.payload.get("omitted", [])),
            "secret_literal_detector_count": pack.payload.get("secret_literal_detector_count", 0),
        }
        if as_json:
            console.print_json(json.dumps(summary))
        else:
            console.print(f"Typed context pack written to {output}")
            console.print(f"Pack hash: {pack.pack_hash}")
    except ValueError as exc:
        message = str(exc)
        code = ExitCode.SECRET_DETECTED if "secret" in message.lower() else ExitCode.INVALID_ARGS
        console.print(f"Error: {message}")
        _exit_with_error(code)
    except OSError as exc:
        console.print(f"Error: {exc}")
        _exit_with_error(ExitCode.WRITE_ERROR)


def _load_secret_patterns(policy_path: Path | None) -> SecretPatterns:
    """Load trusted secret policy metadata for typed materialisation."""
    if policy_path is None:
        raise ValueError("Trusted secret policy is required")  # noqa: TRY003
    data, _ = _load_json(policy_path)
    raw = data.get("secret_patterns")
    if not isinstance(raw, dict):
        raise TypeError("Trusted secret policy must contain secret_patterns")  # noqa: TRY003
    return SecretPatterns.model_validate(raw)


@app.command("context-materialise")
def context_materialise(  # noqa: PLR0913, PLR0917
    pack_path: Annotated[Path, typer.Option("--pack", exists=True, readable=True)],
    policy_path: Annotated[Path, typer.Option("--policy", exists=True, readable=True)],
    repo_root: Annotated[Path, typer.Option("--repo-root", exists=True, file_okay=False)],
    staging_parent: Annotated[Path, typer.Option("--staging-parent")],
    out: Annotated[Path, typer.Option("--out", help="Receipt/result JSON path")],
    harness: Annotated[str, typer.Option("--harness")] = "opencode",
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON result")] = False,
) -> None:
    """Materialise a typed pack using an explicit trusted secret policy."""
    try:
        pack_data, _ = _load_json(pack_path)
        patterns = _load_secret_patterns(policy_path)
        result = materialise_typed_context(
            pack_data,
            repo_root=repo_root.resolve(),
            staging_parent=staging_parent.resolve(),
            harness=harness,
            secret_patterns=patterns,
        )
        atomic_write_bytes(out, canonical_json_bytes(result))
        if as_json:
            console.print_json(json.dumps(result))
        else:
            statuses: dict[str, int] = {}
            for outcome in result["outcomes"]:
                status = str(outcome["status"])
                statuses[status] = statuses.get(status, 0) + 1
            console.print(f"Materialisation result written to {out}")
            console.print(", ".join(f"{key}={value}" for key, value in sorted(statuses.items())))
    except (OSError, TypeError, ValueError) as exc:
        console.print(f"Error: {exc}")
        code = ExitCode.DESTINATION_ERROR if "Unsafe" in str(exc) else ExitCode.INVALID_ARGS
        _exit_with_error(code)


@app.command()
def materialise(  # noqa: PLR0913, PLR0917
    pack: Annotated[Path | None, typer.Option("--pack", help="Compiled context pack JSON")] = None,
    parent: Annotated[
        Path | None, typer.Option("--parent", help="Staging parent directory")
    ] = None,
    out: Annotated[Path | None, typer.Option("--out", help="Materialisation plan JSON")] = None,
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="Legacy config path")
    ] = None,
    output_dir: Annotated[
        Path | None, typer.Option("--output-dir", "-d", help="Legacy output directory")
    ] = None,
    mode: Annotated[str, typer.Option("--mode", "-m", help="Materialisation mode")] = "files",
) -> None:
    """Materialise a compiled pack using the signed-off pack/parent/out contract."""
    try:
        if pack is not None or parent is not None or out is not None:
            if pack is None or parent is None or out is None:
                _exit_with_error(ExitCode.INVALID_ARGS)
            assert pack is not None
            assert parent is not None
            assert out is not None
            plan = materialise_pack(pack, parent, out)
            console.print(
                f"[green]Materialised {len(plan['outputs'])} files to {plan['output_dir']}[/green]"
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
        if mode == "stdout":
            console.print(materialise_to_stdout(config, audit_result, repo_root))
            return
        out_dir = output_dir or Path(config.staging_parent) / "materialised"
        result = materialise_files(config, audit_result, repo_root, out_dir, mode)
        console.print(f"[green]Materialised {len(result.written_files)} files to {out_dir}[/green]")
        if result.errors:
            for error in result.errors:
                console.print(f"  {error}")
            _exit_with_error(ExitCode.WRITE_ERROR)
    except typer.Exit:
        raise
    except ValueError as e:
        code = ExitCode.DESTINATION_ERROR if "Unsafe" in str(e) else ExitCode.COMPILATION_ERROR
        console.print(f"[red]Error: {e}[/red]")
        _exit_with_error(code)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        _exit_with_error(ExitCode.COMPILATION_ERROR)


@app.command()
def verify(
    plan: Annotated[
        Path,
        typer.Option(
            "--plan",
            help="Existing manifest or materialisation plan",
            exists=True,
            readable=True,
        ),
    ],
    output: Annotated[
        Path, typer.Option("--out", "--output", "-o", help="Existing pack or materialisation path")
    ],
) -> None:
    """Verify an existing materialisation plan and output without writing."""
    try:
        result = verify_all(plan, output)
        if output.suffix.lower() == ".json" and not output.exists():
            output.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(
                output,
                canonical_json_bytes(
                    {
                        "verified": result.verified,
                        "mismatches": result.mismatches,
                        "errors": result.errors,
                    }
                ),
            )

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
def receipt(  # noqa: PLR0913, PLR0917
    init_path: Annotated[Path | None, typer.Option("--init")] = None,
    audit_path: Annotated[Path | None, typer.Option("--audit")] = None,
    manifest_path: Annotated[Path | None, typer.Option("--manifest")] = None,
    pack_path: Annotated[Path | None, typer.Option("--pack")] = None,
    materialisation_path: Annotated[Path | None, typer.Option("--materialisation")] = None,
    verification_path: Annotated[Path | None, typer.Option("--verification")] = None,
    output: Annotated[Path | None, typer.Option("--out", "--output", "-o")] = None,
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="Legacy config path")
    ] = None,
    requested_by: Annotated[
        str, typer.Option("--requested-by", help="Who requested the operation")
    ] = "human",
    outcome: Annotated[str, typer.Option("--outcome", help="Operation outcome")] = "success",
) -> None:
    """Write a receipt from the seven explicit lifecycle artefacts."""
    try:
        artefact_inputs = (
            init_path,
            audit_path,
            manifest_path,
            pack_path,
            materialisation_path,
            verification_path,
        )
        if any(value is not None for value in artefact_inputs):
            if any(value is None for value in artefact_inputs) or output is None:
                _exit_with_error(ExitCode.INVALID_ARGS)
            assert init_path and audit_path and manifest_path and pack_path
            assert materialisation_path and verification_path and output
            artefact_paths = {
                "init": init_path,
                "audit": audit_path,
                "manifest": manifest_path,
                "pack": pack_path,
                "materialisation": materialisation_path,
                "verification": verification_path,
            }
            artefacts = {
                name: load_receipt_artefact(path, name) for name, path in artefact_paths.items()
            }
            config, repo_root = _get_config_and_repo(config_path)
            revision = str(artefacts["init"].get("revision", "unknown"))
            receipt_obj = generate_receipt(
                config=config,
                audit=AuditResult(),
                manifest=generate_manifest(config, AuditResult(), repo_root, revision),
                revision=revision,
                artefacts=artefacts,
                requested_by=RequestedBy(requested_by),
                outcome=OutcomeStatus(outcome),
            )
            receipt_obj.save(output)
            console.print(f"[green]Receipt written to {output}[/green]")
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
    except typer.Exit:
        raise
    except Exception as e:
        _handle_generic_error(e, ExitCode.RECEIPT_ERROR)


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
        source_files = [source.path for source in audit_result.sources if source.included]
        source_bytes = [(str(path), path.read_bytes()) for path in source_files]
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
