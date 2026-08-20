"""Turn a repository on disk into the structure the rules reason about.

Discovery does no judging. It parses, it records where everything was found,
and it reports what it could not read. Every rule downstream depends on two
properties established here:

* **Location fidelity.** A finding without a file and a line is an opinion, so
  every node carries the line it came from and the raw source line it sits on.
* **Honest failure.** A workflow that does not parse is recorded as a parse
  failure, never dropped. A scanner that silently skips what it cannot read
  reports green on exactly the pipeline most likely to be wrong.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

WORKFLOW_DIR = Path(".github/workflows")
WORKFLOW_SUFFIXES = (".yml", ".yaml")

#: Manifests whose presence means the ecosystem's dependencies are resolved
#: from a locked set rather than from a range at build time.
LOCKFILES = (
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "go.sum",
)

REQUIREMENTS_GLOBS = ("requirements*.txt", "requirements/*.txt")

_LOADER = YAML(typ="rt")
_LOADER.preserve_quotes = True


def _line_of(node: Any, key: Any, default: int) -> int:
    """1-based source line for ``key`` inside ``node``, or ``default``."""
    lc = getattr(node, "lc", None)
    if lc is None:
        return default
    try:
        position = lc.key(key)
    except (KeyError, AttributeError, TypeError):
        return default
    if position is None:
        return default
    return int(position[0]) + 1


def _own_line(node: Any, default: int) -> int:
    lc = getattr(node, "lc", None)
    if lc is None or lc.line is None:
        return default
    return int(lc.line) + 1


@dataclass(frozen=True, slots=True)
class Step:
    """One step of one job."""

    index: int
    line: int
    uses: str | None = None
    run: str | None = None
    name: str | None = None
    with_: dict[str, Any] = field(default_factory=dict)
    env: dict[str, Any] = field(default_factory=dict)

    @property
    def is_third_party(self) -> bool:
        """A ``uses:`` reference outside this repository executes foreign code."""
        return self.uses is not None and not self.uses.startswith("./")


@dataclass(frozen=True, slots=True)
class Job:
    """One job. The unit a token scope is attached to, so the unit I2 cares about."""

    name: str
    line: int
    steps: tuple[Step, ...] = ()
    permissions: Any = None
    permissions_declared: bool = False
    permissions_line: int | None = None
    container_image: str | None = None
    container_line: int | None = None
    service_images: tuple[tuple[str, int], ...] = ()
    timeout_minutes: int | None = None
    uses_workflow: str | None = None

    @property
    def produces_artifact(self) -> bool:
        """Whether anything this job does results in something deployable.

        Deliberately broad: a false positive here asks a maintainer to confirm
        their build emits provenance, while a false negative silently exempts
        the one job that ships.
        """
        markers = (
            "actions/upload-artifact",
            "docker/build-push-action",
            "gradle/gradle-build-action",
            "goreleaser",
            "pypa/gh-action-pypi-publish",
        )
        for step in self.steps:
            if step.uses and any(marker in step.uses for marker in markers):
                return True
            if step.run and _mentions_publish(step.run):
                return True
        return False


def _mentions_publish(script: str) -> bool:
    lowered = script.lower()
    return any(
        phrase in lowered
        for phrase in (
            "docker push",
            "docker build",
            "npm publish",
            "twine upload",
            "cargo publish",
            "helm push",
        )
    )


@dataclass(frozen=True, slots=True)
class Workflow:
    """A workflow definition, parsed or unparsable."""

    path: str
    source_lines: tuple[str, ...]
    triggers: tuple[str, ...] = ()
    permissions: Any = None
    permissions_declared: bool = False
    permissions_line: int | None = None
    jobs: tuple[Job, ...] = ()
    parse_error: str | None = None
    parse_error_line: int | None = None

    @property
    def parsed(self) -> bool:
        return self.parse_error is None

    def source(self, line: int | None) -> str | None:
        """The raw source line, used for evidence and for comment detection."""
        if line is None or not 1 <= line <= len(self.source_lines):
            return None
        return self.source_lines[line - 1].strip()


@dataclass(frozen=True, slots=True)
class Manifest:
    """A dependency manifest, and whether its contents are locked."""

    path: str
    kind: str
    hashed: bool


@dataclass(frozen=True, slots=True)
class Repository:
    """Everything an audit reasons about, and everything it failed to read."""

    root: Path
    workflows: tuple[Workflow, ...] = ()
    manifests: tuple[Manifest, ...] = ()

    @property
    def parsed_workflows(self) -> tuple[Workflow, ...]:
        return tuple(w for w in self.workflows if w.parsed)

    @property
    def unparsable_workflows(self) -> tuple[Workflow, ...]:
        return tuple(w for w in self.workflows if not w.parsed)

    def jobs(self) -> Iterator[tuple[Workflow, Job]]:
        for workflow in self.parsed_workflows:
            for job in workflow.jobs:
                yield workflow, job


def _as_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _triggers(document: Any) -> tuple[str, ...]:
    """Read the ``on:`` block.

    YAML 1.1 folds a bare ``on`` into the boolean ``True``; YAML 1.2 does not.
    Both are accepted rather than depending on which spec version the loader
    happens to implement.
    """
    raw = document.get("on", document.get(True))
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw,)
    if isinstance(raw, list):
        return tuple(str(item) for item in raw)
    if isinstance(raw, dict):
        return tuple(str(key) for key in raw)
    return ()


def _steps(raw_steps: Any, job_line: int) -> tuple[Step, ...]:
    if not isinstance(raw_steps, list):
        return ()
    steps: list[Step] = []
    for index, raw in enumerate(raw_steps):
        if not isinstance(raw, dict):
            continue
        steps.append(
            Step(
                index=index,
                line=_own_line(raw, job_line),
                uses=str(raw["uses"]) if raw.get("uses") is not None else None,
                run=str(raw["run"]) if raw.get("run") is not None else None,
                name=str(raw["name"]) if raw.get("name") is not None else None,
                with_=_as_mapping(raw.get("with")),
                env=_as_mapping(raw.get("env")),
            )
        )
    return tuple(steps)


def _container(raw_job: Any, job_line: int) -> tuple[str | None, int | None]:
    container = raw_job.get("container")
    if container is None:
        return None, None
    line = _line_of(raw_job, "container", job_line)
    if isinstance(container, str):
        return container, line
    if isinstance(container, dict) and container.get("image") is not None:
        return str(container["image"]), _line_of(container, "image", line)
    return None, None


def _services(raw_job: Any, job_line: int) -> tuple[tuple[str, int], ...]:
    services = raw_job.get("services")
    if not isinstance(services, dict):
        return ()
    found: list[tuple[str, int]] = []
    for name, definition in services.items():
        line = _line_of(services, name, job_line)
        if isinstance(definition, dict) and definition.get("image") is not None:
            found.append(
                (str(definition["image"]), _line_of(definition, "image", line))
            )
        elif isinstance(definition, str):
            found.append((definition, line))
    return tuple(found)


def _job(name: str, raw_job: Any, line: int) -> Job:
    permissions_declared = isinstance(raw_job, dict) and "permissions" in raw_job
    container_image, container_line = _container(raw_job, line)
    timeout = raw_job.get("timeout-minutes")
    return Job(
        name=name,
        line=line,
        steps=_steps(raw_job.get("steps"), line),
        permissions=raw_job.get("permissions"),
        permissions_declared=permissions_declared,
        permissions_line=_line_of(raw_job, "permissions", line)
        if permissions_declared
        else None,
        container_image=container_image,
        container_line=container_line,
        service_images=_services(raw_job, line),
        timeout_minutes=int(timeout) if isinstance(timeout, int) else None,
        uses_workflow=str(raw_job["uses"]) if raw_job.get("uses") is not None else None,
    )


def load_workflow(path: Path, relative_to: Path) -> Workflow:
    """Parse one workflow, recording a parse failure rather than raising."""
    relative = path.relative_to(relative_to).as_posix()
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = tuple(text.splitlines())

    try:
        document = _LOADER.load(text)
    except YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        return Workflow(
            path=relative,
            source_lines=lines,
            parse_error=str(getattr(error, "problem", None) or error).strip(),
            parse_error_line=(mark.line + 1) if mark is not None else None,
        )

    if not isinstance(document, dict):
        return Workflow(
            path=relative,
            source_lines=lines,
            parse_error="workflow is not a mapping",
            parse_error_line=1,
        )

    raw_jobs = document.get("jobs")
    jobs: list[Job] = []
    if isinstance(raw_jobs, dict):
        jobs_line = _line_of(document, "jobs", 1)
        for name, raw_job in raw_jobs.items():
            if isinstance(raw_job, dict):
                jobs.append(
                    _job(str(name), raw_job, _line_of(raw_jobs, name, jobs_line))
                )

    declared = "permissions" in document
    return Workflow(
        path=relative,
        source_lines=lines,
        triggers=_triggers(document),
        permissions=document.get("permissions"),
        permissions_declared=declared,
        permissions_line=_line_of(document, "permissions", 1) if declared else None,
        jobs=tuple(jobs),
    )


def _manifests(root: Path) -> tuple[Manifest, ...]:
    found: list[Manifest] = []
    for name in LOCKFILES:
        if (root / name).is_file():
            found.append(Manifest(path=name, kind="lockfile", hashed=True))
    for pattern in REQUIREMENTS_GLOBS:
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            found.append(
                Manifest(
                    path=path.relative_to(root).as_posix(),
                    kind="requirements",
                    hashed="--hash=" in text,
                )
            )
    return tuple(found)


def load_repository(root: Path) -> Repository:
    """Read everything an audit needs from ``root``. Never touches the network."""
    root = root.resolve()
    workflow_dir = root / WORKFLOW_DIR
    paths = (
        sorted(
            path
            for path in workflow_dir.iterdir()
            if path.is_file() and path.suffix in WORKFLOW_SUFFIXES
        )
        if workflow_dir.is_dir()
        else []
    )
    return Repository(
        root=root,
        workflows=tuple(load_workflow(path, root) for path in paths),
        manifests=_manifests(root),
    )
