from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import json
import re
import sys
import urllib.error
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from email.parser import Parser
from pathlib import Path
from typing import Any


LOCK_SCHEMA = "r3/python-lock-verification/v1"
SBOM_FORMAT = "CycloneDX"
SBOM_SPEC_VERSION = "1.5"
OSV_ENDPOINT = "https://api.osv.dev/v1/querybatch"
PYPI_JSON_PREFIX = "https://pypi.org/pypi/"
PYPI_FILE_PREFIX = "https://files.pythonhosted.org/"
NPM_REGISTRY_PREFIX = "https://registry.npmjs.org/"
MAX_METADATA_RESPONSE_BYTES = 5 * 1024 * 1024
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)$")
HASH_RE = re.compile(r"^--hash=sha256:([0-9a-f]{64})$")
DISALLOWED_TOKENS = ("git+", "hg+", "svn+", "bzr+", "://", "-e ", "--editable")
BOOTSTRAP_PACKAGES = {"pip", "setuptools"}


class SupplyChainError(ValueError):
    pass


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_limited_response(response: Any, limit: int = MAX_METADATA_RESPONSE_BYTES) -> bytes:
    body = response.read(limit + 1)
    if len(body) > limit:
        raise SupplyChainError(f"metadata response exceeds {limit} bytes")
    return body


def logical_lines(path: Path) -> list[str]:
    result: list[str] = []
    pending = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1].strip() + " "
            continue
        result.append((pending + stripped).strip())
        pending = ""
    if pending:
        raise SupplyChainError(f"unterminated continuation in {path}")
    return result


def parse_lock(path: Path) -> dict[str, dict[str, Any]]:
    packages: dict[str, dict[str, Any]] = {}
    saw_binary_only = False
    for line in logical_lines(path):
        lower = line.lower()
        if any(token in lower for token in DISALLOWED_TOKENS):
            raise SupplyChainError(f"disallowed URL/VCS/editable token: {line}")
        if line == "--only-binary=:all:":
            saw_binary_only = True
            continue
        tokens = line.split()
        if not tokens:
            continue
        pin = PIN_RE.fullmatch(tokens[0])
        if not pin:
            raise SupplyChainError(f"entry is not an exact == pin: {line}")
        raw_name, version = pin.groups()
        if not NAME_RE.fullmatch(raw_name):
            raise SupplyChainError(f"invalid package name: {raw_name}")
        name = normalize_name(raw_name)
        if name in packages:
            raise SupplyChainError(f"duplicate package: {name}")
        hashes: list[str] = []
        for token in tokens[1:]:
            match = HASH_RE.fullmatch(token)
            if not match:
                raise SupplyChainError(f"unsupported or non-SHA256 option for {name}: {token}")
            hashes.append(match.group(1))
        if not hashes:
            raise SupplyChainError(f"missing SHA256 hash: {name}")
        if len(hashes) != len(set(hashes)):
            raise SupplyChainError(f"duplicate SHA256 hash: {name}")
        packages[name] = {
            "name": raw_name,
            "normalized_name": name,
            "version": version,
            "hashes": sorted(hashes),
        }
    if not saw_binary_only:
        raise SupplyChainError("lock must contain --only-binary=:all:")
    if not packages:
        raise SupplyChainError("lock contains no packages")
    return packages


def parse_direct_requirements(path: Path) -> dict[str, str]:
    direct: dict[str, str] = {}
    for line in logical_lines(path):
        lower = line.lower()
        if any(token in lower for token in DISALLOWED_TOKENS):
            raise SupplyChainError(f"disallowed direct requirement: {line}")
        pin = PIN_RE.fullmatch(line)
        if not pin:
            raise SupplyChainError(f"direct requirement is not an exact == pin: {line}")
        raw_name, version = pin.groups()
        name = normalize_name(raw_name)
        if name in direct:
            raise SupplyChainError(f"duplicate direct requirement: {name}")
        direct[name] = version
    return direct


def read_wheel_metadata(path: Path) -> tuple[str, str, list[str]]:
    if path.suffix.lower() != ".whl":
        raise SupplyChainError(f"non-wheel artifact in wheel directory: {path.name}")
    with zipfile.ZipFile(path) as archive:
        metadata_names = [
            name
            for name in archive.namelist()
            if name.endswith(".dist-info/METADATA") and name.count("/") == 1
        ]
        if len(metadata_names) != 1:
            raise SupplyChainError(
                f"wheel must contain exactly one dist-info/METADATA: {path.name}"
            )
        raw = archive.read(metadata_names[0]).decode("utf-8", errors="strict")
    metadata = Parser().parsestr(raw)
    name = metadata.get("Name")
    version = metadata.get("Version")
    if not name or not version:
        raise SupplyChainError(f"wheel metadata missing Name/Version: {path.name}")
    return normalize_name(name), version, metadata.get_all("Requires-Dist") or []


def inspect_wheelhouse(
    wheel_dir: Path, lock: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    wheels: dict[str, dict[str, Any]] = {}
    for path in sorted(wheel_dir.iterdir(), key=lambda item: item.name.lower()):
        if not path.is_file():
            continue
        name, version, requires_dist = read_wheel_metadata(path)
        if name in wheels:
            raise SupplyChainError(f"multiple wheels for package: {name}")
        digest = sha256_file(path)
        wheels[name] = {
            "filename": path.name,
            "size": path.stat().st_size,
            "sha256": digest,
            "version": version,
            "requires_dist": sorted(requires_dist),
        }
    missing = sorted(set(lock) - set(wheels))
    extra = sorted(set(wheels) - set(lock))
    if missing or extra:
        raise SupplyChainError(f"wheel coverage mismatch; missing={missing}; extra={extra}")
    for name, item in wheels.items():
        expected = lock[name]
        if item["version"] != expected["version"]:
            raise SupplyChainError(
                f"wheel version mismatch for {name}: {item['version']} != {expected['version']}"
            )
        if item["sha256"] not in expected["hashes"]:
            raise SupplyChainError(f"wheel hash is not allowed by lock: {item['filename']}")
    return wheels


def verify_lock(lock_path: Path, direct_path: Path, wheel_dir: Path) -> dict[str, Any]:
    lock = parse_lock(lock_path)
    missing_bootstrap = sorted(BOOTSTRAP_PACKAGES - set(lock))
    if missing_bootstrap:
        raise SupplyChainError(
            f"bootstrap packages missing from lock: {missing_bootstrap}"
        )
    direct = parse_direct_requirements(direct_path)
    for name, version in direct.items():
        if name not in lock:
            raise SupplyChainError(f"direct requirement missing from lock: {name}")
        if lock[name]["version"] != version:
            raise SupplyChainError(
                f"direct requirement version mismatch: {name} {version} != {lock[name]['version']}"
            )
    wheels = inspect_wheelhouse(wheel_dir, lock)
    packages = []
    for name in sorted(lock):
        role = (
            "direct"
            if name in direct
            else "bootstrap"
            if name in BOOTSTRAP_PACKAGES
            else "transitive"
        )
        packages.append(
            {
                **lock[name],
                "direct": name in direct,
                "role": role,
                "wheel": wheels[name],
            }
        )
    bootstrap_count = sum(
        1 for package in packages if package["role"] == "bootstrap"
    )
    return {
        "schema": LOCK_SCHEMA,
        "status": "PASS",
        "verifier_sha256": sha256_file(Path(__file__).resolve()),
        "lock_path": lock_path.as_posix(),
        "lock_sha256": sha256_file(lock_path),
        "direct_requirements_path": direct_path.as_posix(),
        "direct_requirements_sha256": sha256_file(direct_path),
        "binary_only_directive": True,
        "package_count": len(packages),
        "direct_count": len(direct),
        "bootstrap_count": bootstrap_count,
        "transitive_only_count": len(packages) - len(direct) - bootstrap_count,
        "all_exact_pins": True,
        "all_sha256_hashed": True,
        "all_artifacts_are_wheels": True,
        "vcs_url_editable_entries": 0,
        "packages": packages,
    }


def load_pip_inspect(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("installed"), list):
        raise SupplyChainError("pip inspect JSON does not contain an installed list")
    return payload


def installed_by_name(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    installed_items = payload.get("installed")
    if not isinstance(installed_items, list):
        raise SupplyChainError("installed environment does not contain a list")
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(installed_items):
        if not isinstance(item, dict):
            raise SupplyChainError(
                f"installed environment entry {index} is not an object"
            )
        metadata = item.get("metadata") or {}
        raw_name = metadata.get("name")
        version = metadata.get("version")
        if not raw_name or not version:
            raise SupplyChainError(
                f"installed environment entry {index} lacks Name/Version"
            )
        name = normalize_name(str(raw_name))
        if name in result:
            raise SupplyChainError(
                f"duplicate normalized installed package: {name}"
            )
        result[name] = item
    return result


def verify_rebuild(
    lock: dict[str, dict[str, Any]], pip_inspect: dict[str, Any]
) -> dict[str, Any]:
    missing_bootstrap = sorted(BOOTSTRAP_PACKAGES - set(lock))
    if missing_bootstrap:
        raise SupplyChainError(
            f"bootstrap packages missing from rebuilt environment contract: {missing_bootstrap}"
        )
    installed = installed_by_name(pip_inspect)
    runtime_installed = {name: item for name, item in installed.items() if name in lock}
    missing = sorted(set(lock) - set(runtime_installed))
    version_mismatch = {
        name: {
            "expected": lock[name]["version"],
            "actual": runtime_installed[name]["metadata"]["version"],
        }
        for name in sorted(runtime_installed)
        if runtime_installed[name]["metadata"]["version"] != lock[name]["version"]
    }
    if missing or version_mismatch:
        raise SupplyChainError(
            f"rebuilt environment mismatch; missing={missing}; versions={version_mismatch}"
        )
    unexpected_runtime = sorted(name for name in installed if name not in lock)
    if unexpected_runtime:
        raise SupplyChainError(
            f"unexpected runtime packages in rebuilt environment: {unexpected_runtime}"
        )
    return {
        "status": "PASS",
        "locked_count": len(lock),
        "installed_runtime_count": len(runtime_installed),
        "missing": [],
        "version_mismatch": {},
        "unexpected_runtime": [],
        "installer_packages": {
            name: installed[name]["metadata"]["version"]
            for name in ("pip", "setuptools")
            if name in installed
        },
    }


def inspect_current_environment() -> dict[str, Any]:
    installed = []
    for distribution in importlib.metadata.distributions():
        installed.append(
            {
                "metadata": {
                    "name": distribution.metadata.get("Name"),
                    "version": distribution.version,
                }
            }
        )
    return {"installed": installed}


def build_sbom(
    lock_receipt: dict[str, Any], pip_inspect: dict[str, Any]
) -> dict[str, Any]:
    lock = {
        item["normalized_name"]: item for item in lock_receipt.get("packages", [])
    }
    if not lock:
        raise SupplyChainError("lock receipt contains no packages")
    rebuild = verify_rebuild(lock, pip_inspect)
    installed = installed_by_name(pip_inspect)
    components = []
    for name in sorted(lock):
        locked = lock[name]
        metadata = installed[name].get("metadata") or {}
        purl = f"pkg:pypi/{name}@{locked['version']}"
        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": metadata.get("name", locked["name"]),
                "version": locked["version"],
                "purl": purl,
                "hashes": [
                    {"alg": "SHA-256", "content": locked["wheel"]["sha256"]}
                ],
                "properties": [
                    {"name": "r3:direct", "value": str(bool(locked["direct"])).lower()},
                    {
                        "name": "r3:role",
                        "value": locked.get(
                            "role",
                            "direct" if locked["direct"] else "transitive",
                        ),
                    },
                    {"name": "r3:wheel", "value": locked["wheel"]["filename"]},
                ],
            }
        )
    namespace = uuid.UUID("41879cc8-1537-52bd-9da0-24cf6f691a0f")
    serial_seed = lock_receipt["lock_sha256"] + "|" + "|".join(
        f"{name}=={lock[name]['version']}:{lock[name]['wheel']['sha256']}"
        for name in sorted(lock)
    )
    serial = uuid.uuid5(namespace, serial_seed)
    return {
        "bomFormat": SBOM_FORMAT,
        "specVersion": SBOM_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "r3-research-radar",
                "name": "r3-research-radar",
                "version": "0.1.0",
            },
            "properties": [
                {"name": "r3:lock-sha256", "value": lock_receipt["lock_sha256"]},
                {
                    "name": "r3:rebuild-status",
                    "value": rebuild["status"],
                },
                {
                    "name": "r3:dependency-graph",
                    "value": (
                        "omitted: PEP 508 markers and extras are not resolved; "
                        "publishing unverified edges would be false"
                    ),
                },
            ],
        },
        "components": components,
    }


def osv_query(packages: list[dict[str, Any]], timeout_seconds: float) -> dict[str, Any]:
    queries = [
        {
            "package": {
                "name": item["normalized_name"],
                "ecosystem": "PyPI",
            },
            "version": item["version"],
        }
        for item in packages
    ]
    request_body = json.dumps({"queries": queries}, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        OSV_ENDPOINT,
        data=request_body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "r3-research-radar-supply-chain/0.1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            response_body = read_limited_response(response)
            status = response.status
    except (urllib.error.URLError, TimeoutError) as exc:
        raise SupplyChainError(f"OSV query failed; not clean: {exc}") from exc
    if status != 200:
        raise SupplyChainError(f"OSV query HTTP {status}; not clean")
    payload = json.loads(response_body.decode("utf-8"))
    results = payload.get("results")
    if not isinstance(results, list) or len(results) != len(packages):
        raise SupplyChainError("OSV response cardinality mismatch")
    findings = []
    for item, result in zip(packages, results):
        vulnerabilities = result.get("vulns") or []
        if not isinstance(vulnerabilities, list):
            raise SupplyChainError("OSV vulnerabilities field is not a list")
        for vulnerability in vulnerabilities:
            findings.append(
                {
                    "package": item["normalized_name"],
                    "version": item["version"],
                    "id": vulnerability.get("id"),
                    "aliases": sorted(vulnerability.get("aliases") or []),
                    "modified": vulnerability.get("modified"),
                    "severity": vulnerability.get("severity") or [],
                    "database_specific": vulnerability.get("database_specific") or {},
                }
            )
    return {
        "schema": "r3/osv-query-receipt/v1",
        "status": "PASS" if not findings else "REVIEW_REQUIRED",
        "queried_at_utc": datetime.now(timezone.utc).isoformat(),
        "endpoint": OSV_ENDPOINT,
        "query_count": len(queries),
        "response_count": len(results),
        "request_sha256": hashlib.sha256(request_body).hexdigest(),
        "response_sha256": hashlib.sha256(response_body).hexdigest(),
        "findings_count": len(findings),
        "findings": findings,
        "raw_response": payload,
    }


def verify_pypi_payload(
    package: dict[str, Any],
    payload: dict[str, Any],
    response_sha256: str,
) -> dict[str, Any]:
    normalized_name = package["normalized_name"]
    expected_version = package["version"]
    wheel = package["wheel"]
    info = payload.get("info") or {}
    if normalize_name(str(info.get("name", ""))) != normalized_name:
        raise SupplyChainError(f"PyPI name mismatch for {normalized_name}")
    if str(info.get("version", "")) != expected_version:
        raise SupplyChainError(f"PyPI version mismatch for {normalized_name}")
    matches = [
        item
        for item in payload.get("urls") or []
        if item.get("filename") == wheel["filename"]
    ]
    if len(matches) != 1:
        raise SupplyChainError(
            f"PyPI must return exactly one matching wheel for {normalized_name}"
        )
    artifact = matches[0]
    if artifact.get("packagetype") != "bdist_wheel":
        raise SupplyChainError(f"PyPI artifact is not a wheel for {normalized_name}")
    url = artifact.get("url")
    if not isinstance(url, str) or not url.startswith(PYPI_FILE_PREFIX):
        raise SupplyChainError(f"PyPI artifact URL is not official HTTPS for {normalized_name}")
    digest = (artifact.get("digests") or {}).get("sha256")
    if digest != wheel["sha256"]:
        raise SupplyChainError(f"PyPI SHA256 mismatch for {normalized_name}")
    if int(artifact.get("size", -1)) != int(wheel["size"]):
        raise SupplyChainError(f"PyPI size mismatch for {normalized_name}")
    if artifact.get("yanked") is True:
        raise SupplyChainError(f"PyPI artifact is yanked for {normalized_name}")
    return {
        "name": normalized_name,
        "version": expected_version,
        "filename": wheel["filename"],
        "sha256": digest,
        "size": wheel["size"],
        "url": url,
        "requires_python": artifact.get("requires_python"),
        "upload_time_iso_8601": artifact.get("upload_time_iso_8601"),
        "yanked": bool(artifact.get("yanked", False)),
        "metadata_response_sha256": response_sha256,
    }


def pypi_provenance(
    packages: list[dict[str, Any]], timeout_seconds: float
) -> dict[str, Any]:
    artifacts = []
    for package in packages:
        endpoint = (
            f"{PYPI_JSON_PREFIX}{package['normalized_name']}/{package['version']}/json"
        )
        request = urllib.request.Request(
            endpoint,
            headers={"User-Agent": "r3-research-radar-supply-chain/0.1"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                body = read_limited_response(response)
                status = response.status
        except (urllib.error.URLError, TimeoutError) as exc:
            raise SupplyChainError(
                f"PyPI provenance query failed for {package['normalized_name']}: {exc}"
            ) from exc
        if status != 200:
            raise SupplyChainError(
                f"PyPI provenance HTTP {status} for {package['normalized_name']}"
            )
        payload = json.loads(body.decode("utf-8"))
        artifacts.append(
            verify_pypi_payload(
                package,
                payload,
                hashlib.sha256(body).hexdigest(),
            )
        )
    return {
        "schema": "r3/pypi-provenance/v1",
        "status": "PASS",
        "queried_at_utc": datetime.now(timezone.utc).isoformat(),
        "metadata_origin": PYPI_JSON_PREFIX,
        "artifact_origin": PYPI_FILE_PREFIX,
        "artifact_count": len(artifacts),
        "all_official_https": True,
        "all_wheel_hashes_match": True,
        "all_wheels_not_yanked": True,
        "artifacts": artifacts,
    }


def exact_npm_version(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", value)
    )


def valid_npm_integrity(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha512-"):
        return False
    try:
        decoded = base64.b64decode(value[7:], validate=True)
    except (ValueError, TypeError):
        return False
    return len(decoded) == 64


def verify_npm_lock(package_json_path: Path, package_lock_path: Path) -> dict[str, Any]:
    package_json = json.loads(package_json_path.read_text(encoding="utf-8"))
    package_lock = json.loads(package_lock_path.read_text(encoding="utf-8"))
    if package_lock.get("lockfileVersion") != 3:
        raise SupplyChainError("npm package-lock must use lockfileVersion 3")
    packages = package_lock.get("packages")
    if not isinstance(packages, dict) or "" not in packages:
        raise SupplyChainError("npm package-lock packages/root entry missing")
    declared = package_json.get("dependencies") or {}
    locked_root = packages[""].get("dependencies") or {}
    if declared != locked_root:
        raise SupplyChainError("package.json dependencies do not match lock root")
    for name, version in declared.items():
        if not exact_npm_version(version):
            raise SupplyChainError(f"npm direct dependency is not exactly pinned: {name}")
    entries = []
    for path, item in sorted(packages.items()):
        if path == "":
            continue
        if not isinstance(item, dict):
            raise SupplyChainError(f"npm lock entry is not an object: {path}")
        version = item.get("version")
        resolved = item.get("resolved")
        integrity = item.get("integrity")
        if not exact_npm_version(version):
            raise SupplyChainError(f"npm lock entry is not exactly versioned: {path}")
        if not isinstance(resolved, str) or not resolved.startswith(NPM_REGISTRY_PREFIX):
            raise SupplyChainError(f"npm lock entry uses a non-registry source: {path}")
        if not valid_npm_integrity(integrity):
            raise SupplyChainError(f"npm lock entry lacks valid SHA-512 integrity: {path}")
        entries.append(
            {
                "path": path,
                "version": version,
                "resolved": resolved,
                "integrity": integrity,
                "optional": bool(item.get("optional", False)),
                "os": sorted(item.get("os") or []),
                "cpu": sorted(item.get("cpu") or []),
                "has_install_script": bool(item.get("hasInstallScript", False)),
            }
        )
    return {
        "schema": "r3/npm-lock-verification/v1",
        "status": "PASS",
        "package_json_sha256": sha256_file(package_json_path),
        "package_lock_sha256": sha256_file(package_lock_path),
        "lockfile_version": 3,
        "direct_dependencies": [
            {"name": name, "version": declared[name]} for name in sorted(declared)
        ],
        "package_entry_count": len(entries),
        "all_direct_exact": True,
        "all_entries_exact": True,
        "all_resolved_official_registry_https": True,
        "all_entries_sha512_integrity": True,
        "entries_with_install_script": sum(
            1 for entry in entries if entry["has_install_script"]
        ),
        "reconstruction_required_flag": "--ignore-scripts",
        "entries": entries,
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def command_verify(args: argparse.Namespace) -> None:
    receipt = verify_lock(args.lock, args.direct, args.wheel_dir)
    write_json(args.output, receipt)


def command_sbom(args: argparse.Namespace) -> None:
    lock_receipt = json.loads(args.lock_receipt.read_text(encoding="utf-8"))
    pip_inspect = load_pip_inspect(args.pip_inspect)
    sbom = build_sbom(lock_receipt, pip_inspect)
    sbom["metadata"]["properties"].append(
        {
            "name": "r3:verifier-sha256",
            "value": sha256_file(Path(__file__).resolve()),
        }
    )
    write_json(args.output, sbom)


def command_verify_current_environment(args: argparse.Namespace) -> None:
    lock = parse_lock(args.lock)
    receipt = verify_rebuild(lock, inspect_current_environment())
    receipt.update(
        {
            "schema": "r3/current-environment-verification/v1",
            "lock_path": args.lock.as_posix(),
            "lock_sha256": sha256_file(args.lock),
            "verifier_sha256": sha256_file(Path(__file__).resolve()),
        }
    )
    write_json(args.output, receipt)


def command_osv(args: argparse.Namespace) -> None:
    lock_receipt = json.loads(args.lock_receipt.read_text(encoding="utf-8"))
    packages = lock_receipt.get("packages") or []
    if not packages:
        raise SupplyChainError("lock receipt contains no packages")
    receipt = osv_query(packages, args.timeout)
    receipt["input_lock_sha256"] = lock_receipt.get("lock_sha256")
    receipt["verifier_sha256"] = sha256_file(Path(__file__).resolve())
    write_json(args.output, receipt)
    if receipt["status"] != "PASS":
        raise SupplyChainError(
            f"OSV returned {receipt['findings_count']} finding(s); manual severity review required"
        )


def command_pypi(args: argparse.Namespace) -> None:
    lock_receipt = json.loads(args.lock_receipt.read_text(encoding="utf-8"))
    packages = lock_receipt.get("packages") or []
    if not packages:
        raise SupplyChainError("lock receipt contains no packages")
    receipt = pypi_provenance(packages, args.timeout)
    receipt["input_lock_sha256"] = lock_receipt.get("lock_sha256")
    receipt["verifier_sha256"] = sha256_file(Path(__file__).resolve())
    write_json(args.output, receipt)


def command_npm(args: argparse.Namespace) -> None:
    receipt = verify_npm_lock(args.package_json, args.package_lock)
    receipt["verifier_sha256"] = sha256_file(Path(__file__).resolve())
    write_json(args.output, receipt)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Fail-closed verification and receipts for the R3 local dependency lock."
    )
    subparsers = root.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser("verify-lock")
    verify.add_argument("--lock", type=Path, required=True)
    verify.add_argument("--direct", type=Path, required=True)
    verify.add_argument("--wheel-dir", type=Path, required=True)
    verify.add_argument("--output", type=Path, required=True)
    verify.set_defaults(func=command_verify)

    sbom = subparsers.add_parser("build-sbom")
    sbom.add_argument("--lock-receipt", type=Path, required=True)
    sbom.add_argument("--pip-inspect", type=Path, required=True)
    sbom.add_argument("--output", type=Path, required=True)
    sbom.set_defaults(func=command_sbom)

    current = subparsers.add_parser("verify-current-environment")
    current.add_argument("--lock", type=Path, required=True)
    current.add_argument("--output", type=Path, required=True)
    current.set_defaults(func=command_verify_current_environment)

    osv = subparsers.add_parser("query-osv")
    osv.add_argument("--lock-receipt", type=Path, required=True)
    osv.add_argument("--output", type=Path, required=True)
    osv.add_argument("--timeout", type=float, default=20.0)
    osv.set_defaults(func=command_osv)

    pypi = subparsers.add_parser("query-pypi-provenance")
    pypi.add_argument("--lock-receipt", type=Path, required=True)
    pypi.add_argument("--output", type=Path, required=True)
    pypi.add_argument("--timeout", type=float, default=20.0)
    pypi.set_defaults(func=command_pypi)

    npm = subparsers.add_parser("verify-npm-lock")
    npm.add_argument("--package-json", type=Path, required=True)
    npm.add_argument("--package-lock", type=Path, required=True)
    npm.add_argument("--output", type=Path, required=True)
    npm.set_defaults(func=command_npm)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        args.func(args)
    except (OSError, SupplyChainError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"supply-chain verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
