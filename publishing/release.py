"""Release guardrails (standard library only). No publish command is implemented here."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
CENTRAL = "https://repo.maven.apache.org/maven2/"
SPEC_COMMIT = "4623a7e1718e23504903096c92332597057bd8f0"
SPEC_PIN_SHA256 = "f4212f2c1d22d3acb553751755e5ca30689c7138776140a59b69383e27557b08"
UPLOAD_STEP = "Publish and release to Maven Central"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def git(*args, **kwargs):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, **kwargs).strip()


def inputs():
    version = os.environ["REQUESTED_VERSION"]
    commit = os.environ["REQUESTED_COMMIT"]
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?", version), "Invalid release version")
    require(not version.upper().endswith("-SNAPSHOT"), "A release cannot be a SNAPSHOT")
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "commit must be exactly 40 lowercase hexadecimal characters")
    require(os.environ["DISPATCH_REF"] == "refs/heads/main", "Dispatch must select main")
    require(os.environ["DISPATCH_SHA"] == commit, "Dispatch SHA differs from reviewed commit")
    return version, commit


def request(url, token=None):
    headers = {"User-Agent": "totipo-java-release", "Accept": "application/json"} if "api.github.com/" in url else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as response:
            require(response.status == 200, f"Unexpected HTTP {response.status}: {url}")
            return 200, response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return 404, b""
        raise RuntimeError(f"Unexpected HTTP {error.code}: {url}") from None
    except (OSError, urllib.error.URLError) as error:
        raise RuntimeError(f"Network failure for {url}: {type(error).__name__}") from None


def release_record(version):
    status, body = request(f"https://api.github.com/repos/{os.environ['GITHUB_REPOSITORY']}/releases/tags/v{version}", os.environ.get("GH_TOKEN"))
    return json.loads(body) if status == 200 else None


def identity(allow_tag=False):
    version, commit = inputs()
    require(git("rev-parse", "HEAD") == commit, "Checkout differs from reviewed commit")
    require((ROOT / "VERSION").read_text() == version + "\n", "VERSION differs from requested version")
    require(not git("status", "--porcelain", "--untracked-files=all"), "Checkout must be clean")
    require(hashlib.sha256((ROOT / "SPEC_PIN.md").read_bytes()).hexdigest() == SPEC_PIN_SHA256, "Exact reviewed spec pin changed")
    git("fetch", "--no-recurse-submodules", "--tags", "origin", "+refs/heads/main:refs/remotes/origin/main")
    require(git("rev-parse", "refs/remotes/origin/main") == commit, "Current origin/main differs from reviewed commit")
    tag = f"refs/tags/v{version}"
    remote = git("ls-remote", "--tags", "origin", tag, tag + "^{}")
    local = git("tag", "--list", f"v{version}")
    if allow_tag:
        if remote:
            lines = dict(line.split()[::-1] for line in remote.splitlines())
            require(lines.get(tag + "^{}", lines.get(tag)) == commit, "Remote tag points elsewhere; never move it")
        if local:
            require(git("rev-parse", tag + "^{commit}") == commit, "Local tag points elsewhere; never move it")
    else:
        require(not local and not remote, "Release tag already exists")
        require(release_record(version) is None, "GitHub release already exists")
    print(f"Identity OK: {commit}, version {version}, spec {SPEC_COMMIT}")


def prior_upload():
    """Public GitHub run history proves only this same run could have uploaded.

    Anonymous reads keep validation tokens at contents:read. A private repository
    would need a deliberately reviewed actions:read permission instead.
    """
    attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
    repo = os.environ["GITHUB_REPOSITORY"]
    run_id = os.environ["GITHUB_RUN_ID"]
    for previous in range(1, attempt):
        page = 1
        while True:
            status, body = request(f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/attempts/{previous}/jobs?per_page=100&page={page}")
            require(status == 200, "Cannot prove previous upload attempt in this workflow run")
            jobs = json.loads(body)["jobs"]
            for job in jobs:
                require(job["head_sha"] == os.environ["REQUESTED_COMMIT"], "Previous attempt commit differs")
                if job["name"] == "publish-central" and any(step["name"] == UPLOAD_STEP and step.get("started_at") and step.get("conclusion") != "skipped" for step in job.get("steps", [])):
                    return True
            if len(jobs) < 100:
                break
            page += 1
    return False


def central_state():
    version, _ = inputs()
    statuses = [request(f"{CENTRAL}org/totipo/totipo-{module}/{version}/totipo-{module}-{version}.pom")[0]
                for module in ("core", "storage-nio")]
    attempted = prior_upload()
    if 200 in statuses:
        require(attempted, "Version already exists on Central; no prior upload in this same run")
        print("Same-run possible partial Central success: skip all upload; strict verification follows")
        return "verify"
    require(statuses == [404, 404], "Central absence was not established")
    require(not attempted, "Prior upload may still be propagating. Do not upload again; inspect Portal and retry verification once visible")
    print("Both Central GAVs absent (404); publication may proceed")
    return "publish"


def inventory():
    data = json.loads((ROOT / "build/publication-sha256.json").read_text())
    version, _ = inputs()
    require(len(data) == 10, "Expected 10 verified unsigned release artifacts")
    for path, digest in data.items():
        require(re.fullmatch(r"org/totipo/(totipo-(?:core|storage-nio))/" + re.escape(version) + r"/\1-" + re.escape(version) + r"(?:-sources\.jar|-javadoc\.jar|\.jar|\.pom|\.module)", path), "Invalid inventory path")
        require(re.fullmatch(r"[0-9a-f]{64}", digest), "Invalid inventory SHA-256")
    return data


def compare_inventory():
    current = inventory()
    require(current == json.loads(os.environ["EXPECTED_INVENTORY"]), "Fresh artifact inventory differs from preflight")
    print("10/10 rebuilt artifact hashes match preflight")


def signed():
    """Locate the sign task's unsigned inputs and detached signatures, not staging copies."""
    expected = inventory()
    for path, digest in expected.items():
        module = "storage-nio" if "/totipo-storage-nio/" in path else "core"
        name = Path(path).name
        actual = {".pom": "pom-default.xml", ".module": "module.json"}.get(Path(name).suffix, name)
        directory = ROOT / module / "build"
        candidates = list(directory.rglob(actual + ".asc"))
        require(len(candidates) == 1, f"Expected exactly one signing output for {name}")
        signature = candidates[0].read_bytes()
        unsigned = candidates[0].with_suffix("").read_bytes()
        require(b"-----BEGIN PGP SIGNATURE-----" in signature and b"-----END PGP SIGNATURE-----" in signature, f"Missing detached signature: {name}")
        require(hashlib.sha256(unsigned).hexdigest() == digest, f"Signed input differs from reviewed unsigned artifact: {name}")
    print("10/10 exact reviewed artifacts have detached signing outputs")


def verify_remote(timeout=2400):
    compare_inventory()
    remaining = inventory()
    deadline = time.monotonic() + timeout
    delay = 10
    while remaining:
        for path, digest in list(remaining.items()):
            status, data = request(CENTRAL + path)
            if status == 404:
                continue
            require(hashlib.sha256(data).hexdigest() == digest, f"PERMANENT artifact hash mismatch: {path}; do not tag or release")
            status, signature = request(CENTRAL + path + ".asc")
            if status == 404:
                continue
            require(b"-----BEGIN PGP SIGNATURE-----" in signature and b"-----END PGP SIGNATURE-----" in signature, f"Invalid remote detached signature: {path}")
            del remaining[path]
        if remaining:
            left = deadline - time.monotonic()
            require(left > 0, f"Central propagation deadline exceeded: {len(remaining)} artifacts/signatures missing")
            print(f"Waiting for {len(remaining)} Central artifacts/signatures", flush=True)
            time.sleep(min(delay, left))
            delay = min(delay * 2, 60)
    print("10/10 exact Central artifact hashes match; 10/10 detached signatures present")


def test_results(focused=False):
    files = list((ROOT / "core/build/test-results/test").glob("TEST-*.xml"))
    if not focused:
        files += list((ROOT / "storage-nio/build/test-results/test").glob("TEST-*.xml"))
    require(files, "No JUnit test evidence")
    suites = {ET.parse(path).getroot().attrib["name"]: ET.parse(path).getroot() for path in files}
    total = 0
    for suite in suites.values():
        total += int(suite.attrib["tests"])
        require(all(int(suite.attrib.get(key, "0")) == 0 for key in ("failures", "errors", "skipped")), "JUnit failures/errors/skips")
    wanted = {"org.totipo.conformance.SpecSnapshotIntegrityTest": 3, "org.totipo.conformance.R18ProfileIntegrityTest": 1}
    for name, count in wanted.items():
        require(name in suites and int(suites[name].attrib["tests"]) == count, f"Missing explicit integrity accounting: {name}")
    if not focused:
        corpus = suites.get("org.totipo.format.Phase2ConformanceTest")
        require(corpus is not None and any(t.attrib["name"].startswith("everyImplementedCaseExecutesWithoutSkipping") for t in corpus.findall("testcase")), "Missing explicit 90/90 portable-case execution test")
        print("90/90 portable cases: exact-set execution assertion passed")
    print(f"{total} JUnit tests; zero failures/errors/skips; snapshot 3/3; profile 1/1")


def secrets():
    for name, prop in [("MAVEN_CENTRAL_USERNAME", "mavenCentralUsername"), ("MAVEN_CENTRAL_PASSWORD", "mavenCentralPassword"), ("SIGNING_IN_MEMORY_KEY", "signingInMemoryKey")]:
        require(bool(os.environ.get("ORG_GRADLE_PROJECT_" + prop)), f"Missing required environment secret: {name}")
    # GPG only inspects packet metadata from stdin; it does not import the key.
    # Its output (which can contain private packet details) stays in memory.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="totipo-key-inspection-") as directory:
        result = subprocess.run(["gpg", "--no-options", "--batch", "--no-autostart",
                                 "--homedir", directory, "--pinentry-mode", "error", "--list-packets"],
                                input=os.environ["ORG_GRADLE_PROJECT_signingInMemoryKey"],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(":secret key packet:" in result.stdout, "SIGNING_IN_MEMORY_KEY is not a readable OpenPGP private key")
    encrypted = "protected" in result.stdout or "protect algo:" in result.stdout
    if encrypted:
        require(bool(os.environ.get("ORG_GRADLE_PROJECT_signingInMemoryKeyPassword")),
                "Missing required environment secret for encrypted key: SIGNING_IN_MEMORY_KEY_PASSWORD")
    print("Required environment secrets are present; signing task will validate the key/password")


def tag_release():
    identity(allow_tag=True)
    version, commit = inputs()
    tag = f"v{version}"
    require(git("cat-file", "-t", "v0.1.0") == "tag", "Established source-tag style must remain annotated")
    require("-----BEGIN PGP SIGNATURE-----" not in git("cat-file", "-p", "v0.1.0"), "Existing source-tag signing policy needs human review")
    notes = (ROOT / "review/V0_1_1_RELEASE_NOTES.md").read_text()
    require(notes.startswith(f"## {tag}\n"), "Reviewed release notes do not match requested version; update the release workflow for the next version")
    body = notes.rstrip() + f"\n\n### Release provenance\n\n- Java source commit: `{commit}`\n- Totipo v1/r18 spec commit: `{SPEC_COMMIT}`\n- Portable corpus: 90/90 executed, none deferred.\n"
    record = release_record(version)
    if record:
        require(record["tag_name"] == tag and record["name"] == tag and not record["draft"] and not record["prerelease"] and record["body"].replace("\r\n", "\n").rstrip() == body.rstrip(), "Existing GitHub release is inconsistent; do not overwrite")
        require(bool(git("ls-remote", "--tags", "origin", f"refs/tags/{tag}")), "Existing release has no remote source tag")
        require(git("cat-file", "-t", tag) == "tag", "Existing source tag must be annotated")
        print("Existing source tag and GitHub release verified")
        return
    git("config", "user.name", "github-actions[bot]")
    git("config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
    if not git("tag", "--list", tag):
        git("-c", "tag.gpgSign=false", "tag", "-a", tag, commit, "-m", f"totipo-java {version}")
    require(git("cat-file", "-t", tag) == "tag", "Source tag must be annotated")
    # Token goes in an ephemeral process environment, never in persisted Git config.
    push_env = os.environ.copy()
    push_env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
                    GIT_CONFIG_VALUE_0="AUTHORIZATION: basic " + base64.b64encode(("x-access-token:" + os.environ["GH_TOKEN"]).encode()).decode())
    git("push", "origin", f"refs/tags/{tag}", env=push_env)
    import tempfile
    with tempfile.TemporaryDirectory(prefix="totipo-release-body-") as directory:
        path = Path(directory) / "body.md"
        path.write_text(body)
        subprocess.run(["gh", "release", "create", tag, "--repo", os.environ["GITHUB_REPOSITORY"], "--verify-tag", "--title", tag, "--notes-file", str(path)], check=True, cwd=ROOT)
    print("Annotated source tag pushed and GitHub release created after Central verification")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["inputs", "identity", "state", "inventory", "compare", "signed", "remote", "tests", "focused-tests", "secrets", "upload-ready", "tag-release"])
    args = parser.parse_args()
    if args.command == "upload-ready":
        require(central_state() == "publish", "Central version appeared; skip upload and rerun for strict verification")
    elif args.command == "state":
        state = central_state()
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write(f"mode={state}\n")
    elif args.command == "inventory":
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write("inventory=" + json.dumps(inventory(), separators=(",", ":"), sort_keys=True) + "\n")
    else:
        {"inputs": inputs, "identity": identity, "compare": compare_inventory, "signed": signed,
         "remote": verify_remote, "tests": test_results, "focused-tests": lambda: test_results(True),
         "secrets": secrets, "tag-release": tag_release}[args.command]()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Release check failed: {error}", file=sys.stderr)
        sys.exit(1)
