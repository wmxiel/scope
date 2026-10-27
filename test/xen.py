import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


project = Path(__file__).resolve().parent.parent
headers = Path(sys.argv[1] if len(sys.argv) > 1 else "/usr/include").resolve()
if not (headers / "xenctrl.h").exists():
    raise SystemExit("xen headers missing; pass their include directory")

with tempfile.TemporaryDirectory(prefix="scopexen") as directory:
    root = Path(directory)
    environment = dict(os.environ)
    environment["C_INCLUDE_PATH"] = str(headers)
    build = root / "build"
    subprocess.run(["dune", "build", "--build-dir", str(build), "bin/main.exe"], cwd=project, env=environment, check=True)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", "-I", str(headers),
                    str(project / "test/native.c"), "-o", str(root / "libxenctrl.so")], check=True)
    (root / "libxenforeignmemory.so").symlink_to(root / "libxenctrl.so")
    environment["LD_LIBRARY_PATH"] = str(root)
    environment["SCOPE_TEST_LOG"] = str(root / "log")
    environment["OCAMLRUNPARAM"] = "s=4k"
    scope = build / "default/bin/main.exe"
    checks = 0

    def run(failure=None, paused=False, pause=True, status=0):
        global checks
        env = dict(environment)
        if failure:
            env["SCOPE_TEST_FAILURE"] = failure
        if paused:
            env["SCOPE_TEST_PAUSED"] = "1"
        log = root / "log"
        log.unlink(missing_ok=True)
        command = [str(scope), "capture", "7", str(root / "capture"), "--vcpu", "0", "--phys-bits", "48",
                   "--nx", "on", "--gb-pages", "on", "--json"]
        if pause:
            command.append("--pause")
        result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=10)
        assert result.returncode == status, (failure, result.stdout, result.stderr)
        records = log.read_text().splitlines()
        if failure not in ("open", "logged"):
            assert records[-1].startswith("close ")
        if pause and failure not in ("open", "logged", "info", "pause", "identity", "unpause"):
            assert f"unpause {int(paused)}" in records, records
            assert f"close {int(paused)}" == records[-1], records
        if not pause:
            assert not any(line.startswith("unpause ") for line in records), records
        if failure is None:
            assert sum(line.startswith("map ") for line in records) == sum(line.startswith("unmap ") for line in records)
        if failure == "page":
            assert sum(line.startswith("map ") for line in records) == sum(line.startswith("unmap ") for line in records) == 1
        if failure == "unmap":
            assert sum(line.startswith("unmap ") for line in records) == 2
        checks += 1
        return json.loads(result.stdout or result.stderr), records

    run()
    run(paused=True)
    run(paused=True, pause=False)
    run(pause=False, status=2)
    for failure in ("logged", "info", "pause", "foreignopen", "registers", "map", "page", "unmap", "unpause", "identity", "signal", "opensignal"):
        run(failure=failure, status=2)
    environment["SCOPE_TEST_WATCH"] = "1"
    log = root / "log"
    log.unlink()
    result = subprocess.run([str(scope), "watch", "7", str(root / "history"), "--vcpu", "0", "--phys-bits", "48",
                             "--nx", "on", "--gb-pages", "on", "--pause", "--interval", "0.001", "--count", "4",
                             "--retain", "2", "--aliases", "--json"], env=environment, text=True, capture_output=True, timeout=10)
    assert result.returncode == 1, (result.stdout, result.stderr)
    events = [json.loads(line) for line in result.stdout.splitlines()]
    assert [event["event"] for event in events] == ["baseline", "change", "sample", "address_space"]
    assert events[0]["summary"]["mappings"] == 2
    assert events[1]["changes"][0]["kinds"] == ["backing"]
    assert len(list((root / "history").iterdir())) == 2
    records = log.read_text().splitlines()
    assert records.count("pause 1") == records.count("unpause 0") == 4
    print(f"{checks} xen api fault-injection checks and a four-sample watch passed; no hypervisor was used")
