import json
from pathlib import Path
import subprocess
import sys
import tempfile


executable = str(Path(sys.argv[1]).resolve())
checks = 0


def run(*args, status=0, structured=True):
    global checks
    command = [executable, *map(str, args)]
    if structured:
        command.append("--json")
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert result.returncode == status, (command, result.returncode, result.stdout, result.stderr)
    checks += 1
    if structured:
        value = json.loads(result.stdout if result.stdout else result.stderr)
        assert value["schema"] == "scope.report.v1"
        return value
    return result.stdout


with tempfile.TemporaryDirectory(prefix="scope") as directory:
    root = Path(directory)
    run("demo", root)
    before, after = root / "before", root / "after"
    assert run("info", before)["pages"] == 5
    result = run("walk", before, "0x400abc")
    assert result["result"]["mapping"]["physical"] == "0x0000000000009abc"
    result = run("explain", before, "0x400000", "--access", "write", "--privilege", "supervisor", status=1)
    assert result["result"]["fault"]["level"] == 2
    assert result["result"]["fault"]["error_code"] == 3
    assert len(run("aliases", before, status=1)["aliases"]) == 1
    assert run("aliases", after)["aliases"] == []
    assert len(run("diff", before, after, status=1)["changes"]) == 2
    assert run("diff", before, before)["changes"] == []
    assert len(run("mappings", before, "--start", "0x800000")["regions"]) == 1
    assert run("walk", before, "0x800000000000", status=1)["result"]["fault"]["vector"] == 13
    overridden = run("walk", before, "0x400000", "--root", "0x6000", status=2)
    assert overridden["complete"] is False
    assert overridden["context"]["registers"]["cr3"] == "0x0000000000001000"
    assert overridden["context"]["root"] == "0x0000000000006000"
    run("explain", before, "0x400000", status=64)
    run("walk", before, "0x400000", "--include-ad", status=64)
    run("walk", before, "0x400000", "--root", "0x1000", "--root", "0x2000", status=64)
    run("mappings", before, "--max-entries", "1", status=2)
    run("capture", "0", root / "capture", "--vcpu", "0", "--phys-bits", "48", "--nx", "on", "--gb-pages", "on", status=2)
    run("walk", before, "-1", status=64)
    run("unknown", status=64)
    run("watch", "7", root / "history", "--interval", "nan", status=64)
    run("watch", "7", root / "history", "--retain", "0", status=64)
    run("walk", before, "0x400000", "--count", "2", status=64)
    run("info", root / "missing", status=2)
    text = run("explain", before, "0x400000", "--access", "write", "--privilege", "supervisor", status=1, structured=False)
    assert "level=2" in text and "error=0x3" in text
    damaged = root / "damaged"
    damaged.write_bytes(before.read_bytes()[:-1])
    run("info", damaged, status=2)
    transcript = root / "transcript"
    transcript.write_text("context 0x80010001 0x0 0x1000 0x20 0xd00 0x2 0x0 48 1 1\nmissing 0x1000 permission denied\n")
    run("import", transcript, root / "partial", "--source", 'quote" and newline\n', status=2)
    assert run("walk", root / "partial", "0x0", status=2)["result"]["reason"] == "permission denied"
    partial = run("diff", before, root / "partial", status=2)
    assert all(change["kinds"] == ["incomplete"] for change in partial["changes"])
    page = (0x83).to_bytes(8, "little") + bytes(4088)
    transcript.write_text("context 0x80010001 0x0 0x1000 0x20 0xd00 0x2 0x0 48 1 1\npage 0x1000 " + page.hex() + "\n")
    run("import", transcript, root / "invalid")
    assert run("mappings", root / "invalid", status=1)["regions"][0]["state"]["status"] == "invalid"
    assert run("aliases", root / "invalid", status=1)["aliases"] == []

print(f"{checks} cli checks passed")
