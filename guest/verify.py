import json
from pathlib import Path
import subprocess
import sys
import tempfile


scope = Path(sys.argv[1]).resolve()
disk = Path(sys.argv[2]).resolve()
with tempfile.TemporaryDirectory(prefix="scopeguest") as directory:
    root = Path(directory)
    transcript = root / "transcript"
    command = [
        "qemu-system-x86_64", "-machine", "pc,accel=tcg", "-cpu", "max",
        "-m", "32M", "-display", "none", "-serial", "none", "-monitor", "none",
        "-no-reboot", "-drive", f"format=raw,file={disk}",
        "-debugcon", f"file:{transcript}", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
    except subprocess.TimeoutExpired:
        print(transcript.read_text()[-2000:] if transcript.exists() else "no guest output", file=sys.stderr)
        raise
    assert result.returncode == 33, (result.returncode, result.stderr, transcript.read_text()[-2000:])
    lines = transcript.read_text().splitlines()
    assert lines[-1] == "done", "guest did not finish"
    current = None
    checks = 0
    discrepancies = 0
    for line in lines:
        if line.startswith("begin "):
            _, name, access, address, privilege = line.split()
            current = []
        elif line.startswith("context ") or line.startswith("page "):
            assert current is not None
            current.append(line)
        elif line.startswith("observed "):
            _, vector, error = line.split()
            observed = int(vector), int(error)
        elif line == "end":
            assert current is not None
            source = root / "source"
            capture = root / "capture"
            source.write_text("\n".join(current) + "\n")
            subprocess.run([str(scope), "import", str(source), str(capture), "--source", f"qemu guest case {name}"],
                           check=True, capture_output=True, text=True)
            result = subprocess.run([str(scope), "explain", str(capture), address, "--access",
                                     ["read", "write", "execute"][int(access)], "--privilege", privilege, "--json"],
                                    capture_output=True, text=True, timeout=10)
            assert result.returncode in (0, 1), (name, result.stderr)
            prediction = json.loads(result.stdout)["result"]
            if prediction["status"] == "mapped":
                predicted = 0, 0
            else:
                predicted = prediction["fault"]["vector"], prediction["fault"]["error_code"]
            if observed != predicted:
                known = name in {"reserved", "nxe", "alignment", "pml"} and observed == (14, predicted[1] & ~1) and predicted == (14, 9)
                assert known, (name, "observed", observed, "predicted", predicted, prediction)
                discrepancies += 1
                print(f"{name}: known tcg discrepancy, observed=0x{observed[1]:x} architectural=0x{predicted[1]:x}")
            else:
                print(f"{name}: vector={observed[0]} error=0x{observed[1]:x}")
            checks += 1
            current = None
    assert checks == 31, checks
    print(f"{checks - discrepancies} exact guest comparisons, {discrepancies} reserved-bit tcg discrepancies")
