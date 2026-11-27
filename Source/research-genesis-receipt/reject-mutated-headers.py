"""Exercise the actual guest with invalid public witnesses. No private wallet inputs."""
import argparse
import pathlib
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("verifier", type=pathlib.Path)
    parser.add_argument("public_header_dump", type=pathlib.Path)
    args = parser.parse_args()
    with args.public_header_dump.open("rb") as file:
        prefix = file.read(804)
    assert len(prefix) == 804
    assert prefix[:2] == prefix[402:404] == (400).to_bytes(2, "big")
    # Flip one bit of a canonical field of the h1 witness. The exact genesis stays fixed.
    for label, index in (("wrong_version", 1), ("wrong_height", 9), ("wrong_parent", 18),
                         ("wrong_parent_root", 50), ("wrong_total_work", 233),
                         ("wrong_scaling", 237), ("wrong_graph", 246), ("broken_cycle", 247)):
        data = bytearray(prefix)
        data[404 + index] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            src = root / "invalid-header.bin"
            src.write_bytes(data)
            out = root / "result"
            run = subprocess.run([args.verifier.resolve(), "prove", src, out],
                                 capture_output=True, text=True, timeout=240)
            if run.returncode != 1 or out.exists() or "local r0vm prover failed" not in run.stderr:
                raise RuntimeError(f"{label}: expected an explicit refusal from the guest/prover; "
                                   f"exit={run.returncode} output_dir={out.exists()} {run.stderr}")
            print(f"PASS {label}", flush=True)


if __name__ == "__main__":
    main()

