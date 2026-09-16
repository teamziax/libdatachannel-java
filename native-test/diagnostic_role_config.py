#!/usr/bin/env python3
"""Offline executable config validation; no peer, STUN or network test is started."""
import json
import pathlib
import subprocess
import sys
import tempfile
import time

argv = pathlib.Path(sys.argv[1]).read_text().splitlines()
with tempfile.TemporaryDirectory(prefix="diagnostic-config-") as directory:
    root = pathlib.Path(directory)
    key = root / "key.pem"
    key.write_text("private fixture; never parsed by --validate-config")
    key.chmod(0o600)
    config = {
        "version": "1", "role": "host", "mode": "first-contact", "bindAddress": "127.0.0.1", "localPort": "39000",
        "peerAddress": "127.0.0.1", "peerPort": "39100", "publicAddress": "127.0.0.1", "publicPort": "39000",
        "expiresAtMillis": str(int(time.time() * 1000) + 110000), "maxDurationMillis": "10000",
        "certificatePath": str(root / "cert.pem"), "keyPath": str(key),
        "localUfrag": "a" * 32, "localPassword": "b" * 32, "remoteUfrag": "c" * 32, "remotePassword": "d" * 32,
        "remoteFingerprint": ":".join(["AB"] * 32), "offerPath": str(root / "offer.sdp"), "answerPath": str(root / "answer.sdp")}
    def render(value):
        return "".join(k + "=" + v + "\n" for k, v in value.items())
    cases = [("valid", render(config), 0o600, True),
             ("assisted", render({**config, "mode": "assisted"}), 0o600, True),
             ("ipv6", render({**config, "bindAddress": "::1", "peerAddress": "::1", "publicAddress": "::1"}), 0o600, True)]
    for name, changed in [
        ("expired", {"expiresAtMillis": "1"}),
        ("excessive-duration", {"maxDurationMillis": "120001"}),
        ("hostname", {"peerAddress": "example.invalid"}),
        ("port", {"localPort": "65536"}),
        ("unsupported-mode", {"mode": "unknown"}),
        ("wrong-family", {"peerAddress": "::1"}),
        ("secret-escape", {"localPassword": "\\u0061" * 32}),
        ("relative-path", {"keyPath": "key.pem"})]:
        cases.append((name, render({**config, **changed}), 0o600, False))
    cases += [("duplicate", render(config) + "localPort=39000\n", 0o600, False),
              ("unknown", render(config) + "extra=value\n", 0o600, False),
              ("permissions", render(config), 0o644, False),
              ("oversized", "x" * 65537, 0o600, False)]
    for name, text, permissions, valid in cases:
        path = root / (name + ".properties")
        path.write_text(text); path.chmod(permissions)
        result = subprocess.run(argv + ["--validate-config", str(path)], capture_output=True, text=True, timeout=5)
        assert (result.returncode == 0) == valid, (name, result.returncode, result.stdout, result.stderr)
        event = json.loads(result.stdout)
        assert event["event"] == ("config_valid" if valid else "failed"), (name, event)
        assert config["localPassword"] not in result.stdout and str(key) not in result.stdout
print(f"diagnostic role config PASS cases={len(cases)} networkStarted=false")
