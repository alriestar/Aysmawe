#!/usr/bin/env python3
"""Unduh IOC stalkerware dari AssoEchap/stalkerware-indicators lalu tulis versi JSON ringkas
ke app/src/main/assets/stalkerware_ioc.json.

Data berlisensi CC-BY 4.0 (c) Echap: https://github.com/AssoEchap/stalkerware-indicators

Pemakaian: python3 tools/update_ioc.py   (butuh PyYAML)
"""
import datetime
import json
import pathlib
import urllib.request

import yaml

BASE = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/"
SOURCES = ["ioc.yaml", "watchware.yaml"]
OUT = pathlib.Path(__file__).resolve().parent.parent / "app/src/main/assets/stalkerware_ioc.json"


def main():
    apps = []
    for name in SOURCES:
        with urllib.request.urlopen(BASE + name, timeout=60) as resp:
            entries = yaml.safe_load(resp.read())
        for e in entries:
            packages = sorted(set(e.get("packages") or []))
            certs = sorted({c.upper() for c in e.get("certificates") or []})
            if not packages and not certs:
                continue
            apps.append({
                "name": e["name"],
                "type": e.get("type", "stalkerware"),
                "packages": packages,
                "certificates": certs,
            })

    data = {
        "source": "https://github.com/AssoEchap/stalkerware-indicators",
        "license": "CC-BY 4.0, Echap",
        "updated": datetime.date.today().isoformat(),
        "apps": apps,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, separators=(",", ":"), ensure_ascii=False))
    print(f"{len(apps)} entri -> {OUT}")


if __name__ == "__main__":
    main()
