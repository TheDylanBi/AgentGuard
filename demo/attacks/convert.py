"""Convert a raw dataset into normalized auth samples.

Usage:
  python demo/attacks/convert.py --adapter wasp \\
      --input demo/attacks/data/raw/wasp_sample.json \\
      --output demo/attacks/data/converted.json
"""
import argparse
import json
from pathlib import Path

from adapters import ADAPTERS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", required=True, choices=sorted(ADAPTERS))
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    raw = json.loads(Path(args.input).read_text(encoding="utf-8"))
    adapter = ADAPTERS[args.adapter]()

    samples = []
    for r in raw:
        samples.extend(adapter.convert(r))

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(samples, ensure_ascii=False, indent=2), encoding="utf-8")
    attacks = sum(1 for s in samples if s["category"] == "attack")
    benign = sum(1 for s in samples if s["category"] == "benign")
    print(f"converted {len(raw)} raw samples -> {len(samples)} normalized "
          f"({attacks} attacks + {benign} benign)")
    print(f"-> {out}")


if __name__ == "__main__":
    main()
