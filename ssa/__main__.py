from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .common.errors import SSAError
from .common.logging import configure_logging
from .core.engine import analyze
from .gui.app import run_gui


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssa",
        description="Sentinel Static Analyzer ile EXE statik analiz aracı",
    )
    parser.add_argument("path", nargs="?", help="Analiz edilecek EXE dosya yolu")
    parser.add_argument(
        "--yara-rules",
        dest="yara_rules",
        default=None,
        help="YARA kural dosyaları dizini",
    )
    parser.add_argument(
        "--gui",
        dest="gui",
        action="store_true",
        help="Grafik arayüzü başlat",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Sonucu JSON formatında yazdır",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv[1:]
    logger = configure_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.gui:
        initial = Path(args.path) if args.path else None
        run_gui(initial)
        return
    if not args.path:
        parser.print_help()
        return
    target = Path(args.path)
    yara_dir = Path(args.yara_rules) if args.yara_rules else None
    try:
        result = analyze(target, yara_rules_dir=yara_dir)
    except SSAError as exc:
        logger.error(str(exc))
        sys.exit(1)
    if args.as_json:
        payload = result.to_dict()
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        score = result.score
        print(f"Dosya: {result.file_path}")
        print(f"Toplam risk skoru: {score.total} ({score.level})")
        print(f"Ayrıntılar için --json ile çalıştırabilirsiniz.")


if __name__ == "__main__":
    main()
