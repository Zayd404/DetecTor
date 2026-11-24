import json
from pathlib import Path
from datetime import datetime, timezone

from .metadata import generate_metadata


def save_json_report(
    data,
    output_dir="reports",
    version="unknown",
    report_type="web_recon",
):
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = f"detector_report_{timestamp}.json"
    filepath = directory / filename

    report = {
        "metadata": generate_metadata(version, report_type),
        "results": data,
    }

    with filepath.open("w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False,
            default=str,
        )

    return filepath
