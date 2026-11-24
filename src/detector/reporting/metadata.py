from datetime import datetime, timezone


def generate_metadata(version="unknown", report_type="web_recon"):
    return {
        "framework": "DetecTor",
        "version": version,
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "report_type": report_type,
    }
