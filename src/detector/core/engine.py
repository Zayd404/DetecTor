from detector.common.system_info import get_system_info
from detector.modules.web_recon.domain import normalize_target
from detector.modules.web_recon.dns import lookup_dns
from detector.modules.web_recon.headers import inspect_headers
from detector.modules.web_recon.technology import identify_technology
from detector.modules.web_recon.ssl import inspect_ssl
from detector.modules.web_recon.attack_surface import (
    detect_waf_and_stack,
    check_sensitive_paths,
    enumerate_subdomains,
)
from detector.modules.web_recon.ip_recon import (
    normalize_ip_target, inspect_ip_network,
    lookup_ip_geolocation, lookup_passive_exposure, probe_direct_http,
)
from detector.reporting import (
    save_json_report,
    save_text_report,
)
from pathlib import Path

from .config import Config
from .logger import setup_logger


class DetecTorEngine:
    def __init__(self, config_path=None):
        self.config = Config.load(config_path)

        log_dir = self.config.get(
            "logging", "output_directory", "logs"
        )
        log_level = self.config.get("logging", "level", "INFO")

        self.logger = setup_logger(log_dir, log_level)
        self.name = self.config.get("app", "name", "DetecTor")
        self.version = self.config.get("app", "version", "1.1.0")

    def web_recon(self, target, authorized=False):
        if not authorized:
            raise PermissionError(
                "Konfirmasi izin diperlukan sebelum pemeriksaan."
            )

        url = normalize_target(target)

        self.logger.info("Starting Web Recon: %s", url)

        results = {
            "target": url,
            "dns": lookup_dns(url),
            "headers": inspect_headers(url),
            "technology": identify_technology(url),
            "attack_surface": detect_waf_and_stack(url),
            "sensitive_paths": check_sensitive_paths(url),
            "subdomains": enumerate_subdomains(url),
        }

        if url.startswith("https://"):
            results["ssl"] = inspect_ssl(url)
        else:
            results["ssl"] = {
                "note": "SSL inspection requires HTTPS."
            }

        self.logger.info("Web Recon completed: %s", url)

        report_dir = self.config.get(
            "reporting", "output_directory", "reports"
        )

        formats = self.config.get(
            "reporting", "format", ["json"]
        )

        report_paths = {}

        if "json" in formats:
            report_paths["json"] = str(save_json_report(
                results,
                report_dir,
                version=self.version,
                report_type="web_recon",
            ))

        if "txt" in formats:
            report_paths["txt"] = str(save_text_report(
                results,
                report_dir,
                version=self.version,
                report_type="web_recon",
            ))

        if report_paths:
            results["report"] = report_paths.get(
                "json", next(iter(report_paths.values()))
            )
            results["reports"] = report_paths

        return results



    def ip_recon(self, target, authorized=False):
        if not authorized:
            raise PermissionError("Konfirmasi izin diperlukan sebelum pemeriksaan.")
        ip_target = normalize_ip_target(target)
        self.logger.info("Starting IP Recon: %s", ip_target)
        results = {
            "target": ip_target,
            "network": inspect_ip_network(ip_target),
            "geolocation": lookup_ip_geolocation(ip_target),
            "exposure": lookup_passive_exposure(ip_target),
            "web_services": probe_direct_http(ip_target),
        }
        self.logger.info("IP Recon completed: %s", ip_target)
        report_dir = self.config.get("reporting", "output_directory", "reports")
        formats = self.config.get("reporting", "format", ["json"])
        report_paths = {}
        if "json" in formats:
            report_paths["json"] = str(save_json_report(results, report_dir, version=self.version, report_type="ip_recon"))
        if "txt" in formats:
            report_paths["txt"] = str(save_text_report(results, report_dir, version=self.version, report_type="ip_recon"))
        if report_paths:
            results["report"] = report_paths.get("json", next(iter(report_paths.values())))
            results["reports"] = report_paths
        return results

    def save_people_report(self, results: dict, report_type: str = "people_osint") -> dict:
        if not results.get("valid"):
            return results
        report_dir = self.config.get("reporting", "output_directory", "reports")
        formats = self.config.get("reporting", "format", ["json"])
        report_paths = {}
        if "json" in formats:
            report_paths["json"] = str(save_json_report(results, report_dir, version=self.version, report_type=report_type))
        if "txt" in formats:
            report_paths["txt"] = str(save_text_report(results, report_dir, version=self.version, report_type=report_type))
        if report_paths:
            results["report"] = report_paths.get("json", next(iter(report_paths.values())))
            results["reports"] = report_paths
        return results

    def status(self):
        return {
            "name": self.name,
            "version": self.version,
            "web_recon": self.config.get("web_recon", "enabled", False),
            "people_osint": self.config.get(
                "people_osint", "enabled", False
            ),
            "system": get_system_info(),
        }

    def initialize(self):
        self.logger.info(
            "%s v%s initialized", self.name, self.version
        )
        return self.status()
