from ipaddress import ip_address

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def _status_style(status):
    styles = {
        "PRESENT": "green",
        "GOOD": "green",
        "VALID": "green",
        "ACCEPTABLE": "yellow",
        "MISSING": "yellow",
        "INVALID": "red",
        "EXPIRED": "red",
        "OUTDATED": "red",
        "NOT_APPLICABLE": "dim",
        "UNKNOWN": "yellow",
    }
    return styles.get(str(status).upper(), "white")


def _display_value(value):
    if value is None:
        return "N/A"

    if isinstance(value, (dict, list)):
        return str(value)

    return str(value)


def render_web_report(results, console=None):
    console = console or Console()

    if not isinstance(results, dict):
        results = {}

    target = results.get("target", "Unknown target")

    console.print()
    console.print(
        Panel(
            Text(str(target), style="bold white"),
            title="[bold red]DETECTOR WEB RECON[/bold red]",
            border_style="red",
        )
    )

    _render_dns(results.get("dns"), console)
    _render_headers(results.get("headers"), console)
    _render_technology(results.get("technology"), console)
    _render_ssl(results.get("ssl"), console)
    _render_attack_surface(results.get("attack_surface"), console)
    _render_sensitive_paths(results.get("sensitive_paths"), console)
    _render_subdomains(results.get("subdomains"), console)

    reports = results.get("reports", {})

    if not isinstance(reports, dict):
        reports = {}

    if reports:
        report_lines = Text()

        for index, (name, report_path) in enumerate(reports.items()):
            if index:
                report_lines.append("\n")

            report_lines.append(str(name).upper(), style="green")
            report_lines.append(": ")
            report_lines.append(str(report_path))

        console.print(
            Panel(
                report_lines,
                title="REPORT FILES",
                border_style="green",
            )
        )
    elif results.get("report"):
        report_line = Text("Report saved: ", style="green")
        report_line.append(str(results["report"]))
        console.print(report_line)


def _render_dns(data, console):
    table = Table(title="DNS RECORDS")
    table.add_column("TYPE", style="cyan")
    table.add_column("VALUE", style="white")

    if not isinstance(data, dict):
        table.add_row("STATUS", "Unavailable")
    else:
        for record_type, key in (
            ("IPv4", "ipv4"),
            ("IPv6", "ipv6"),
        ):
            values = data.get(key, [])

            if not isinstance(values, (list, tuple)):
                table.add_row(record_type, "Invalid DNS data")
                continue

            if values:
                for value in values:
                    if not isinstance(value, str):
                        table.add_row(record_type, "Invalid DNS record")
                        continue

                    try:
                        address = ip_address(value)
                    except ValueError:
                        table.add_row(record_type, "Invalid DNS record")
                        continue

                    expected_version = 4 if record_type == "IPv4" else 6

                    if address.version != expected_version:
                        table.add_row(record_type, "Invalid DNS record")
                        continue

                    table.add_row(record_type, str(address))
            else:
                table.add_row(record_type, "No records")

        error = data.get("error")

        if isinstance(error, str) and error.strip():
            table.add_row("ERROR", Text(error.strip()))

    console.print(table)


def _render_headers(data, console):
    table = Table(title="HTTP SECURITY HEADERS")
    table.add_column("HEADER", style="cyan")
    table.add_column("STATUS")
    table.add_column("RECOMMENDATION")

    if not isinstance(data, dict):
        table.add_row("STATUS", "Unavailable", "N/A")
        console.print(table)
        return

    status_code = data.get("status")
    method = data.get("method")

    if isinstance(status_code, int) and not isinstance(status_code, bool):
        console.print(
            f"[bold]HTTP Status:[/bold] [cyan]{status_code}[/cyan]"
        )

    if isinstance(method, str) and method.strip():
        method_text = Text("Request Method: ", style="bold")
        method_text.append(method.strip(), style="cyan")
        console.print(method_text)

    analysis = data.get("security_analysis", {})

    if not isinstance(analysis, dict):
        analysis = {}

    headers = analysis.get("headers", {})

    if not isinstance(headers, dict):
        headers = {}

    for name, details in headers.items():
        if not isinstance(details, dict):
            details = {}

        status = details.get("status", "UNKNOWN")

        if not isinstance(status, str) or not status.strip():
            status = "UNKNOWN"

        recommendation = details.get("recommendation")

        if not isinstance(recommendation, str) or not recommendation.strip():
            recommendation = "-"

        status_text = Text(
            str(status),
            style=_status_style(status),
        )

        table.add_row(
            str(name),
            status_text,
            str(recommendation),
        )

    if not headers:
        table.add_row("STATUS", "Unavailable", "N/A")

    console.print(table)

    summary = analysis.get("summary", {})

    if not isinstance(summary, dict):
        summary = {}

    if summary:
        summary_values = {}

        for key in ("present", "missing", "invalid", "not_applicable"):
            value = summary.get(key, 0)

            if not isinstance(value, int) or isinstance(value, bool):
                value = 0

            summary_values[key] = value

        summary_text = Text("Header summary: ", style="bold")
        summary_text.append(
            f"Present: {summary_values['present']}  ",
            style="green",
        )
        summary_text.append(
            f"Missing: {summary_values['missing']}  ",
            style="yellow",
        )
        summary_text.append(
            f"Invalid: {summary_values['invalid']}  ",
            style="red",
        )
        summary_text.append(
            f"Not applicable: {summary_values['not_applicable']}"
        )

        console.print(summary_text)

    error = data.get("error")

    if isinstance(error, str) and error.strip():
        error_text = Text("HTTP error: ", style="red")
        error_text.append(error.strip())
        console.print(error_text)


def _render_technology(data, console):
    table = Table(title="TECHNOLOGY DETECTION")
    table.add_column("SOURCE", style="cyan")
    table.add_column("VALUE", style="white")

    if not isinstance(data, dict):
        table.add_row("STATUS", "Unavailable")
    else:
        technologies = data.get("technologies", [])

        if not isinstance(technologies, (list, tuple)):
            technologies = []
            table.add_row(
                "STATUS",
                "Invalid technology data",
            )

        for item in technologies:
            if not isinstance(item, dict):
                table.add_row(
                    "Unknown",
                    "Invalid technology data",
                )
                continue

            source_value = item.get("source", "Unknown")
            technology_value = item.get("value", "N/A")

            if not isinstance(source_value, str) or not source_value.strip():
                source_value = "Unknown"

            if not isinstance(technology_value, str) or not technology_value.strip():
                technology_value = "N/A"

            table.add_row(
                Text(source_value.strip()),
                Text(technology_value.strip()),
            )

        if not technologies:
            table.add_row("TECHNOLOGY", "No public headers detected")

        methods = data.get("allowed_methods", [])

        if isinstance(methods, (list, tuple)):
            valid_methods = [
                method.strip()
                for method in methods
                if isinstance(method, str) and method.strip()
            ]

            if valid_methods:
                methods_text = Text(", ".join(valid_methods))
                table.add_row(
                    "HTTP METHODS",
                    methods_text,
                )

            if len(valid_methods) != len(methods):
                table.add_row(
                    "STATUS",
                    "Invalid HTTP method data",
                )
        elif methods:
            table.add_row(
                "STATUS",
                "Invalid HTTP methods collection",
            )

        error = data.get("error")

        if isinstance(error, str) and error.strip():
            table.add_row("ERROR", Text(error.strip()))

    console.print(table)


def _render_ssl(data, console):
    table = Table(title="SSL / TLS INSPECTION")
    table.add_column("PROPERTY", style="cyan")
    table.add_column("VALUE")

    if not isinstance(data, dict):
        table.add_row("STATUS", "Unavailable")
    else:
        note = data.get("note")

        if isinstance(note, str) and note.strip():
            table.add_row("STATUS", Text(note.strip()))
            console.print(table)
            return

        fields = (
            ("TLS Version", "tls_version"),
            ("TLS Grade", "tls_grade"),
            ("Certificate", "certificate_grade"),
            ("Issuer", "issuer"),
            ("Valid From", "valid_from"),
            ("Valid Until", "valid_until"),
            ("Days Remaining", "days_remaining"),
        )

        for label, key in fields:
            value = data.get(key)

            if key == "days_remaining":
                if not isinstance(value, int) or isinstance(value, bool):
                    value = None
            elif not isinstance(value, str) or not value.strip():
                value = None

            if key in ("tls_grade", "certificate_grade"):
                style = _status_style(value)
                value = Text(_display_value(value), style=style)
            else:
                value = Text(_display_value(value))

            table.add_row(label, value)

        error = data.get("error")

        if isinstance(error, str) and error.strip():
            table.add_row("ERROR", Text(error.strip()))

    console.print(table)


def render_ip_report(results, console=None):
    console = console or Console()
    if not isinstance(results, dict):
        results = {}

    target = results.get("target", "Unknown IP")
    console.print()
    console.print(Panel(Text(str(target), style="bold white"), title="[bold red]DETECTOR IP ADDRESS RECON[/bold red]", border_style="red"))

    net = results.get("network", {})
    net_table = Table(title="NETWORK & REVERSE DNS")
    net_table.add_column("PROPERTY", style="cyan")
    net_table.add_column("VALUE", style="white")
    if isinstance(net, dict):
        net_table.add_row("IP Version", str(net.get("version", "N/A")))
        net_table.add_row("Reverse DNS (PTR)", str(net.get("reverse_dns", "N/A")))
        net_table.add_row("Address Scope", "Public / Global" if net.get("is_global") else "Private / Local")
    console.print(net_table)

    geo = results.get("geolocation", {})
    geo_table = Table(title="GEOLOCATION & ASN")
    geo_table.add_column("PROPERTY", style="cyan")
    geo_table.add_column("VALUE", style="white")
    if isinstance(geo, dict):
        if "note" in geo:
            geo_table.add_row("STATUS", geo["note"])
        elif "error" in geo:
            geo_table.add_row("ERROR", geo["error"])
        else:
            geo_table.add_row("Location", f"{geo.get('city', '-')}, {geo.get('regionName', '-')}, {geo.get('country', '-')}")
            geo_table.add_row("Coordinates", f"{geo.get('lat', '-')}, {geo.get('lon', '-')}")
            geo_table.add_row("Timezone", str(geo.get("timezone", "-")))
            geo_table.add_row("ISP", str(geo.get("isp", "-")))
            geo_table.add_row("Organization", str(geo.get("org", "-")))
            geo_table.add_row("ASN", str(geo.get("as", "-")))
            infra_type = []
            if geo.get("hosting"): infra_type.append("Cloud / Data Center")
            if geo.get("proxy"): infra_type.append("Proxy / VPN / Exit Node")
            geo_table.add_row("Infrastructure", ", ".join(infra_type) if infra_type else "Residential / Standard ISP")
    console.print(geo_table)

    exp = results.get("exposure", {})
    exp_table = Table(title="PASSIVE PORTS & EXPOSURE")
    exp_table.add_column("CATEGORY", style="cyan")
    exp_table.add_column("DETAILS", style="white")
    if isinstance(exp, dict):
        if "note" in exp:
            exp_table.add_row("STATUS", exp["note"])
        elif "error" in exp:
            exp_table.add_row("ERROR", exp["error"])
        else:
            exp_table.add_row("Open Ports", ", ".join(map(str, exp.get("ports", []))) or "None detected")
            exp_table.add_row("Associated Hosts", ", ".join(exp.get("hostnames", [])) or "None")
            exp_table.add_row("Service Tags", ", ".join(exp.get("tags", [])) or "None")
            exp_table.add_row("Indexed CVEs", ", ".join(exp.get("vulns", [])[:8]) or "No known CVEs indexed")
            banners = exp.get("banners", {})
            if isinstance(banners, dict) and banners:
                banner_str = " | ".join(f"{p}: {b}" for p, b in banners.items())
                exp_table.add_row("Service Banners", banner_str)
    console.print(exp_table)

    web = results.get("web_services", {})
    web_table = Table(title="DIRECT WEB SERVICE PROBE")
    web_table.add_column("PROTOCOL", style="cyan")
    web_table.add_column("HTTP STATUS", style="white")
    web_table.add_column("SERVER HEADER", style="white")
    if isinstance(web, dict):
        for proto in ("HTTP", "HTTPS"):
            info = web.get(proto, {})
            web_table.add_row(proto, str(info.get("status", "N/A")), str(info.get("server", "-")))
    console.print(web_table)

    reports = results.get("reports", {})
    if isinstance(reports, dict) and reports:
        report_lines = Text()
        for index, (name, report_path) in enumerate(reports.items()):
            if index:
                report_lines.append("\n")
            report_lines.append(str(name).upper(), style="green")
            report_lines.append(": ")
            report_lines.append(str(report_path))
        console.print(Panel(report_lines, title="REPORT FILES", border_style="green"))


def _render_attack_surface(data, console):
    table = Table(title="WAF / CDN, STACK & COOKIE AUDIT")
    table.add_column("CATEGORY", style="cyan")
    table.add_column("FINDINGS", style="white")
    if not isinstance(data, dict):
        table.add_row("STATUS", "Unavailable")
    elif "error" in data:
        table.add_row("ERROR", str(data["error"]))
    else:
        table.add_row("WAF / CDN", ", ".join(data.get("waf_cdn", [])))
        table.add_row("CMS / Framework", ", ".join(data.get("detected_stack", [])))
        table.add_row("Cookie Security", "\n".join(data.get("cookies", [])))
    console.print(table)


def _render_sensitive_paths(data, console):
    table = Table(title="SENSITIVE PATHS & RECON FILES")
    table.add_column("PATH", style="cyan")
    table.add_column("STATUS", style="white")
    table.add_column("ANALYSIS", style="white")
    if not isinstance(data, list) or not data:
        table.add_row("STATUS", "-", "Unavailable")
    else:
        for item in data:
            status_val = str(item.get("status", "-"))
            note_val = str(item.get("note", "-"))
            style = "bold red" if "CRITICAL" in note_val else ("green" if status_val == "200" else "dim")
            table.add_row(str(item.get("path", "-")), status_val, Text(note_val, style=style))
    console.print(table)


def _render_subdomains(data, console):
    table = Table(title="PASSIVE SUBDOMAINS (CRT.SH)")
    table.add_column("PROPERTY", style="cyan")
    table.add_column("VALUE", style="white")
    if not isinstance(data, dict):
        table.add_row("STATUS", "Unavailable")
    elif "error" in data:
        table.add_row("ERROR", str(data["error"]))
    else:
        total = data.get("total_found", 0)
        subs = data.get("subdomains", [])
        table.add_row("Root Domain", str(data.get("root_domain", "-")))
        table.add_row("Total Unique Found", str(total))
        table.add_row("Sample Subdomains", ", ".join(subs) if subs else "None indexed")
    console.print(table)
