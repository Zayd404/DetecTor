from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def _render_report_files(result: dict, console: Console):
    reports = result.get("reports", {})
    if isinstance(reports, dict) and reports:
        report_lines = Text()
        for index, (name, report_path) in enumerate(reports.items()):
            if index:
                report_lines.append("\n")
            report_lines.append(str(name).upper(), style="green")
            report_lines.append(": ")
            report_lines.append(str(report_path))
        console.print(Panel(report_lines, title="REPORT FILES", border_style="green"))


def show_username_result(result: dict, console=None):
    console = console or Console()

    if not result.get("valid"):
        console.print(f"\n[bold red][!] {result.get('error', 'Invalid username')}[/bold red]")
        return

    username = result.get("username", "-")
    found_count = result.get("found_count", 0)

    console.print()
    console.print(
        Panel(
            Text(f"Target: {username}  |  Confirmed Active Accounts: {found_count}", style="bold white"),
            title="[bold red]DETECTOR PEOPLE OSINT - USERNAME INTEL[/bold red]",
            border_style="red",
        )
    )

    # Tabel 1: Platform Verification
    table = Table(title="PLATFORM ACCOUNT VERIFICATION")
    table.add_column("PLATFORM", style="cyan")
    table.add_column("STATUS")
    table.add_column("PROFILE URL", style="white")

    for platform, info in result.get("profiles", {}).items():
        if isinstance(info, dict):
            st = str(info.get("status", "UNKNOWN"))
            url = str(info.get("url", "-"))
        else:
            st = "LINK"
            url = str(info)

        if st == "FOUND":
            st_text = Text(st, style="bold green")
        elif st == "NOT FOUND":
            st_text = Text(st, style="dim")
        elif "MANUAL" in st:
            st_text = Text(st, style="yellow")
        else:
            st_text = Text(st, style="red")

        table.add_row(platform, st_text, url)

    console.print(table)

    # Tabel 2: GitHub Public Metadata Extraction
    gh = result.get("github_intel", {})
    if isinstance(gh, dict) and gh:
        gh_table = Table(title="GITHUB PUBLIC METADATA & COMMIT INTEL")
        gh_table.add_column("FIELD", style="cyan")
        gh_table.add_column("VALUE", style="white")
        gh_table.add_row("Full Name", str(gh.get("name", "-")))
        gh_table.add_row("Bio", str(gh.get("bio", "-")))
        gh_table.add_row("Company", str(gh.get("company", "-")))
        gh_table.add_row("Location", str(gh.get("location", "-")))
        gh_table.add_row("Website / Blog", str(gh.get("blog", "-")))
        gh_table.add_row("Public Email", str(gh.get("public_email", "-")))
        gh_table.add_row("Public Repos / Followers", f"{gh.get('public_repos', 0)} repos / {gh.get('followers', 0)} followers")
        gh_table.add_row("Account Created", str(gh.get("created_at", "-")))
        commit_emails = gh.get("commit_emails", [])
        if commit_emails:
            gh_table.add_row("Commit Author Emails", Text(", ".join(commit_emails), style="bold green"))
        console.print(gh_table)

    # Tabel 3: GitLab Metadata jika ditemukan
    gl = result.get("gitlab_intel", {})
    if isinstance(gl, dict) and gl:
        gl_table = Table(title="GITLAB PUBLIC METADATA")
        gl_table.add_column("FIELD", style="cyan")
        gl_table.add_column("VALUE", style="white")
        gl_table.add_row("User ID", str(gl.get("user_id", "-")))
        gl_table.add_row("Name", str(gl.get("name", "-")))
        gl_table.add_row("Account State", str(gl.get("state", "-")))
        console.print(gl_table)

    _render_report_files(result, console)


def show_name_search_result(result: dict, console=None):
    console = console or Console()

    if not result.get("valid"):
        console.print(f"\n[bold red][!] {result.get('error', 'Invalid query')}[/bold red]")
        return

    query = result.get("query", "-")

    console.print()
    console.print(
        Panel(
            Text(f"Target Query: {query}", style="bold white"),
            title="[bold red]DETECTOR PEOPLE OSINT - PUBLIC NAME & DORKS[/bold red]",
            border_style="red",
        )
    )

    # Tabel 1: Generated Username Permutations
    variants = result.get("username_variants", [])
    if variants:
        var_table = Table(title="GENERATED USERNAME PATTERNS")
        var_table.add_column("SUGGESTED HANDLES (FOR USERNAME SEARCH)", style="green")
        var_table.add_row(", ".join(variants))
        console.print(var_table)

    # Tabel 2: Categorized OSINT Dorks
    dork_table = Table(title="CATEGORIZED OSINT SEARCH DORKS")
    dork_table.add_column("CATEGORY", style="cyan")
    dork_table.add_column("SEARCH URL", style="white")

    for category, url in result.get("search_links", {}).items():
        dork_table.add_row(category, str(url))

    console.print(dork_table)
    _render_report_files(result, console)
