import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


def show_main_menu(version):
    menu = Table.grid(padding=(0, 2))
    menu.add_column(justify="center")
    menu.add_column(style="#D5D5D5")

    menu.add_row("[bold cyan][1][/bold cyan]", "Web & App Recon")
    menu.add_row("[bold cyan][2][/bold cyan]", "People OSINT")
    menu.add_row("[bold cyan][3][/bold cyan]", "System Status")
    menu.add_row("[bold cyan][4][/bold cyan]", "Help & Panduan")
    menu.add_row("[bold cyan][0][/bold cyan]", "Exit")

    content = Table.grid(padding=(0, 1))
    content.add_column()
    content.add_row("[bold cyan]DetecTor Framework[/bold cyan]")
    content.add_row(f"[cyan]Version: {version}[/cyan]")
    content.add_row("")
    content.add_row(menu)

    panel = Panel(content, title="[bold red]MAIN MENU[/bold red]", border_style="red", expand=False, padding=(1, 3))
    Console(file=sys.stdout).print(panel)


def show_web_menu():
    menu = Table.grid(padding=(0, 2))
    menu.add_column(style="bold red", justify="center")
    menu.add_column(style="bright_white")

    menu.add_row("[1]", "URL / Domain Recon")
    menu.add_row("[2]", "IP Address Recon")
    menu.add_row("[0]", "Back to Main Menu")

    panel = Panel(menu, title="[bold red]WEB & APP RECON[/bold red]", border_style="red", expand=False, padding=(1, 3))
    Console(file=sys.stdout).print(panel)


def show_people_menu():
    menu = Table.grid(padding=(0, 2))
    menu.add_column(style="bold red", justify="center")
    menu.add_column(style="bright_white")

    menu.add_row("[1]", "Username Profile Search")
    menu.add_row("[2]", "Public Name Search")
    menu.add_row("[0]", "Back to Main Menu")

    panel = Panel(menu, title="[bold red]PEOPLE OSINT[/bold red]", border_style="red", expand=False, padding=(1, 3))
    Console(file=sys.stdout).print(panel)


def show_help_menu():
    console = Console(file=sys.stdout)
    guide = Table(title="DETECTOR FRAMEWORK - PANDUAN PENGGUNAAN & FORMAT INPUT", border_style="red")
    guide.add_column("MODUL / FITUR", style="bold cyan", width=22)
    guide.add_column("CONTOH INPUT VALID", style="green", width=25)
    guide.add_column("FUNGSI & HASIL ANALISIS", style="white")

    guide.add_row(
        "1.1 URL / Domain Recon",
        "example.com\nhttps://target.org",
        "Cek DNS (IPv4/IPv6), Security Headers, Tech Stack, SSL/TLS, WAF/CDN, Audit Cookie, Path Sensitif & Subdomain."
    )
    guide.add_row(
        "1.2 IP Address Recon",
        "8.8.8.8\n2606:4700:4700::1111",
        "Cek IPv4/IPv6, Reverse DNS (PTR), Geolokasi & ASN, Deteksi Hosting/Proxy, Port Terbuka & Banner Layanan."
    )
    guide.add_row(
        "2.1 Username Search",
        "torvalds\nzanony_scarela",
        "Cek keaktifan akun di 12 platform, ekstraksi metadata profil publik GitHub/GitLab & email commit publik."
    )
    guide.add_row(
        "2.2 Public Name Search",
        "Zanony Scarela\nBudi Santoso",
        "Pembuat variasi pola username otomatis & tautan Google/DuckDuckGo OSINT dork per kategori."
    )
    guide.add_row(
        "3. System Status",
        "Pilih Menu 3",
        "Cek kesiapan modul, status koneksi Online/Offline, IP Lokal & IP Publik (OpSec), penyimpanan & jumlah laporan."
    )

    console.print()
    console.print(guide)
    console.print(
        Panel(
            "[bold yellow]Tips Cepat:[/bold yellow] Ketik [bold cyan]help[/bold cyan] atau [bold cyan]?[/bold cyan] pada kolom input target mana pun untuk melihat panduan singkat tanpa keluar menu.\n"
            "[bold yellow]Laporan:[/bold yellow] Seluruh hasil pemeriksaan otomatis tersimpan di folder [bold green]reports/[/bold green] dalam format .json dan .txt.\n"
            "[bold yellow]Etika:[/bold yellow] Gunakan framework ini hanya pada aset milik sendiri atau target yang telah memberikan izin resmi.",
            title="[bold red]TIPS PENGGUNAAN & ETIKA[/bold red]",
            border_style="red",
            expand=False,
        )
    )


def show_system_status(status):
    system = status["system"]

    framework = Table.grid(padding=(0, 2))
    framework.add_column(style="bold red")
    framework.add_column(style="bright_white")
    framework.add_row("Framework", status["name"])
    framework.add_row("Version", status["version"])
    framework.add_row("Web & IP Recon", str(status["web_recon"]))
    framework.add_row("People OSINT", str(status["people_osint"]))
    framework.add_row("Saved Reports", system.get("saved_reports", "0 files"))

    net_state = system.get("network_status", "UNKNOWN")
    net_color = "bold green" if net_state == "ONLINE" else "bold red"

    network = Table.grid(padding=(0, 2))
    network.add_column(style="bold red")
    network.add_column(style="bright_white")
    network.add_row("Connectivity", f"[{net_color}]{net_state}[/{net_color}]")
    network.add_row("Local IP", system.get("local_ip", "Unavailable"))
    network.add_row("Public Exit IP", system.get("public_ip", "Unavailable"))

    device = Table.grid(padding=(0, 2))
    device.add_column(style="bold red")
    device.add_column(style="bright_white")
    device.add_row("Environment", system.get("environment", system["system"]))
    device.add_row("Architecture", system["machine"])
    device.add_row("Storage", system.get("storage", "Unavailable"))
    device.add_row("Python", f"{system['python_version']} ({system.get('implementation', 'CPython')})")
    device.add_row("Executable", system["executable"])

    console = Console(file=sys.stdout)
    console.print(Panel(framework, title="[bold red]FRAMEWORK & MODULES[/bold red]", border_style="red", expand=False, padding=(1, 2)))
    console.print(Panel(network, title="[bold red]NETWORK & OPSEC STATUS[/bold red]", border_style="red", expand=False, padding=(1, 2)))
    console.print(Panel(device, title="[bold red]DEVICE & STORAGE INFO[/bold red]", border_style="red", expand=False, padding=(1, 2)))
