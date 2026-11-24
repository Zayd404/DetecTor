def show_main_menu(version):
    import sys

    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    menu = Table.grid(padding=(0, 2))
    menu.add_column(justify="center")
    menu.add_column(style="#D5D5D5")

    menu.add_row("[bold cyan][1][/bold cyan]", "Web & App Recon")
    menu.add_row("[bold cyan][2][/bold cyan]", "People OSINT")
    menu.add_row("[bold cyan][3][/bold cyan]", "System Status")
    menu.add_row("[bold cyan][0][/bold cyan]", "Exit")

    content = Table.grid(padding=(0, 1))
    content.add_column()

    content.add_row(
        "[bold cyan]DetecTor Framework[/bold cyan]"
    )
    content.add_row(f"[cyan]Version: {version}[/cyan]")
    content.add_row("")
    content.add_row(menu)

    panel = Panel(
        content,
        title="[bold red]MAIN MENU[/bold red]",
        border_style="red",
        expand=False,
        padding=(1, 3),
    )

    menu_console = Console(file=sys.stdout)
    menu_console.print(panel)


def show_people_menu():
    import sys

    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    menu = Table.grid(padding=(0, 2))
    menu.add_column(style="bold red", justify="center")
    menu.add_column(style="bright_white")

    menu.add_row("[1]", "Username Profile Search")
    menu.add_row("[2]", "Public Name Search")
    menu.add_row("[0]", "Back to Main Menu")

    panel = Panel(
        menu,
        title="[bold red]PEOPLE OSINT[/bold red]",
        border_style="red",
        expand=False,
        padding=(1, 3),
    )

    Console(file=sys.stdout).print(panel)


def show_system_status(status):
    import sys

    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    system = status["system"]

    framework = Table.grid(padding=(0, 2))
    framework.add_column(style="bold red")
    framework.add_column(style="bright_white")

    framework.add_row("Framework", status["name"])
    framework.add_row("Version", status["version"])
    framework.add_row("Web Recon", str(status["web_recon"]))
    framework.add_row("People OSINT", str(status["people_osint"]))

    device = Table.grid(padding=(0, 2))
    device.add_column(style="bold red")
    device.add_column(style="bright_white")

    device.add_row("OS", system["system"])
    device.add_row("Platform", system["platform"])
    device.add_row("Architecture", system["machine"])
    device.add_row("Python", system["python_version"])
    device.add_row("Executable", system["executable"])

    framework_panel = Panel(
        framework,
        title="[bold red]SYSTEM STATUS[/bold red]",
        border_style="red",
        expand=False,
        padding=(1, 2),
    )

    device_panel = Panel(
        device,
        title="[bold red]DEVICE INFORMATION[/bold red]",
        border_style="red",
        expand=False,
        padding=(1, 2),
    )

    console = Console(file=sys.stdout)
    console.print(framework_panel)
    console.print(device_panel)
