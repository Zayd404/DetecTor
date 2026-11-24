import time

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme


custom_theme = Theme({
    "primary": "bold red",
    "secondary": "bright_white",
    "success": "bold green",
    "info": "bright_cyan",
    "warning": "bold yellow",
})

console = Console(theme=custom_theme)

RED = "\033[91m"
RESET = "\033[0m"
CYAN = "\033[96m"
GREEN = "\033[92m"
BOLD = "\033[1m"
WHITE = "\033[97m"


def show_loading(message="Loading", duration=1.5):
    with console.status(
        f"[info]{message}...[/info]",
        spinner="dots",
    ):
        time.sleep(duration)

    console.print(
        f"[success][✓] {message} complete.[/success]"
    )


def show_banner(version='1.1.0'):
    mask = r"""
                     ==:            :==
                     -+#=:        :+#+:
                       :*#-      -%+:
                         =@=    =@-
                          -@-  -@-
                           #%++%#
                         :+#----#*:
                :---::   :@-    -%:   ::---:
                -++++****=-+====+-=****++++-
                       ::*@+====+@*::
                  :=+++-:##      ##:-+++=:
           :---==+#+-:-+@%#*:  :*#%@+-:-+#+==---:
           =+====-:     %=:#*::##:=%     :-====+=
                    :--=@- :#*-=: -@=--:
                  -**++*@:  :%+   :@*++**-
                  +@:  =@:   -@=  :@=  :@+
                  -@-  -@-    =@: -@-  -@-
                   %+  :@=     ## =@:  +%
                   *#   ##     := *#   #*
                   +%:  -@-      -@-  :%+
                   *#    =@-    -@=    #*
                  :@+     =%+--+%=     +@:
                  :#-      :====:      -#:
"""

    console.print(
        Text(mask, style="bold red")
    )

    from rich.columns import Columns

    identity = Panel(
        "[bold red]DETECTOR FRAMEWORK[/bold red]\n"
        "[white]By: Zanony_Scarela[/white]",
        border_style="red",
        expand=False,
    )

    version_box = Panel(
        f"[bold red]VERSION {version}[/bold red]\n"
        "[white]Cybersecurity Toolkit[/white]",
        border_style="red",
        expand=False,
    )

    console.print(
        Columns(
            [identity, version_box],
            expand=False,
            equal=False,
            padding=(0, 16),
        )
    )
