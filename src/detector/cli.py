from .handlers.web_handler import handle_web_recon, handle_ip_recon
from .ui.menus import show_main_menu, show_web_menu, show_people_menu, show_system_status, show_help_menu
from .ui.display import show_loading, show_banner
from .handlers.people_handler import handle_username_search, handle_name_search
from .core.engine import DetecTorEngine


def run():
    show_loading("Initializing DetecTor")
    engine = DetecTorEngine()
    status = engine.initialize()

    while True:
        show_banner(status["version"])
        show_main_menu(status["version"])
        choice = input("\nSelect menu: ").strip()

        if choice == "1":
            show_web_menu()
            web_choice = input("\nSelect menu: ").strip()
            if web_choice == "1":
                handle_web_recon(engine)
            elif web_choice == "2":
                handle_ip_recon(engine)
            elif web_choice == "0":
                continue
            else:
                print("\n[!] Invalid selection.")

        elif choice == "2":
            show_people_menu()
            people_choice = input("\nSelect menu: ").strip()
            if people_choice == "1":
                handle_username_search(engine)
            elif people_choice == "2":
                handle_name_search(engine)
            elif people_choice == "0":
                continue
            else:
                print("\n[!] Invalid selection.")

        elif choice == "3":
            status = engine.status()
            show_system_status(status)

        elif choice == "4":
            show_help_menu()

        elif choice == "0":
            print("\nDetecTor closed.")
            break
        else:
            print("\n[!] Invalid selection.")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    run()
