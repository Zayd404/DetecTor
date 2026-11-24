from .display import RESET, RED, GREEN, CYAN, WHITE


def show_username_result(result):
    print(f"\n{RED}[ PUBLIC PROFILE SEARCH ]{RESET}")

    if not result["valid"]:
        print(f"{RED}[!] {result['error']}{RESET}")
        return

    print(f"\n{GREEN}[+] Username valid{RESET}")
    print(f"Username: {result['username']}")

    print(f"\n{WHITE}[ PUBLIC PROFILE LINKS ]{RESET}")

    for platform, url in result["profiles"].items():
        print(f"{CYAN}{platform:<12}: {url}{RESET}")


def show_name_search_result(result):
    print(f"\n{RED}[ PUBLIC NAME SEARCH ]{RESET}")

    if not result["valid"]:
        print(f"{RED}[!] {result['error']}{RESET}")
        return

    print(f"\n{GREEN}[+] Search links generated{RESET}")
    print(f"Query: {result['query']}")

    print(f"\n{WHITE}[ SEARCH ENGINES ]{RESET}")

    for engine, url in result["search_links"].items():
        print(f"{CYAN}{engine:<12}: {url}{RESET}")
