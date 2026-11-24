from detector.modules.people_osint.public_profiles import (
    generate_profile_links,
)
from detector.modules.people_osint.name_search import (
    generate_search_links,
)
from detector.ui.people import (
    show_username_result,
    show_name_search_result,
)


def handle_username_search():
    username = input("Masukkan username: ").strip()

    result = generate_profile_links(username)
    show_username_result(result)


def handle_name_search():
    print("Gunakan untuk audit nama sendiri atau dengan izin.")

    query = input("Masukkan kata kunci: ").strip()

    result = generate_search_links(query)
    show_name_search_result(result)
