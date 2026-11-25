from detector.modules.people_osint.public_profiles import generate_profile_links
from detector.modules.people_osint.name_search import generate_search_links
from detector.ui.people import show_username_result, show_name_search_result


def handle_username_search(engine=None):
    print("\n[USERNAME PROFILE & METADATA SEARCH]")
    print("Gunakan untuk audit identitas publik sendiri atau dengan izin.")
    username = input("\nMasukkan username: ").strip()

    if engine:
        engine.logger.info("Starting People OSINT Username Search: %s", username)

    result = generate_profile_links(username)
    if engine and result.get("valid"):
        result = engine.save_people_report(result, report_type="people_username")
        engine.logger.info("People OSINT Username Search completed: %s", username)

    show_username_result(result)


def handle_name_search(engine=None):
    print("\n[PUBLIC NAME & DORK FOOTPRINT SEARCH]")
    print("Gunakan untuk audit nama sendiri atau dengan izin.")
    query = input("\nMasukkan nama lengkap / kata kunci: ").strip()

    if engine:
        engine.logger.info("Starting People OSINT Name Search: %s", query)

    result = generate_search_links(query)
    if engine and result.get("valid"):
        result = engine.save_people_report(result, report_type="people_name")
        engine.logger.info("People OSINT Name Search completed: %s", query)

    show_name_search_result(result)
