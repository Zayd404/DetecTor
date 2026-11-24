import json


def handle_web_recon(engine):
    print("\n[WEB & APP RECON]")
    print("Gunakan hanya domain milik sendiri atau yang")
    print("sudah memberikan izin pemeriksaan.")

    target = input("\nMasukkan domain/URL: ").strip()

    if not target:
        print("[!] Target tidak boleh kosong.")
        return

    confirmation = input(
        "Apakah kamu memiliki izin? (yes/no): "
    ).strip().lower()

    if confirmation != "yes":
        print("[!] Pemeriksaan dibatalkan.")
        return

    try:
        results = engine.web_recon(
            target,
            authorized=True,
        )

        print("\n[RECON RESULTS]")
        print(json.dumps(
            results,
            indent=4,
            ensure_ascii=False,
        ))

        if results.get("report"):
            print("\n[+] Report saved:", results["report"])

    except (ValueError, PermissionError) as error:
        print("\n[!] Error:", error)

    except Exception:
        engine.logger.exception("Web Recon failed")
        print("\n[!] Unexpected error.")
