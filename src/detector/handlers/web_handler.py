from detector.ui.reporter import render_web_report, render_ip_report


def handle_web_recon(engine):
    print("\n[URL / DOMAIN RECON]")
    print("Gunakan hanya domain milik sendiri atau yang sudah memberikan izin pemeriksaan.")
    target = input("\nMasukkan domain/URL: ").strip()
    if not target:
        print("[!] Target tidak boleh kosong.")
        return
    if input("Apakah kamu memiliki izin? (yes/no): ").strip().lower() != "yes":
        print("[!] Pemeriksaan dibatalkan.")
        return
    try:
        render_web_report(engine.web_recon(target, authorized=True))
    except (ValueError, PermissionError) as error:
        print("\n[!] Error:", error)
    except Exception:
        engine.logger.exception("Web Recon failed")
        print("\n[!] Unexpected error.")


def handle_ip_recon(engine):
    print("\n[IP ADDRESS RECON]")
    print("Gunakan hanya alamat IP milik sendiri atau yang sudah memberikan izin pemeriksaan.")
    target = input("\nMasukkan alamat IP (IPv4/IPv6): ").strip()
    if not target:
        print("[!] Target IP tidak boleh kosong.")
        return
    if input("Apakah kamu memiliki izin? (yes/no): ").strip().lower() != "yes":
        print("[!] Pemeriksaan dibatalkan.")
        return
    try:
        render_ip_report(engine.ip_recon(target, authorized=True))
    except (ValueError, PermissionError) as error:
        print("\n[!] Error:", error)
    except Exception:
        engine.logger.exception("IP Recon failed")
        print("\n[!] Unexpected error.")
