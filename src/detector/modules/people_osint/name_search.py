import re
from urllib.parse import quote_plus, urlunsplit


def _generate_username_variants(full_name: str) -> list:
    clean = re.sub(r"[^a-zA-Z0-9\s]", " ", full_name).strip().lower()
    tokens = [t for t in clean.split() if t]
    if not tokens:
        return []
    first = next(iter(tokens))
    if len(tokens) == 1:
        return [first, f"{first}_official", f"{first}.id", f"real{first}", f"{first}404"]

    last = tokens.pop()
    variants = [
        f"{first}{last}",
        f"{first}.{last}",
        f"{first}_{last}",
        f"{first[:1]}{last}",
        f"{first[:1]}.{last}",
        f"{last}{first}",
        f"{first}-{last}",
    ]
    return list(dict.fromkeys(variants))


def generate_search_links(query: str) -> dict:
    query = query.strip()

    if not query:
        return {"valid": False, "error": "Search query cannot be empty.", "search_links": {}}

    if len(query) > 100:
        return {"valid": False, "error": "Search query is too long.", "search_links": {}}

    exact = f'"{query}"'
    dork_queries = {
        "General Web": ("google.com", "/search", f"q={quote_plus(exact)}"),
        "LinkedIn Profile": ("google.com", "/search", f"q={quote_plus(exact + ' site:linkedin.com')}"),
        "Social Media": ("google.com", "/search", f"q={quote_plus(exact + ' (site:instagram.com OR site:x.com OR site:tiktok.com OR site:facebook.com)')}"),
        "Code & Git": ("google.com", "/search", f"q={quote_plus(exact + ' (site:github.com OR site:gitlab.com)')}"),
        "Documents (PDF/DOC)": ("google.com", "/search", f"q={quote_plus(exact + ' (filetype:pdf OR filetype:docx OR filetype:xlsx)')}"),
        "Paste & Leaks": ("google.com", "/search", f"q={quote_plus(exact + ' (site:pastebin.com OR site:justpaste.it OR site:ghostbin.com)')}"),
        "DuckDuckGo": ("duckduckgo.com", "/", f"q={quote_plus(exact)}"),
    }

    search_links = {
        cat: urlunsplit(("https", host, path, q_str, ""))
        for cat, (host, path, q_str) in dork_queries.items()
    }

    return {
        "valid": True,
        "query": query,
        "username_variants": _generate_username_variants(query),
        "search_links": search_links,
    }
