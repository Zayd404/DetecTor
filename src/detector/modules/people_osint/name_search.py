from urllib.parse import quote_plus


SEARCH_ENGINES = {
    "Google": "https://www.google.com/search?q={}",
    "Bing": "https://www.bing.com/search?q={}",
    "DuckDuckGo": "https://duckduckgo.com/?q={}",
}


def generate_search_links(query):
    query = query.strip()

    if not query:
        return {
            "valid": False,
            "error": "Search query cannot be empty.",
            "search_links": {},
        }

    if len(query) > 100:
        return {
            "valid": False,
            "error": "Search query is too long.",
            "search_links": {},
        }

    encoded_query = quote_plus(query)

    search_links = {
        engine: template.format(encoded_query)
        for engine, template in SEARCH_ENGINES.items()
    }

    return {
        "valid": True,
        "query": query,
        "search_links": search_links,
    }
