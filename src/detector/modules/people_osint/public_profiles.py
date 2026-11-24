from .username import validate_username


PLATFORMS = {
    "GitHub": "https://github.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "TikTok": "https://www.tiktok.com/@{}",
    "X": "https://x.com/{}",
    "Reddit": "https://www.reddit.com/user/{}/",
}


def generate_profile_links(username):
    validation = validate_username(username)

    if not validation["valid"]:
        return {
            "valid": False,
            "username": username,
            "error": validation["message"],
            "profiles": {},
        }

    username = validation["username"]

    profiles = {
        platform: template.format(username)
        for platform, template in PLATFORMS.items()
    }

    return {
        "valid": True,
        "username": username,
        "profiles": profiles,
    }
