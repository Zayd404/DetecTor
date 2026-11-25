def format_value(value, indent=0):
    prefix = " " * indent
    lines = []

    if value is None:
        return f"{prefix}N/A"

    if isinstance(value, dict):
        if not value:
            return f"{prefix}(empty)"

        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.append(
                    format_value(item, indent + 4)
                )
            else:
                formatted = (
                    "N/A" if item is None else str(item)
                )
                lines.append(
                    f"{prefix}{key}: {formatted}"
                )

        return "\n".join(lines)

    if isinstance(value, list):
        if not value:
            return f"{prefix}(empty)"

        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}-")
                lines.append(
                    format_value(item, indent + 4)
                )
            else:
                formatted = (
                    "N/A" if item is None else str(item)
                )
                lines.append(f"{prefix}- {formatted}")

        return "\n".join(lines)

    return f"{prefix}{value}"
