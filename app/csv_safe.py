"""Sanitize untrusted text only at the spreadsheet CSV export boundary.

CSV quoting does *not* stop spreadsheet software from interpreting
cells beginning with =, +, -, @ or leading control characters as
formulas. Preserve the original stored values and JSON exports.
"""

FORMULA_PREFIXES = ("=", "+", "-", "@")


def spreadsheet_safe(value):
    """Make a single CSV cell inert when opened in Excel-like software."""
    if not isinstance(value, str) or not value:
        return value
    # A leading tab, LF, or CR can also trigger formula interpretation or
    # break import assumptions in certain spreadsheet applications.
    if value[0] in ("\t", "\r", "\n"):
        return "'" + value
    if value.lstrip(" \t\r\n").startswith(FORMULA_PREFIXES):
        return "'" + value
    return value
