import csv
import io

from app.csv_safe import spreadsheet_safe


def test_formula_payloads_escaped():
    payloads = ("=HYPERLINK(\"https://attacker.invalid\")", "+cmd",
                "-SUM(1,1)", "@SUM(A1:A2)", "  =2+2",
                "\t=1+2", "\r+2", "\n@3")
    for cell in payloads:
        assert spreadsheet_safe(cell) == "'" + cell


def test_benign_values_remain_unchanged():
    for value in ("BTC", "0xabc", "https://explorer.invalid/address/123",
                  "  a string", "", "0", 0, None):
        assert spreadsheet_safe(value) == value


def test_csv_quote_is_not_enough_without_prefix():
    """CSV preserves the apostrophe after quoting embedded commas."""
    payload = '=HYPERLINK("https://attacker.invalid", "click")'
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([spreadsheet_safe(payload)])
    assert next(csv.reader(io.StringIO(buf.getvalue())))[0] == "'" + payload
