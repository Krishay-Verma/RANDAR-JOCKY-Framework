from jocky.analysis.persistence_enrichment import expand_windows_vars
from jocky.collectors.registry import is_known_collector, list_collectors
from jocky.collectors.user_context import collect_clipboard_metadata, collect_browser_history_metadata, collect_browser_cookie_metadata


def test_windows_variable_expansion_handles_backslashes_without_regex_replacement_error(monkeypatch):
    monkeypatch.setenv("WINDIR", r"C:\Windows")
    out = expand_windows_vars(r"%windir%\System32\SecurityHealthSystray.exe")
    assert out.casefold().endswith(r"c:\windows\system32\securityhealthsystray.exe")


def test_user_context_collectors_are_registered_and_privacy_bounded_on_non_windows():
    assert is_known_collector("clipboard_metadata")
    assert is_known_collector("browser_history_metadata")
    assert is_known_collector("browser_cookie_metadata")
    if __import__("os").name != "nt":
        for fn in (collect_clipboard_metadata, collect_browser_history_metadata, collect_browser_cookie_metadata):
            result = fn()
            assert result["status"] == "not_supported"


def test_browser_cookie_schema_contains_no_cookie_value_field():
    if __import__("os").name != "nt":
        return
    result = collect_browser_cookie_metadata()
    assert all("value" not in r and "encrypted_value" not in r for r in result.get("records", []))
