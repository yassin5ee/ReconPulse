from engine.normalization import (
    dedupe,
    has_dev_indicator,
    is_valid_ip,
    normalize_hostname,
    normalize_ip,
    normalize_url,
    parent_domain,
)


def test_hostname_basic():
    assert normalize_hostname("API.Example.COM") == "api.example.com"


def test_hostname_strips_scheme_port_path():
    assert normalize_hostname("https://Api.example.com:8443/path") == "api.example.com"
    assert normalize_hostname("api.example.com.") == "api.example.com"


def test_hostname_invalid_returns_none():
    assert normalize_hostname("") is None
    assert normalize_hostname("not a host!") is None
    assert normalize_hostname("a" * 300 + ".com") is None


def test_ip_validation():
    assert is_valid_ip("1.2.3.4")
    assert is_valid_ip("::1")
    assert not is_valid_ip("999.1.1.1")
    assert not is_valid_ip("example.com")
    assert normalize_ip(" 2606:2800::1 ") == "2606:2800::1"
    assert normalize_ip("nope") is None


def test_url_normalization():
    assert normalize_url("HTTP://Example.com:80/") == "http://example.com/"
    assert normalize_url("https://example.com:443/a?b=1#frag") == "https://example.com/a?b=1"
    assert normalize_url("example.com") == "http://example.com/"
    assert normalize_url("ftp://example.com") is None
    assert normalize_url("") is None


def test_parent_domain():
    assert parent_domain("api.example.com") == "example.com"
    assert parent_domain("deep.api.example.com") == "example.com"
    assert parent_domain("example.com") == "example.com"


def test_dev_indicator():
    assert has_dev_indicator("dev.example.com") == "dev"
    assert has_dev_indicator("staging-api.example.com") == "staging"
    assert has_dev_indicator("api.example.com") is None


def test_dedupe_merges_sources():
    items = [
        {"value": "a.example.com", "source": "crtsh"},
        {"value": "b.example.com", "source": "crtsh"},
        {"value": "a.example.com", "source": "subfinder"},
    ]
    out = dedupe(items, "value")
    assert len(out) == 2
    a = next(i for i in out if i["value"] == "a.example.com")
    assert sorted(a["sources"]) == ["crtsh", "subfinder"]
