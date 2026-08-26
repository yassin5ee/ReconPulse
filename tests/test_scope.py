from engine.scope import ScopeChecker

RULES = [
    ("example.com", "ALLOW"),
    ("*.staging.example.com", "ALLOW"),
    ("10.0.0.0/8", "ALLOW"),
    ("192.168.1.1", "ALLOW"),
    ("admin.example.com", "DENY"),
    ("thirdparty.example.net", "DENY"),
]


def checker() -> ScopeChecker:
    return ScopeChecker(RULES)


def test_exact_domain_allow():
    assert checker().classify("example.com") == "IN_SCOPE"


def test_wildcard_covers_apex_and_depths():
    assert checker().classify("staging.example.com") == "IN_SCOPE"
    assert checker().classify("a.b.staging.example.com") == "IN_SCOPE"


def test_unlisted_subdomain_unknown():
    assert checker().classify("api.example.com") == "UNKNOWN"


def test_deny_wins_even_if_wildcard_allows():
    assert checker().classify("admin.example.com") == "OUT_OF_SCOPE"


def test_out_of_scope_external_domain():
    assert checker().classify("thirdparty.example.net") == "OUT_OF_SCOPE"
    assert checker().classify("evil.com") == "UNKNOWN"


def test_cidr_matching():
    assert checker().classify("10.20.30.40") == "IN_SCOPE"
    assert checker().classify("11.0.0.1") == "UNKNOWN"


def test_exact_ip_allow():
    assert checker().classify("192.168.1.1") == "IN_SCOPE"
    assert checker().classify("192.168.1.2") == "UNKNOWN"


def test_normalization_before_match():
    assert checker().classify("EXAMPLE.com.") == "IN_SCOPE"
    assert checker().classify("  admin.example.com ") == "OUT_OF_SCOPE"


def test_active_scan_gate():
    assert checker().allows_active_scan("example.com") is True
    assert checker().allows_active_scan("admin.example.com") is False
    assert checker().allows_active_scan("api.example.com") is False  # UNKNOWN never active


def test_empty_value_is_unknown():
    assert checker().classify("") == "UNKNOWN"
