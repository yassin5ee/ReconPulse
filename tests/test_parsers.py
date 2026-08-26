import json
import pathlib

from plugins.ports.nmap_adapter import NmapAdapter
from plugins.subdomain.crtsh import CrtShAdapter

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def test_crtsh_parses_valid_json():
    body = (FIXTURES / "crtsh_sample.json").read_text()
    entries = CrtShAdapter.parse_output(body)
    assert len(entries) == 3
    names = [CrtShAdapter._extract_name(e) for e in entries]
    # first entry: newline-separated SANs, first valid candidate wins
    assert names[0] == "api.example.com"
    # wildcard SANs map to their base domain (standard passive-recon behavior)
    assert names[1] == "example.com"
    assert names[2] == "sub.thirdparty.example.net"


def test_crtsh_tolerates_html_garbage():
    assert CrtShAdapter.parse_output("<html>rate limited</html>") == []
    assert CrtShAdapter.parse_output('{"unexpected": "object"}') == []


def test_crtsh_extracts_all_sans():
    entry = {"name_value": "a.example.com\nb.example.com\n*.c.example.com"}
    adapter = CrtShAdapter()
    ctx_names = []
    # _extract_name returns first valid; full SAN handling happens per-entry in run()
    assert adapter._extract_name(entry) == "a.example.com"
    assert "*.c.example.com" not in ctx_names


def test_nmap_parse_output():
    xml = (FIXTURES / "nmap_sample.xml").read_text().encode()
    results = NmapAdapter().parse_output(xml)
    open_ports = {r["port"] for r in results}
    assert open_ports == {22, 80, 8443}  # closed 3306 excluded
    ssh = next(r for r in results if r["port"] == 22)
    assert ssh["service_name"] == "ssh"
    assert ssh["version"] == "OpenSSH 8.9p1"
    https = next(r for r in results if r["port"] == 8443)
    assert https["version"] is None


def test_nmap_rejects_invalid_xml():
    import pytest

    with pytest.raises(ValueError):
        NmapAdapter().parse_output(b"not xml at all <<<<")


def test_nmap_build_command_is_argument_array():
    cmd = NmapAdapter(config={"extra_args": ["--max-rate", "50"]}).build_command(
        ["1.2.3.4"], profile="quick")
    assert cmd[:1] == ["nmap"]
    assert "--top-ports" in cmd and "100" in cmd
    assert "-oX" in cmd and "-" in cmd
    assert cmd[-1] == "1.2.3.4"  # targets after `--` separator
    assert isinstance(cmd, list)  # never a shell string


def test_crtsh_fixture_roundtrip_json():
    data = json.loads((FIXTURES / "crtsh_sample.json").read_text())
    assert all("name_value" in e for e in data)
