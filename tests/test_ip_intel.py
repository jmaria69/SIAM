"""Enriquecimiento WHOIS/RDAP (siem/ip_intel.py). Se mockea httpx.get -- no
hace falta red real, y así el test es determinista sobre las formas de
respuesta RDAP verificadas a mano (registrant/abuse como entities de nivel
superior, o abuse anidado dentro del registrant)."""
import httpx

from siem import ip_intel


class _FakeResponse:
    def __init__(self, payload: dict, *, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=self)

    def json(self) -> dict:
        return self._payload


def _vcard(*, fn=None, org=None, email=None) -> list:
    entries = []
    if fn:
        entries.append(["fn", {}, "text", fn])
    if org:
        entries.append(["org", {}, "text", org])
    if email:
        entries.append(["email", {}, "text", email])
    return ["vcard", entries]


def test_lookup_ip_extracts_org_and_abuse_email_from_top_level_entities(monkeypatch):
    payload = {
        "name": "GOOGLE",
        "entities": [
            {"roles": ["registrant"], "vcardArray": _vcard(org="Google LLC")},
            {"roles": ["abuse"], "vcardArray": _vcard(email="abuse@google.com")},
        ],
    }
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResponse(payload))

    result = ip_intel.lookup_ip("8.8.8.8")
    assert result == {"org": "Google LLC", "network_name": "GOOGLE", "abuse_email": "abuse@google.com"}


def test_lookup_ip_finds_abuse_entity_nested_inside_registrant(monkeypatch):
    payload = {
        "name": "SOME-NET",
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": _vcard(fn="Some Registrant"),
                "entities": [{"roles": ["abuse"], "vcardArray": _vcard(email="abuse@example.net")}],
            },
        ],
    }
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResponse(payload))

    result = ip_intel.lookup_ip("203.0.113.5")
    assert result == {"org": "Some Registrant", "network_name": "SOME-NET", "abuse_email": "abuse@example.net"}


def test_lookup_ip_prefers_fn_over_org_when_both_present(monkeypatch):
    payload = {
        "name": None,
        "entities": [{"roles": ["registrant"], "vcardArray": _vcard(fn="Persona Registrante", org="Empresa SL")}],
    }
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResponse(payload))

    result = ip_intel.lookup_ip("203.0.113.6")
    assert result["org"] == "Persona Registrante"


def test_lookup_ip_returns_none_when_no_useful_data(monkeypatch):
    payload = {"name": None, "entities": []}
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResponse(payload))
    assert ip_intel.lookup_ip("203.0.113.7") is None


def test_lookup_ip_fails_open_on_http_error(monkeypatch):
    def _boom(*a, **k):
        raise httpx.ConnectError("no network")

    monkeypatch.setattr(httpx, "get", _boom)
    assert ip_intel.lookup_ip("203.0.113.8") is None


def test_lookup_ip_fails_open_on_http_status_error(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResponse({}, status_code=404))
    assert ip_intel.lookup_ip("203.0.113.9") is None


def test_lookup_ip_fails_open_on_invalid_json(monkeypatch):
    class _BadJson(_FakeResponse):
        def json(self):
            raise ValueError("not json")

    monkeypatch.setattr(httpx, "get", lambda *a, **k: _BadJson({}))
    assert ip_intel.lookup_ip("203.0.113.10") is None
