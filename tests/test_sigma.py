import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from logsentinel import cli
from logsentinel.detectors import web
from logsentinel.models import HttpEvent, Severity
from logsentinel.parsers import web as web_parser
from logsentinel.sigma import RuleError, load_rule, load_rules

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules" / "web"
SAMPLE = ROOT / "samples" / "access.log"
TS = datetime(2026, 11, 22, 15, 0, tzinfo=timezone.utc)


def ev(path="/", method="GET", status=200, ua="Mozilla/5.0", referrer="", ip="203.0.113.9", raw=""):
    return HttpEvent(TS, ip, method, path, "HTTP/1.1", status, 100, referrer, ua, raw)


def rule(detection, **extra):
    data = {"title": "test rule", "logsource": {"category": "webserver"}, "detection": detection, **extra}
    return load_rule(data)


# ------------------------------------------------------------------- value matching

@pytest.mark.parametrize(
    "field, value, event, expected",
    [
        ("cs-uri-stem", "/admin", ev("/admin?x=1"), True),           # plain value = whole field
        ("cs-uri-stem", "/admin", ev("/admin/users"), False),
        ("cs-uri-stem", "/ADMIN", ev("/admin"), True),                # case-insensitive
        ("cs-uri-stem", "/adm*", ev("/administrator"), True),         # wildcard
        ("cs-uri-stem", "/a?min", ev("/admin"), True),
        ("cs-uri-stem", r"/a\*", ev("/a*"), True),                    # escaped wildcard
        ("cs-uri-stem", r"/a\*", ev("/abc"), False),
        ("cs-uri-stem|contains", "etc/pass", ev("/x/etc/passwd"), True),
        ("cs-uri-stem|startswith", "/wp-", ev("/wp-login.php"), True),
        ("cs-uri-stem|endswith", ".bak", ev("/config.php.bak"), True),
        ("cs-uri-stem|endswith", ".bak", ev("/config.bak.php"), False),
        ("cs-uri-query|contains", "cmd=", ev("/x.php?cmd=id"), True),
        ("cs-uri-query|contains", "cmd=", ev("/cmd=/x.php"), False),  # stem, not query
        ("sc-status", 404, ev(status=404), True),                     # YAML numbers
        ("sc-status", [401, 403], ev(status=404), False),
        ("cs-method", ["PUT", "DELETE"], ev(method="DELETE"), True),  # list = OR
        ("c-useragent|contains", "curl", ev(ua="curl/8.5"), True),
        ("cs-referer", None, ev(referrer=""), True),                  # null = empty
        ("cs-referer", None, ev(referrer="https://example.com/"), False),
        ("cs-uri|re", r"id=\d+$", ev("/p?id=42"), True),
        ("cs-uri|re", r"ID=\d+$", ev("/p?id=42"), False),             # re is case-sensitive...
        ("cs-uri|re|i", r"ID=\d+$", ev("/p?id=42"), True),            # ...unless |i
    ],
)
def test_field_values(field, value, event, expected):
    assert rule({"sel": {field: value}, "condition": "sel"}).matches(event) is expected


def test_all_modifier_requires_every_value():
    r = rule({"sel": {"cs-uri|contains|all": ["union", "select"]}, "condition": "sel"})
    assert r.matches(ev("/p?id=1 union select 1"))
    assert not r.matches(ev("/p?id=1 union all"))


def test_fields_in_a_map_are_and():
    r = rule({"sel": {"cs-method": "POST", "sc-status": 200}, "condition": "sel"})
    assert r.matches(ev(method="POST", status=200))
    assert not r.matches(ev(method="POST", status=404))


def test_list_of_maps_is_or():
    r = rule({"sel": [{"cs-method": "PUT"}, {"sc-status": 500}], "condition": "sel"})
    assert r.matches(ev(method="PUT")) and r.matches(ev(status=500))
    assert not r.matches(ev())


def test_encoded_payload_matches_decoded_rule():
    # The rule is written in plain text; the attacker URL-encoded and commented it.
    r = rule({"sel": {"cs-uri-query|contains": "' or 1=1"}, "condition": "sel"})
    assert r.matches(ev("/login?u=admin%27%20or%201%3D1--"))
    assert r.matches(ev("/login?u=admin'/**/or/**/1=1"))
    assert not r.matches(ev("/login?u=admin"))


def test_encoded_rule_value_still_matches_raw_log():
    # Rules copied from elsewhere often contain the encoded form: keep matching the raw value.
    r = rule({"sel": {"cs-uri-query|contains": "%27"}, "condition": "sel"})
    assert r.matches(ev("/p?id=1%27"))


def test_keywords_search_the_raw_line():
    r = rule({"keywords": ["jndi:ldap"], "condition": "keywords"})
    assert r.matches(ev(raw='203.0.113.9 - - [...] "GET / HTTP/1.1" 200 1 "-" "${jndi:ldap://x}"'))
    assert not r.matches(ev(raw='203.0.113.9 - - [...] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"'))


# ---------------------------------------------------------------------- conditions

DET = {
    "sel_a": {"cs-method": "POST"},
    "sel_b": {"sc-status": 200},
    "filter": {"cs-uri-stem": "/health"},
}


@pytest.mark.parametrize(
    "condition, event, expected",
    [
        ("sel_a and sel_b", ev(method="POST", status=200), True),
        ("sel_a and sel_b", ev(method="POST", status=404), False),
        ("sel_a or sel_b", ev(status=200), True),
        ("sel_a and not filter", ev("/health", method="POST"), False),
        ("sel_a and not filter", ev("/login", method="POST"), True),
        ("not sel_a and sel_b", ev(status=200), True),                # not binds tighter than and
        ("sel_a or sel_b and filter", ev(method="POST", status=404), True),  # and before or
        ("(sel_a or sel_b) and filter", ev(method="POST", status=404), False),
        ("1 of sel_*", ev(status=200), True),
        ("all of sel_*", ev(status=200), False),
        ("all of sel_*", ev(method="POST", status=200), True),
        ("1 of them", ev("/health"), True),
        ("SEL_A", ev(method="POST"), "error"),                        # identifiers are case-sensitive
    ],
)
def test_conditions(condition, event, expected):
    if expected == "error":
        with pytest.raises(RuleError):
            rule({**DET, "condition": condition})
        return
    assert rule({**DET, "condition": condition}).matches(event) is expected


def test_them_ignores_underscore_selections():
    r = rule({"sel": {"cs-method": "POST"}, "_helper": {"sc-status": 200}, "condition": "all of them"})
    assert r.matches(ev(method="POST", status=404))


def test_list_of_conditions_is_or():
    r = rule({**DET, "condition": ["sel_a", "filter"]})
    assert r.matches(ev("/health")) and r.matches(ev(method="POST"))


# ------------------------------------------------------------- metadata and errors

def test_metadata_mapping():
    r = rule({"sel": {"cs-method": "GET"}, "condition": "sel"}, id="abc-123", level="critical",
             tags=["attack.initial_access", "attack.t1190", "attack.t1505.003", "cve.2021-44228"])
    assert (r.rule_id, r.severity, r.mitre_technique) == ("abc-123", Severity.CRITICAL, "T1190, T1505.003")


def test_informational_level_is_low():
    assert rule({"s": {"cs-method": "GET"}, "condition": "s"}, level="informational").severity is Severity.LOW


@pytest.mark.parametrize(
    "data, message",
    [
        ({"title": "x", "logsource": {"product": "windows"}, "detection": {"s": {}, "condition": "s"}}, "webserver"),
        ({"title": "x", "logsource": {"category": "webserver", "product": "iis"},
          "detection": {"s": {"cs-method": "GET"}, "condition": "s"}}, "product"),
        ({"title": "x", "logsource": {"category": "webserver"}}, "detection"),
        ({"logsource": {"category": "webserver"}, "detection": {"s": {"cs-method": "GET"}, "condition": "s"}}, "title"),
    ],
)
def test_invalid_rules_are_rejected(data, message):
    with pytest.raises(RuleError, match=message):
        load_rule(data)


@pytest.mark.parametrize(
    "detection, message",
    [
        ({"s": {"cs-method": "GET"}, "condition": "s | count() > 5"}, "aggregation"),
        ({"s": {"cs-method": "GET"}, "timeframe": "5m", "condition": "s"}, "timeframe"),
        ({"s": {"cs-uri|base64": "x"}, "condition": "s"}, "modifier"),
        ({"s": {"cs-uri|i": "x"}, "condition": "s"}, "'i'"),
        ({"s": {"Image": "cmd.exe"}, "condition": "s"}, "field"),
        ({"s": {"cs-uri|re": "("}, "condition": "s"}, "regular expression"),
        ({"s": {"cs-method": "GET"}}, "condition"),
        ({"s": {"cs-method": "GET"}, "condition": "s and other"}, "unknown selection"),
        ({"s": {"cs-method": "GET"}, "condition": "1 of x*"}, "matches no selection"),
        ({"s": {"cs-method": "GET"}, "condition": "(s"}, "\\)"),
    ],
)
def test_unsupported_features_fail_loudly(detection, message):
    # Silently ignoring part of a rule would make it look active while it never fires.
    with pytest.raises(RuleError, match=message):
        rule(detection)


# ------------------------------------------------------------ files and the CLI

def test_load_rules_from_directory_and_multi_document_file(tmp_path):
    pytest.importorskip("yaml")
    (tmp_path / "a.yml").write_text(
        "title: A\nlogsource: {category: webserver}\ndetection: {s: {cs-method: PUT}, condition: s}\n"
        "---\n"
        "title: B\nlogsource: {category: webserver}\ndetection: {s: {cs-method: DELETE}, condition: s}\n",
        encoding="utf-8",
    )
    (tmp_path / "notes.txt").write_text("not a rule", encoding="utf-8")
    rules = load_rules([tmp_path])
    assert [r.title for r in rules] == ["A", "B"]
    assert rules[0].rule_id == "a"            # no id: falls back to the file name


def test_bad_yaml_names_the_file(tmp_path):
    pytest.importorskip("yaml")
    bad = tmp_path / "bad.yml"
    bad.write_text("title: [unclosed\n", encoding="utf-8")
    with pytest.raises(RuleError, match="bad.yml"):
        load_rules([bad])


def test_missing_path_is_an_error(tmp_path):
    pytest.importorskip("yaml")
    with pytest.raises(RuleError, match="no such file"):
        load_rules([tmp_path / "nope"])


def test_missing_pyyaml_gives_install_hint(monkeypatch):
    monkeypatch.setitem(sys.modules, "yaml", None)     # makes "import yaml" fail
    with pytest.raises(RuleError, match=r"logsentinel\[yaml\]"):
        load_rules([RULES])


def _sample_alerts():
    pytest.importorskip("yaml")
    with SAMPLE.open(encoding="utf-8") as fh:
        return web.detect(web_parser.parse_lines(fh), rules=load_rules([RULES]))


def test_example_rules_fire_on_the_sample_log():
    alerts = _sample_alerts()
    by_rule = {}
    for a in alerts:
        by_rule.setdefault(a.title, set()).add(a.source_ip)
    assert by_rule["Web shell access attempt"] == {"203.0.113.120"}
    assert by_rule["Probe for backup, dump or secrets files"] == {"203.0.113.50", "203.0.113.120"}


def test_example_rules_ignore_legitimate_traffic():
    sigma_titles = {"Web shell access attempt", "Probe for backup, dump or secrets files"}
    assert not [a for a in _sample_alerts() if a.title in sigma_titles and a.source_ip.startswith("198.51.100.")]


def test_example_rules_false_positives():
    pytest.importorskip("yaml")
    rules = load_rules([RULES])
    benign = [
        ev("/downloads/logsentinel-0.2.0.tar.gz"),   # filtered public downloads folder
        ev("/backup-policy.html"),
        ev("/tools/shell.php.html"),
        ev("/search.php?q=cmd+line+tips"),           # "cmd" but not "cmd="
        ev("/sql-tutorial"),
    ]
    assert [(e.path, r.title) for e in benign for r in rules if r.matches(e)] == []


def test_cli_with_rules(capsys):
    pytest.importorskip("yaml")
    code = cli.main(["web", str(SAMPLE), "--rules", str(RULES), "--no-color"])
    out = capsys.readouterr().out
    assert code == 1
    assert "Web shell access attempt" in out and "T1505.003" in out


def test_cli_invalid_rules_exit_code_2(tmp_path, capsys):
    pytest.importorskip("yaml")
    bad = tmp_path / "bad.yml"
    bad.write_text("title: x\nlogsource: {product: windows}\ndetection: {s: {a: b}, condition: s}\n", encoding="utf-8")
    assert cli.main(["web", str(SAMPLE), "--rules", str(bad)]) == 2
    assert "webserver" in capsys.readouterr().err
