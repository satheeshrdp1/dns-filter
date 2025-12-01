import tempfile
from pathlib import Path

from src.dns_filter.filter_rules import FilterRules


def test_exact_and_suffix(tmp_path: Path):
    f = tmp_path / "rules.txt"
    f.write_text("ads.example.com\n*.tracking.example\n")
    rules = FilterRules(str(f))

    assert rules.is_blocked("ads.example.com.")
    assert rules.is_blocked("sub.tracking.example.")
    assert not rules.is_blocked("good.example.")


def test_add_remove(tmp_path: Path):
    f = tmp_path / "rules.txt"
    rules = FilterRules(str(f))
    rules.add("test.block")
    assert rules.is_blocked("test.block.")
    rules.remove("test.block")
    assert not rules.is_blocked("test.block.")
