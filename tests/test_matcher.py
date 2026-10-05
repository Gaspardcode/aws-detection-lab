import pytest

from tests.matcher import matches


def test_exact_and_nested():
    assert matches({"a": ["x"], "b": {"c": [1]}}, {"a": "x", "b": {"c": 1}, "d": 2})
    assert not matches({"a": ["x"]}, {"a": "y"})
    assert not matches({"b": {"c": [1]}}, {"a": 1})


def test_operators():
    assert matches({"a": [{"prefix": "adl-"}]}, {"a": "adl-patients"})
    assert not matches({"a": [{"prefix": "adl-"}]}, {"a": "other"})
    assert matches({"a": [{"anything-but": ["x"]}]}, {"a": "y"})
    assert matches({"a": [{"exists": False}]}, {})
    assert not matches({"a": [{"exists": True}]}, {})


def test_unknown_operator_fails_loudly():
    with pytest.raises(NotImplementedError):
        matches({"a": [{"numeric": [">", 1]}]}, {"a": 2}) if False else matches({"a": [{"foo": 1}]}, {"a": 2})
