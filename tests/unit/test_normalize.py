from perflens.stacks.normalize import normalize_symbol


def test_normalization_is_conservative() -> None:
    assert normalize_symbol("worker.isra.42") == "worker"
    assert normalize_symbol("worker.constprop.7") == "worker"
    assert normalize_symbol("worker.cold") == "worker"
    assert normalize_symbol("worker+0x2a") == "worker"
    assert normalize_symbol("foo<int, long>(int)") == "foo<int, long>(int)"


def test_rust_hash_is_removed_but_namespace_is_preserved() -> None:
    assert normalize_symbol("crate::module::work::h0123456789abcdef") == "crate::module::work"
