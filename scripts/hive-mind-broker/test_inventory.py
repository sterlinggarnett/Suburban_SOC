"""
inventory.py — path-resolution fallback (#215).

app.py's module-level Inventory("inventory.yaml") relies on this resolving
correctly regardless of the process's cwd; every other test in this
directory runs with cwd == scripts/hive-mind-broker/, so it never exercises
the fallback branch itself.
"""
import os

from inventory import Inventory

HERE = os.path.dirname(os.path.abspath(__file__))


def test_default_filepath_falls_back_to_module_dir_when_cwd_lacks_it(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # a directory with no inventory.yaml
    inv = Inventory()
    assert inv.filepath == os.path.join(HERE, "inventory.yaml")
    assert os.path.exists(inv.filepath)


def test_cwd_inventory_yaml_takes_precedence_over_fallback(tmp_path, monkeypatch):
    (tmp_path / "inventory.yaml").write_text("routers: []\n")
    monkeypatch.chdir(tmp_path)
    inv = Inventory()
    assert inv.filepath == "inventory.yaml"


def test_explicit_non_default_filepath_is_never_overridden(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # still no inventory.yaml here
    inv = Inventory(filepath="custom.yaml")
    assert inv.filepath == "custom.yaml"  # not silently redirected to the module dir
