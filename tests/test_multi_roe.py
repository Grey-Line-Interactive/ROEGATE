"""Tests for Multi-ROE Specification Manager."""

import copy
import tempfile
from pathlib import Path

import pytest
import yaml

from src.service.multi_roe import MultiROEManager, ROEEntry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ACME_ROE_PATH = Path(__file__).parent.parent / "examples" / "local_corp_roe.yaml"


def _minimal_roe(engagement_id: str = "ENG-TEST-001", client: str = "Test Client") -> dict:
    """Return a minimal valid ROE spec dict (inner, without 'roe' wrapper)."""
    return {
        "metadata": {
            "engagement_id": engagement_id,
            "client": client,
        },
        "scope": {
            "in_scope": {"networks": [{"cidr": "10.0.0.0/24"}]},
        },
        "actions": {
            "allowed": [{"category": "reconnaissance", "methods": ["port_scan"]}],
        },
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMultiROEManager:
    """Tests for MultiROEManager."""

    def test_load_roe_from_yaml_file(self):
        """Loading a ROE spec from a YAML file returns a valid ROEEntry."""
        mgr = MultiROEManager()
        entry = mgr.load_roe(ACME_ROE_PATH)

        assert isinstance(entry, ROEEntry)
        assert entry.engagement_id == "ENG-2024-001"
        assert entry.client == "Local Corp"
        assert entry.status == "active"
        assert entry.file_path is not None
        assert entry.roe_hash.startswith("sha256:")

    def test_add_parsed_roe_spec(self):
        """Adding an already-parsed ROE spec creates an entry."""
        mgr = MultiROEManager()
        spec = _minimal_roe("ENG-PARSED-001", "Parsed Client")
        entry = mgr.add_roe(spec)

        assert entry.engagement_id == "ENG-PARSED-001"
        assert entry.client == "Parsed Client"
        assert entry.status == "active"
        assert entry.file_path is None

    def test_add_parsed_roe_spec_with_wrapper(self):
        """Adding a spec wrapped in a 'roe' key also works."""
        mgr = MultiROEManager()
        spec = {"roe": _minimal_roe("ENG-WRAPPED-001")}
        entry = mgr.add_roe(spec)

        assert entry.engagement_id == "ENG-WRAPPED-001"

    def test_get_roe_by_engagement_id(self):
        """get_roe returns the correct entry by engagement_id."""
        mgr = MultiROEManager()
        mgr.add_roe(_minimal_roe("ENG-GET-001"))

        entry = mgr.get_roe("ENG-GET-001")
        assert entry is not None
        assert entry.engagement_id == "ENG-GET-001"

    def test_get_roe_returns_none_for_unknown(self):
        """get_roe returns None for an unknown engagement_id."""
        mgr = MultiROEManager()
        assert mgr.get_roe("DOES-NOT-EXIST") is None

    def test_list_active_roes(self):
        """get_active returns only entries with status 'active'."""
        mgr = MultiROEManager()
        mgr.add_roe(_minimal_roe("ENG-A1"))
        mgr.add_roe(_minimal_roe("ENG-A2"))
        mgr.add_roe(_minimal_roe("ENG-A3"))
        mgr.archive("ENG-A2")

        active = mgr.get_active()
        ids = [e.engagement_id for e in active]
        assert "ENG-A1" in ids
        assert "ENG-A3" in ids
        assert "ENG-A2" not in ids

    def test_list_all_includes_archived(self):
        """list_all returns entries regardless of status."""
        mgr = MultiROEManager()
        mgr.add_roe(_minimal_roe("ENG-ALL-1"))
        mgr.add_roe(_minimal_roe("ENG-ALL-2"))
        mgr.archive("ENG-ALL-2")

        all_entries = mgr.list_all()
        ids = [e.engagement_id for e in all_entries]
        assert "ENG-ALL-1" in ids
        assert "ENG-ALL-2" in ids

    def test_archive_changes_status(self):
        """Archiving a ROE changes its status to 'archived'."""
        mgr = MultiROEManager()
        mgr.add_roe(_minimal_roe("ENG-ARCH-001"))

        entry_before = mgr.get_roe("ENG-ARCH-001")
        assert entry_before.status == "active"

        mgr.archive("ENG-ARCH-001")

        entry_after = mgr.get_roe("ENG-ARCH-001")
        assert entry_after.status == "archived"

    def test_remove_roe(self):
        """Removing a ROE makes it inaccessible."""
        mgr = MultiROEManager()
        mgr.add_roe(_minimal_roe("ENG-RM-001"))
        assert mgr.get_roe("ENG-RM-001") is not None

        mgr.remove("ENG-RM-001")
        assert mgr.get_roe("ENG-RM-001") is None

    def test_remove_unknown_raises(self):
        """Removing an unknown engagement_id raises KeyError."""
        mgr = MultiROEManager()
        with pytest.raises(KeyError):
            mgr.remove("NOPE")

    def test_archive_unknown_raises(self):
        """Archiving an unknown engagement_id raises KeyError."""
        mgr = MultiROEManager()
        with pytest.raises(KeyError):
            mgr.archive("NOPE")

    def test_duplicate_engagement_id_rejected(self):
        """Adding a spec with a duplicate engagement_id raises ValueError."""
        mgr = MultiROEManager()
        mgr.add_roe(_minimal_roe("ENG-DUP-001"))

        with pytest.raises(ValueError, match="Duplicate engagement_id"):
            mgr.add_roe(_minimal_roe("ENG-DUP-001"))

    def test_validation_missing_metadata(self):
        """A spec without metadata fails validation."""
        mgr = MultiROEManager()
        bad_spec = {"scope": {}, "actions": {}}
        with pytest.raises(ValueError, match="metadata"):
            mgr.add_roe(bad_spec)

    def test_validation_missing_engagement_id(self):
        """A spec with metadata but no engagement_id fails validation."""
        mgr = MultiROEManager()
        bad_spec = {"metadata": {"client": "X"}, "scope": {}, "actions": {}}
        with pytest.raises(ValueError, match="engagement_id"):
            mgr.add_roe(bad_spec)

    def test_validation_missing_scope(self):
        """A spec missing 'scope' fails validation."""
        mgr = MultiROEManager()
        bad_spec = {"metadata": {"engagement_id": "X"}, "actions": {}}
        with pytest.raises(ValueError, match="scope"):
            mgr.add_roe(bad_spec)

    def test_validation_missing_actions(self):
        """A spec missing 'actions' fails validation."""
        mgr = MultiROEManager()
        bad_spec = {"metadata": {"engagement_id": "X"}, "scope": {}}
        with pytest.raises(ValueError, match="actions"):
            mgr.add_roe(bad_spec)

    def test_select_returns_spec(self):
        """select() returns the parsed ROE spec dict."""
        mgr = MultiROEManager()
        original = _minimal_roe("ENG-SEL-001")
        mgr.add_roe(original)

        spec = mgr.select("ENG-SEL-001")
        assert spec["metadata"]["engagement_id"] == "ENG-SEL-001"

    def test_select_unknown_raises(self):
        """select() on an unknown engagement_id raises KeyError."""
        mgr = MultiROEManager()
        with pytest.raises(KeyError):
            mgr.select("NOPE")

    def test_load_all_from_directory(self):
        """Initializing with a directory loads all .yaml files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(3):
                spec = {
                    "roe": _minimal_roe(f"ENG-DIR-{i}", f"Client {i}")
                }
                path = Path(tmpdir) / f"roe_{i}.yaml"
                with open(path, "w") as f:
                    yaml.dump(spec, f)

            mgr = MultiROEManager(roe_dir=tmpdir)
            assert len(mgr.list_all()) == 3

    def test_load_file_not_found(self):
        """Loading a nonexistent file raises FileNotFoundError."""
        mgr = MultiROEManager()
        with pytest.raises(FileNotFoundError):
            mgr.load_roe("/nonexistent/path/roe.yaml")

    def test_roe_hash_is_deterministic(self):
        """The same spec produces the same hash."""
        mgr = MultiROEManager()
        spec = _minimal_roe("ENG-HASH-001")
        entry = mgr.add_roe(copy.deepcopy(spec))

        mgr2 = MultiROEManager()
        entry2 = mgr2.add_roe(copy.deepcopy(spec))

        assert entry.roe_hash == entry2.roe_hash
