"""Streamlit shell smoke test; no dataset is loaded or training started."""

import pytest
from pathlib import Path

pytest.importorskip("streamlit")

from streamlit.testing.v1 import AppTest


def test_dashboard_renders_group_provenance_controls(tmp_path):
    # The default app view is read-only and should render while no model exists.
    (tmp_path / "synthetic.csv").write_text("unused test header\n", encoding="utf-8")
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "app.py",
                            default_timeout=15).run()
    assert not app.exception
    assert app.title[0].value == "Offline Wireless Intrusion Detection"
    app.get_by_key("awid3_source_directory").set_value(str(tmp_path)).run()
    assert app.get_by_key("capture_group_tag").value == "AWID3-Deauth-series-unverified"
    assert app.get_by_key("capture_id_verified").value is False
