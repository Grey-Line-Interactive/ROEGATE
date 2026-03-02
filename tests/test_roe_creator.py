"""Tests for the ROE Creator Dashboard."""

from src.service.roe_creator import build_roe_creator_html


class TestROECreator:
    """Tests for build_roe_creator_html()."""

    def setup_method(self):
        self.html = build_roe_creator_html()

    def test_returns_non_empty_string(self):
        assert isinstance(self.html, str)
        assert len(self.html) > 0

    def test_contains_roe_creator_title(self):
        assert "ROE Creator" in self.html

    def test_contains_all_form_sections(self):
        """All 8 accordion sections must be present."""
        assert "Metadata" in self.html
        assert "Schedule" in self.html
        assert "Scope &mdash; In-Scope" in self.html or "In-Scope" in self.html
        assert "Scope &mdash; Out-of-Scope" in self.html or "Out-of-Scope" in self.html
        assert "Actions &mdash; Allowed" in self.html or "Allowed" in self.html
        assert "Actions &mdash; Denied" in self.html or "Denied" in self.html
        assert "Constraints" in self.html
        assert "Emergency" in self.html

    def test_contains_yaml_preview_panel(self):
        assert "yaml-output" in self.html
        assert "YAML Preview" in self.html

    def test_contains_generate_yaml_function(self):
        assert "function generateYAML()" in self.html

    def test_contains_import_export_buttons(self):
        assert "Import YAML" in self.html
        assert "Download" in self.html
        assert "Copy" in self.html

    def test_valid_html_structure(self):
        assert "<html" in self.html
        assert "<head>" in self.html
        assert "<body>" in self.html
        assert "</html>" in self.html

    def test_contains_validate_function(self):
        assert "function validateForm()" in self.html

    def test_contains_download_function(self):
        assert "function downloadYAML()" in self.html

    def test_contains_copy_function(self):
        assert "function copyYAML()" in self.html

    def test_contains_import_function(self):
        assert "function doImport()" in self.html

    def test_contains_to_yaml_function(self):
        assert "function toYAML(" in self.html

    def test_no_external_cdn_links(self):
        """Page must be fully self-contained."""
        assert "cdn." not in self.html.lower()
        assert "unpkg.com" not in self.html
        assert "jsdelivr" not in self.html

    def test_contains_keyboard_shortcuts(self):
        assert "Ctrl+S" in self.html or "ctrlKey" in self.html
        assert "Ctrl+Shift+C" in self.html or "shiftKey" in self.html

    def test_contains_dark_theme_colors(self):
        assert "#0d1117" in self.html
        assert "#161b22" in self.html
        assert "#00ff41" in self.html

    def test_contains_accordion_mechanics(self):
        assert "toggleAccordion" in self.html
        assert "accordion" in self.html

    def test_contains_dynamic_row_functions(self):
        assert "function addRow" in self.html or "function addInScopeNetwork" in self.html
        assert "function removeRow" in self.html
