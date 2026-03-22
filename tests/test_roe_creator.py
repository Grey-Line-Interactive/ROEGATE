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
        """All 10 accordion sections must be present."""
        assert "Metadata" in self.html
        assert "Schedule" in self.html
        assert "Scope &mdash; In-Scope" in self.html or "In-Scope" in self.html
        assert "Scope &mdash; Out-of-Scope" in self.html or "Out-of-Scope" in self.html
        assert "Actions &mdash; Allowed" in self.html or "Allowed" in self.html
        assert "Actions &mdash; Denied" in self.html or "Denied" in self.html
        assert "Requires Approval" in self.html
        assert "Constraints" in self.html
        assert "Data Handling" in self.html
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

    # ── New tests for overhauled creator ──────────────────────────────

    def test_contains_all_action_categories(self):
        """All 24 ActionCategory values must be present in the HTML."""
        categories = [
            "reconnaissance", "port_scanning", "service_enumeration",
            "web_application_testing", "api_testing", "authentication_testing",
            "credential_testing", "authorization_testing", "injection_testing",
            "exploitation", "post_exploitation",
            "lateral_movement", "privilege_escalation",
            "data_exfiltration", "denial_of_service",
            "social_engineering", "physical", "wireless", "cloud",
            "direct_database_access", "file_access", "command_execution",
            "network_connect", "other",
        ]
        for cat in categories:
            assert cat in self.html, f"Missing category: {cat}"

    def test_contains_data_handling_section(self):
        assert "sec-data-handling" in self.html
        assert "dh-pii" in self.html
        assert "dh-credentials" in self.html
        assert "dh-evidence-size" in self.html
        assert "dh-encryption" in self.html
        assert "dh-max-records" in self.html
        # Check select options
        assert "hash_and_log_metadata_only" in self.html
        assert "log_existence_only_no_values" in self.html
        assert "AES-256-GCM" in self.html
        assert "ChaCha20-Poly1305" in self.html

    def test_contains_requires_approval_section(self):
        assert "sec-requires-approval" in self.html
        assert "requires-approval-list" in self.html
        assert "addRequiresApprovalRow" in self.html
        # Check approver options
        assert "human_operator" in self.html
        assert "team_lead" in self.html
        assert "client_poc" in self.html

    def test_contains_match_criteria_fields(self):
        assert "match-criteria" in self.html
        assert "dm-ports" in self.html
        assert "dm-protos" in self.html
        assert "dm-targets" in self.html
        assert "dm-rct" in self.html

    def test_service_types_match_schema(self):
        """All 11 service types from schema must be in the HTML."""
        service_types = [
            "web_application", "database", "email", "dns", "ftp",
            "ssh", "rdp", "smb", "ldap", "api", "custom",
        ]
        for stype in service_types:
            assert stype in self.html, f"Missing service type: {stype}"

    def test_contains_created_field(self):
        assert 'id="meta-created"' in self.html
        assert "datetime-local" in self.html

    def test_contains_version_field(self):
        assert 'id="meta-version"' in self.html

    def test_contains_notes_field(self):
        assert 'id="meta-notes"' in self.html
        assert "<textarea" in self.html

    def test_validation_engagement_format(self):
        """Engagement ID format regex must be present."""
        assert "ENG-" in self.html
        # The regex pattern for engagement ID validation
        assert "\\d{4}" in self.html or "\\\\d{4}" in self.html

    def test_contains_blackout_windows(self):
        """Blackout model should use blackout_windows (not just blackout_dates objects)."""
        assert "blackout-windows-list" in self.html or "addBlackoutWindow" in self.html

    def test_contains_in_scope_services(self):
        """In-scope section should have a services subsection."""
        assert "in-scope-services" in self.html
        assert "addInScopeService" in self.html

    def test_contains_max_bandwidth(self):
        """Constraints section should have max_bandwidth field."""
        assert "con-max-bandwidth" in self.html

    def test_contains_auto_halt_conditions(self):
        """Emergency section should have auto_halt_conditions checkboxes."""
        assert "auto-halt-conditions" in self.html
        assert "ahc-cb" in self.html

    def test_no_notification_webhook(self):
        """Notification webhook should be removed (not in schema)."""
        assert 'id="em-webhook"' not in self.html

    def test_no_tester_field(self):
        """Tester field should be removed (not in schema)."""
        assert 'id="meta-tester"' not in self.html

    def test_no_classification_field(self):
        """Classification field should be removed (not in schema)."""
        assert 'id="meta-classification"' not in self.html

    def test_approved_by_is_required(self):
        """approved_by must be marked as required."""
        # Check that it has data-required attribute
        idx = self.html.find('id="meta-approved-by"')
        assert idx != -1
        # Check nearby content for data-required
        context = self.html[max(0, idx - 200):idx + 200]
        assert "data-required" in context

    def test_validation_summary_panel(self):
        """Validation summary panel must exist."""
        assert "validation-summary" in self.html

    def test_category_optgroups(self):
        """Categories should use optgroup for grouping."""
        assert "<optgroup" in self.html or "optgroup" in self.html
