import csv
import io
import tempfile
import unittest
from pathlib import Path

from app import create_app
from auth_test_support import instructor_environment, login_instructor
from simulation.analytics import AnalyticsService
from simulation.campaign_service import load_campaigns
from simulation.database import DEFAULT_CAMPAIGN_ID, database_connection
from simulation.event_store import SQLiteEventStore


class AnalyticsServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "phishshield.db"
        self.samples = load_campaigns()
        self.store = SQLiteEventStore(self.database_path, self.samples)
        self.analytics = AnalyticsService(self.database_path)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_dashboard_returns_zero_values_for_empty_database(self):
        dashboard = self.analytics.dashboard_data()

        self.assertEqual(dashboard["summary"]["total_campaigns"], 1)
        self.assertEqual(dashboard["summary"]["display_events"], 0)
        self.assertEqual(dashboard["summary"]["unique_displayed"], 0)
        self.assertEqual(dashboard["campaigns"][0]["click_rate"], 0)
        self.assertFalse(dashboard["timeline"]["available"])
        self.assertIn("No campaign events", dashboard["timeline"]["reason"])

    def test_campaign_and_scenario_rates_use_unique_displayed_denominator(self):
        self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-a", "open"
        )
        self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-b", "open"
        )
        self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-a", "click"
        )
        self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-b", "report"
        )

        dashboard = self.analytics.dashboard_data()
        campaign = dashboard["campaigns"][0]
        scenario = next(
            row for row in dashboard["scenarios"]
            if row["scenario"] == "Fictional account-security notice"
        )

        self.assertEqual(campaign["display_events"], 2)
        self.assertEqual(campaign["click_events"], 1)
        self.assertEqual(campaign["unique_displayed"], 2)
        self.assertEqual(campaign["unique_clicked"], 1)
        self.assertEqual(campaign["unique_reported"], 1)
        self.assertEqual(campaign["click_rate"], 50)
        self.assertEqual(campaign["report_rate"], 50)
        self.assertEqual(scenario["display_events"], 2)
        self.assertEqual(scenario["click_rate"], 50)
        self.assertEqual(scenario["report_rate"], 50)

    def test_event_count_metrics_are_distinct_from_unique_participants(self):
        self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-a", "open"
        )
        self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-a", "click"
        )
        dashboard = self.analytics.dashboard_data()

        self.assertEqual(dashboard["summary"]["display_events"], 1)
        self.assertEqual(dashboard["summary"]["click_events"], 1)
        self.assertEqual(dashboard["summary"]["unique_displayed"], 1)
        self.assertEqual(dashboard["summary"]["unique_clicked"], 1)

    def test_global_unique_participants_are_not_summed_across_campaigns(self):
        self.store.create_campaign("class-two", "Class Two")
        self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "shared-participant", "open"
        )
        self.store.record_once(
            "class-two", "PS-PH-001", "shared-participant", "open"
        )
        self.store.record_once(
            "class-two", "PS-PH-002", "second-participant", "open"
        )

        summary = self.analytics.dashboard_data()["summary"]
        self.assertEqual(summary["total_campaigns"], 2)
        self.assertEqual(summary["display_events"], 3)
        self.assertEqual(summary["unique_displayed"], 2)

    def test_campaign_filter_and_individual_summary(self):
        self.store.create_campaign("class-two", "Class Two")
        self.store.record_once(
            "class-two", "PS-PH-001", "participant-a", "open"
        )

        filtered = self.analytics.dashboard_data(campaign_id="class-two")
        detail = self.analytics.campaign_detail("class-two")

        self.assertEqual(filtered["summary"]["total_campaigns"], 1)
        self.assertEqual(filtered["summary"]["display_events"], 1)
        self.assertEqual(len(filtered["campaign_options"]), 2)
        self.assertEqual(detail["campaign"]["campaign_id"], "class-two")
        self.assertIsNone(self.analytics.campaign_detail("missing-campaign"))

    def test_timeline_groups_valid_dates_and_reports_invalid_timestamps(self):
        event, _created = self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-a", "open"
        )
        timeline = self.analytics.event_timeline(days=5)

        self.assertTrue(timeline["available"])
        self.assertEqual(len(timeline["days"]), 5)
        self.assertEqual(sum(day["displayed"] for day in timeline["days"]), 1)

        with database_connection(self.database_path) as connection:
            connection.execute(
                "UPDATE events SET timestamp = ? WHERE event_id = ?",
                ("not-a-timestamp", event["event_id"]),
            )
            connection.commit()
        invalid_only = self.analytics.event_timeline(days=5)
        self.assertFalse(invalid_only["available"])
        self.assertEqual(invalid_only["invalid_timestamps"], 1)

    def test_csv_export_contains_aggregated_metrics(self):
        self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-a", "open"
        )
        self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-a", "click"
        )

        rows = list(csv.DictReader(io.StringIO(self.analytics.export_campaign_csv())))
        self.assertEqual(rows[0]["display_events"], "1")
        self.assertEqual(rows[0]["click_events"], "1")
        self.assertEqual(rows[0]["click_through_rate_percent"], "100.00")

    def test_csv_export_neutralizes_spreadsheet_formulas(self):
        self.store.create_campaign("=SUM(1,1)", "=SUM(1,1)")
        exported = self.analytics.export_campaign_csv()
        self.assertIn("'=SUM(1,1)", exported)

    def test_dashboard_routes_render_export_and_reject_unknown_campaign(self):
        with instructor_environment():
            app = create_app(
                database_path=self.database_path,
                secret_key="analytics-route-test",
            )
        app.config.update(TESTING=True)
        client = app.test_client()
        self.assertEqual(login_instructor(client).status_code, 302)

        dashboard_response = client.get("/dashboard")
        detail_response = client.get(
            f"/dashboard/campaign/{DEFAULT_CAMPAIGN_ID}"
        )
        unknown_response = client.get("/dashboard/campaign/unknown")
        csv_response = client.get("/dashboard/export.csv")
        chart_script_response = client.get("/static/js/dashboard.js")

        self.assertEqual(dashboard_response.status_code, 200)
        self.assertIn(b"Total campaigns", dashboard_response.data)
        self.assertIn(b"Click-through and report rates", dashboard_response.data)
        self.assertIn(b"How to interpret these results", dashboard_response.data)
        self.assertEqual(detail_response.status_code, 200)
        self.assertEqual(unknown_response.status_code, 404)
        self.assertEqual(csv_response.status_code, 200)
        self.assertTrue(csv_response.mimetype.startswith("text/csv"))
        self.assertIn(b"unique_displayed_participants", csv_response.data)
        self.assertEqual(chart_script_response.status_code, 200)
        self.assertIn(b"renderCampaignChart", chart_script_response.data)
        chart_script_response.close()
        self.assertIn(b"campaign-chart", dashboard_response.data)
        self.assertIn(b"Scenario outcomes", dashboard_response.data)


if __name__ == "__main__":
    unittest.main()
