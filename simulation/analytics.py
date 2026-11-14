"""Read-only, SQLite-backed campaign analytics for the instructor dashboard."""

import csv
import io
import sqlite3
from datetime import date, datetime, timedelta, timezone

from simulation.database import database_connection
from simulation.event_store import EventStoreError


TIMELINE_DAYS = 30


class AnalyticsService:
    """Build aggregate dashboard views directly from Module 3 tables."""

    def __init__(self, database_path):
        self.database_path = database_path

    def dashboard_data(self, campaign_id=None):
        campaign_options = self.list_campaign_statistics()
        campaigns = campaign_options
        if campaign_id is not None:
            campaigns = [
                campaign for campaign in campaigns
                if campaign["campaign_id"] == campaign_id
            ]
        summary = self.summary(campaign_id=campaign_id)
        scenario_rows = self.list_scenario_statistics(campaign_id=campaign_id)
        timeline = self.event_timeline(campaign_id=campaign_id)
        recent_activity = self.recent_activity(campaign_id=campaign_id)
        return {
            "summary": summary,
            "campaigns": campaigns,
            "campaign_options": campaign_options,
            "scenarios": scenario_rows,
            "timeline": timeline,
            "recent_activity": recent_activity,
            "selected_campaign_id": campaign_id,
        }

    def summary(self, campaign_id=None):
        condition = "WHERE c.campaign_id = ?" if campaign_id is not None else ""
        parameters = (campaign_id,) if campaign_id is not None else ()
        query = f"""
            SELECT
                COUNT(DISTINCT c.campaign_id) AS total_campaigns,
                COUNT(DISTINCT CASE WHEN c.status = 'active' AND p.campaign_id IS NULL
                    THEN c.campaign_id END) AS active_campaigns,
                COUNT(DISTINCT CASE WHEN c.status = 'completed'
                    THEN c.campaign_id END) AS completed_campaigns,
                COALESCE(SUM(CASE WHEN e.event_type = 'displayed' THEN 1 ELSE 0 END), 0)
                    AS display_events,
                COALESCE(SUM(CASE WHEN e.event_type = 'clicked' THEN 1 ELSE 0 END), 0)
                    AS click_events,
                COALESCE(SUM(CASE WHEN e.event_type = 'reported' THEN 1 ELSE 0 END), 0)
                    AS report_events,
                COUNT(DISTINCT CASE WHEN e.event_type = 'displayed'
                    THEN e.participant_id END) AS unique_displayed,
                COUNT(DISTINCT CASE WHEN e.event_type = 'clicked'
                    THEN e.participant_id END) AS unique_clicked,
                COUNT(DISTINCT CASE WHEN e.event_type = 'reported'
                    THEN e.participant_id END) AS unique_reported
            FROM campaigns AS c
            LEFT JOIN events AS e ON e.campaign_id = c.campaign_id
            LEFT JOIN campaign_pauses AS p ON p.campaign_id = c.campaign_id
            {condition}
        """
        action_condition = (
            "WHERE campaign_id = ?" if campaign_id is not None else ""
        )
        action_parameters = (campaign_id,) if campaign_id is not None else ()
        try:
            with database_connection(self.database_path) as connection:
                row = connection.execute(query, parameters).fetchone()
                action_row = connection.execute(
                    f"""
                    SELECT
                        COUNT(DISTINCT CASE WHEN action_type = 'joined'
                            THEN participant_id END) AS joined_participants,
                        COUNT(DISTINCT CASE WHEN action_type = 'completed'
                            THEN participant_id END) AS completed_participants,
                        SUM(CASE WHEN action_type = 'answered' AND is_correct = 1
                            THEN 1 ELSE 0 END) AS correct_responses,
                        SUM(CASE WHEN action_type = 'answered' AND is_correct = 0
                            THEN 1 ELSE 0 END) AS incorrect_responses
                    FROM participant_actions
                    {action_condition}
                    """,
                    action_parameters,
                ).fetchone()
                unique_condition = (
                    " AND campaign_id = ?" if campaign_id is not None else ""
                )
                unique_parameters = (
                    (campaign_id, campaign_id)
                    if campaign_id is not None else ()
                )
                unique_participants = connection.execute(
                    f"""
                    SELECT COUNT(DISTINCT participant_id) FROM (
                        SELECT participant_id FROM events
                        WHERE event_type = 'displayed'{unique_condition}
                        UNION
                        SELECT participant_id FROM participant_actions
                        WHERE action_type = 'joined'{unique_condition}
                    )
                    """,
                    unique_parameters,
                ).fetchone()[0]
                result = {**dict(row), **dict(action_row)}
                for key in ("correct_responses", "incorrect_responses"):
                    result[key] = result[key] or 0
                result["joined_participants"] = result["joined_participants"] or 0
                result["completed_participants"] = (
                    result["completed_participants"] or 0
                )
                result["unique_participants"] = unique_participants
                result["completion_rate"] = _rate(
                    result["completed_participants"],
                    result["joined_participants"],
                )
                return result
        except sqlite3.Error as error:
            raise EventStoreError(
                f"Could not calculate dashboard totals: {error}"
            ) from error

    def list_campaign_statistics(self):
        query = """
            SELECT
                c.campaign_id,
                c.campaign_name,
                c.description,
                c.created_at,
                c.started_at,
                c.completed_at,
                CASE WHEN p.campaign_id IS NOT NULL
                    THEN 'paused' ELSE c.status END AS status,
                COALESCE(SUM(CASE WHEN e.event_type = 'displayed' THEN 1 ELSE 0 END), 0)
                    AS display_events,
                COALESCE(SUM(CASE WHEN e.event_type = 'clicked' THEN 1 ELSE 0 END), 0)
                    AS click_events,
                COALESCE(SUM(CASE WHEN e.event_type = 'reported' THEN 1 ELSE 0 END), 0)
                    AS report_events,
                COUNT(DISTINCT CASE WHEN e.event_type = 'displayed'
                    THEN e.participant_id END) AS unique_displayed,
                COUNT(DISTINCT CASE WHEN e.event_type = 'clicked'
                    THEN e.participant_id END) AS unique_clicked,
                COUNT(DISTINCT CASE WHEN e.event_type = 'reported'
                    THEN e.participant_id END) AS unique_reported
            FROM campaigns AS c
            LEFT JOIN events AS e ON e.campaign_id = c.campaign_id
            LEFT JOIN campaign_pauses AS p ON p.campaign_id = c.campaign_id
            GROUP BY c.campaign_id
            ORDER BY c.created_at, c.campaign_id
        """
        try:
            with database_connection(self.database_path) as connection:
                rows = [dict(row) for row in connection.execute(query)]
                for row in rows:
                    row["click_rate"] = _rate(
                        row["unique_clicked"], row["unique_displayed"]
                    )
                    row["report_rate"] = _rate(
                        row["unique_reported"], row["unique_displayed"]
                    )
                    action_row = connection.execute(
                        """
                        SELECT
                            COUNT(DISTINCT CASE WHEN action_type = 'joined'
                                THEN participant_id END) AS joined_participants,
                            COUNT(DISTINCT CASE WHEN action_type = 'completed'
                                THEN participant_id END) AS completed_participants,
                            SUM(CASE WHEN action_type = 'answered'
                                AND is_correct = 1 THEN 1 ELSE 0 END) AS correct_responses,
                            SUM(CASE WHEN action_type = 'answered'
                                AND is_correct = 0 THEN 1 ELSE 0 END) AS incorrect_responses
                        FROM participant_actions WHERE campaign_id = ?
                        """,
                        (row["campaign_id"],),
                    ).fetchone()
                    row.update(dict(action_row))
                    row["correct_responses"] = row["correct_responses"] or 0
                    row["incorrect_responses"] = row["incorrect_responses"] or 0
                    row["joined_participants"] = row["joined_participants"] or 0
                    row["completed_participants"] = (
                        row["completed_participants"] or 0
                    )
                    row["completion_rate"] = _rate(
                        row["completed_participants"], row["joined_participants"]
                    )
                return rows
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not calculate campaign analytics: {error}") from error

    def list_scenario_statistics(self, campaign_id=None):
        campaign_join = (
            "AND e.campaign_id = ?" if campaign_id is not None else ""
        )
        query = f"""
            SELECT
                s.scenario,
                s.email_type,
                COUNT(DISTINCT CASE WHEN e.event_type = 'displayed'
                    THEN e.event_id END) AS display_events,
                COUNT(DISTINCT CASE WHEN e.event_type = 'clicked'
                    THEN e.event_id END) AS click_events,
                COUNT(DISTINCT CASE WHEN e.event_type = 'reported'
                    THEN e.event_id END) AS report_events,
                COUNT(DISTINCT CASE WHEN e.event_type = 'displayed'
                    THEN e.participant_id END) AS unique_displayed,
                COUNT(DISTINCT CASE WHEN e.event_type = 'clicked'
                    THEN e.participant_id END) AS unique_clicked,
                COUNT(DISTINCT CASE WHEN e.event_type = 'reported'
                    THEN e.participant_id END) AS unique_reported
            FROM email_samples AS s
            LEFT JOIN events AS e ON e.email_id = s.email_id
                {campaign_join}
            GROUP BY s.scenario, s.email_type
            ORDER BY s.scenario, s.email_type
        """
        try:
            with database_connection(self.database_path) as connection:
                query_parameters = (campaign_id,) if campaign_id is not None else ()
                rows = [
                    dict(row)
                    for row in connection.execute(query, query_parameters)
                ]
                for row in rows:
                    row["click_rate"] = _rate(
                        row["unique_clicked"], row["unique_displayed"]
                    )
                    row["report_rate"] = _rate(
                        row["unique_reported"], row["unique_displayed"]
                    )
                return rows
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not calculate scenario analytics: {error}") from error

    def event_timeline(self, campaign_id=None, days=TIMELINE_DAYS):
        if not isinstance(days, int) or not 1 <= days <= 366:
            raise ValueError("Timeline days must be between 1 and 366.")
        conditions = []
        parameters = []
        if campaign_id is not None:
            conditions.append("campaign_id = ?")
            parameters.append(campaign_id)
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        try:
            with database_connection(self.database_path) as connection:
                rows = connection.execute(
                    f"""
                    SELECT timestamp, event_type
                    FROM events
                    {where_clause}
                    ORDER BY timestamp
                    """,
                    parameters,
                ).fetchall()
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not retrieve event timeline: {error}") from error

        grouped = {}
        invalid_count = 0
        for row in rows:
            event_date = _parse_timestamp_date(row["timestamp"])
            if event_date is None:
                invalid_count += 1
                continue
            daily = grouped.setdefault(
                event_date.isoformat(),
                {"displayed": 0, "clicked": 0, "reported": 0},
            )
            if row["event_type"] in daily:
                daily[row["event_type"]] += 1

        if not grouped:
            return {
                "available": False,
                "reason": (
                    "No valid event timestamps are available yet."
                    if rows
                    else "No campaign events have been recorded yet."
                ),
                "invalid_timestamps": invalid_count,
                "days": [],
            }

        latest_date = max(date.fromisoformat(value) for value in grouped)
        start_date = latest_date - timedelta(days=days - 1)
        timeline_days = []
        for offset in range(days):
            current = start_date + timedelta(days=offset)
            daily = grouped.get(
                current.isoformat(),
                {"displayed": 0, "clicked": 0, "reported": 0},
            )
            timeline_days.append({"date": current.isoformat(), **daily})

        return {
            "available": True,
            "reason": "",
            "invalid_timestamps": invalid_count,
            "days": timeline_days,
        }

    def campaign_detail(self, campaign_id):
        data = self.dashboard_data(campaign_id=campaign_id)
        if not data["campaigns"]:
            return None
        data["campaign"] = data["campaigns"][0]
        data["participants"] = self.campaign_participants(campaign_id)
        return data

    def campaign_participants(self, campaign_id):
        try:
            with database_connection(self.database_path) as connection:
                rows = connection.execute(
                    """
                    SELECT p.participant_id, p.created_at,
                        SUM(CASE WHEN a.action_type = 'answered'
                            AND a.is_correct = 1 THEN 1 ELSE 0 END) AS correct_answers,
                        SUM(CASE WHEN a.action_type = 'answered'
                            AND a.is_correct = 0 THEN 1 ELSE 0 END) AS incorrect_answers,
                        MAX(CASE WHEN a.action_type = 'completed' THEN 1 ELSE 0 END)
                            AS completed
                    FROM participants AS p
                    JOIN participant_actions AS a
                        ON a.participant_id = p.participant_id
                    WHERE a.campaign_id = ?
                    GROUP BY p.participant_id
                    ORDER BY p.created_at DESC
                    """,
                    (campaign_id,),
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as error:
            raise EventStoreError(
                f"Could not retrieve campaign participants: {error}"
            ) from error

    def recent_activity(self, campaign_id=None, limit=15):
        if not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("Recent activity limit must be between 1 and 100.")
        event_filter = "WHERE e.campaign_id = ?" if campaign_id else ""
        action_filter = "WHERE a.campaign_id = ?" if campaign_id else ""
        parameters = (
            (campaign_id, campaign_id, limit)
            if campaign_id else (limit,)
        )
        try:
            with database_connection(self.database_path) as connection:
                rows = connection.execute(
                    f"""
                    SELECT * FROM (
                        SELECT e.timestamp, e.campaign_id, c.campaign_name,
                            e.participant_id, e.email_id, e.event_type AS action,
                            NULL AS response, NULL AS is_correct
                        FROM events AS e
                        JOIN campaigns AS c ON c.campaign_id = e.campaign_id
                        {event_filter}
                        UNION ALL
                        SELECT a.timestamp, a.campaign_id, c.campaign_name,
                            a.participant_id, a.email_id, a.action_type AS action,
                            a.response, a.is_correct
                        FROM participant_actions AS a
                        JOIN campaigns AS c ON c.campaign_id = a.campaign_id
                        {action_filter}
                    )
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    parameters,
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not retrieve recent activity: {error}") from error

    def export_campaign_csv(self):
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(
            [
                "campaign_id",
                "campaign_name",
                "status",
                "display_events",
                "click_events",
                "report_events",
                "unique_displayed_participants",
                "unique_clicked_participants",
                "click_through_rate_percent",
                "unique_reported_participants",
                "report_rate_percent",
            ]
        )
        for campaign in self.list_campaign_statistics():
            writer.writerow(
                [
                    _safe_csv_value(campaign["campaign_id"]),
                    _safe_csv_value(campaign["campaign_name"]),
                    _safe_csv_value(campaign["status"]),
                    campaign["display_events"],
                    campaign["click_events"],
                    campaign["report_events"],
                    campaign["unique_displayed"],
                    campaign["unique_clicked"],
                    f'{campaign["click_rate"]:.2f}',
                    campaign["unique_reported"],
                    f'{campaign["report_rate"]:.2f}',
                ]
            )
        return output.getvalue()


def _rate(numerator, denominator):
    if denominator == 0:
        return 0.0
    return numerator / denominator * 100


def _parse_timestamp_date(value):
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).date()


def _safe_csv_value(value):
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text
