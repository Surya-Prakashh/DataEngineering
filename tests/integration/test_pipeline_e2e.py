
"""
test_pipeline_e2e.py — Integration tests for the end-to-end MalwareScope pipeline.

These tests exercise the full HTTP API via the Flask test client.
They assert on response shape, status codes, and key field presence.

Note: These tests require the full application stack and are run separately
from unit tests in CI (job: integration-tests).
"""


# ─────────────────────────────────────────────────────────────────────────────
#  Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDatasetStatusEndpoint:
    """Tests for /api/pipeline/dataset_status."""

    def test_dataset_status_returns_200(self, flask_test_client):
        """Dataset status endpoint must respond with HTTP 200."""
        response = flask_test_client.get("/api/pipeline/dataset_status")
        assert response.status_code == 200, \
            f"Expected 200, got {response.status_code}"

    def test_dataset_status_has_required_fields(self, flask_test_client):
        """Response must include total_rows, baseline_rows, status fields."""
        response = flask_test_client.get("/api/pipeline/dataset_status")
        data = response.get_json()
        assert data is not None, "Response is not valid JSON"
        for field in ("total_rows", "baseline_rows", "added_rows", "status"):
            assert field in data, f"Missing field '{field}' in dataset_status response"

    def test_dataset_total_rows_is_positive(self, flask_test_client):
        """total_rows must be a positive integer."""
        response = flask_test_client.get("/api/pipeline/dataset_status")
        data = response.get_json()
        assert data["total_rows"] > 0, "total_rows must be > 0"

    def test_dataset_status_values_are_baseline(self, flask_test_client):
        """Status must be 'BASELINE' or 'EXPANDED' (valid enum)."""
        response = flask_test_client.get("/api/pipeline/dataset_status")
        data = response.get_json()
        assert data["status"] in ("BASELINE", "EXPANDED"), \
            f"Unexpected status value: {data['status']}"


class TestPhase1Endpoints:
    """Smoke tests for Phase 1 API endpoints."""

    def test_dataset_overview_200(self, flask_test_client):
        """Phase 1 dataset overview must return 200."""
        response = flask_test_client.get("/api/phase1/dataset_overview")
        assert response.status_code == 200

    def test_dataset_overview_rows_positive(self, flask_test_client):
        """dataset_overview.rows must be > 0."""
        data = flask_test_client.get("/api/phase1/dataset_overview").get_json()
        assert data["rows"] > 0

    def test_class_distribution_200(self, flask_test_client):
        """Phase 1 class distribution must return 200."""
        response = flask_test_client.get("/api/phase1/class_distribution")
        assert response.status_code == 200

    def test_class_distribution_has_labels_and_values(self, flask_test_client):
        """class_distribution response must contain 'labels' and 'values'."""
        data = flask_test_client.get("/api/phase1/class_distribution").get_json()
        assert "labels" in data and "values" in data

    def test_class_distribution_nine_families(self, flask_test_client):
        """There should be exactly 9 malware family labels."""
        data = flask_test_client.get("/api/phase1/class_distribution").get_json()
        assert len(data["labels"]) == 9, \
            f"Expected 9 family labels, got {len(data['labels'])}"

    def test_missing_values_endpoint_200(self, flask_test_client):
        """Phase 1 missing_values endpoint must return 200."""
        response = flask_test_client.get("/api/phase1/missing_values")
        assert response.status_code == 200

    def test_missing_values_zero_missing(self, flask_test_client):
        """The dataset must report zero missing values."""
        data = flask_test_client.get("/api/phase1/missing_values").get_json()
        assert data["total_missing"] == 0, \
            f"Expected 0 missing values, got {data['total_missing']}"

    def test_normalization_stats_200(self, flask_test_client):
        """Normalization stats endpoint must return 200."""
        response = flask_test_client.get("/api/phase1/normalization_stats")
        assert response.status_code == 200

    def test_normalization_stats_returns_list(self, flask_test_client):
        """Normalization stats must return a list of feature records."""
        data = flask_test_client.get("/api/phase1/normalization_stats").get_json()
        assert isinstance(data, list) and len(data) > 0

    def test_entropy_by_family_200(self, flask_test_client):
        """Entropy by family endpoint must return 200."""
        response = flask_test_client.get("/api/phase1/entropy_by_family")
        assert response.status_code == 200


class TestPhase4KafkaEndpoints:
    """Smoke tests for Phase 4 Kafka stream endpoints."""

    def test_kafka_stream_status_200(self, flask_test_client):
        """Kafka stream status endpoint must return 200."""
        response = flask_test_client.get("/api/phase4/kafka_stream_status")
        assert response.status_code == 200

    def test_kafka_stream_status_has_partitions(self, flask_test_client):
        """Kafka stream status must report partition information."""
        data = flask_test_client.get("/api/phase4/kafka_stream_status").get_json()
        assert "partitions" in data or "partition_metrics" in data or "topics" in data, \
            f"Kafka status missing partition info. Keys: {list(data.keys())}"

    def test_phase4_report_200(self, flask_test_client):
        """Phase 4 report endpoint must return 200."""
        response = flask_test_client.get("/api/phase4/report")
        assert response.status_code == 200


class TestEndToEndPipeline:
    """End-to-end pipeline integration test."""

    def test_e2e_pipeline_returns_success(self, flask_test_client):
        """The end-to-end pipeline must complete with status SUCCESS."""
        response = flask_test_client.post("/api/pipeline/run_e2e")
        assert response.status_code == 200, \
            f"Pipeline returned HTTP {response.status_code}"
        data = response.get_json()
        assert data["status"] == "SUCCESS", \
            f"Pipeline did not succeed: {data.get('status')}"

    def test_e2e_pipeline_returns_step_breakdown(self, flask_test_client):
        """Pipeline response must include per-phase step_breakdown."""
        data = flask_test_client.post("/api/pipeline/run_e2e").get_json()
        assert "step_breakdown" in data, "Missing 'step_breakdown' in pipeline response"
        breakdown = data["step_breakdown"]
        for phase in ("phase1", "phase2", "phase3", "phase4"):
            assert phase in breakdown, f"Missing '{phase}' in step_breakdown"

    def test_e2e_pipeline_duration_is_positive(self, flask_test_client):
        """Total pipeline duration must be a positive number."""
        data = flask_test_client.post("/api/pipeline/run_e2e").get_json()
        assert data["total_duration_ms"] > 0, \
            f"total_duration_ms is {data['total_duration_ms']}"

    def test_e2e_pipeline_logs_are_present(self, flask_test_client):
        """Pipeline response must include a non-empty logs list."""
        data = flask_test_client.post("/api/pipeline/run_e2e").get_json()
        assert "logs" in data and len(data["logs"]) > 0, \
            "Pipeline returned no execution logs"

    def test_e2e_phase4_staging_rows_positive(self, flask_test_client):
        """Phase 4 must have written at least 1 row to staging."""
        data = flask_test_client.post("/api/pipeline/run_e2e").get_json()
        staging_rows = data["step_breakdown"]["phase4"]["staging_rows"]
        assert staging_rows > 0, \
            f"Expected staging_rows > 0, got {staging_rows}"
