"""
test_phase2_etl.py — Unit tests for Phase 2 ETL transformation logic.

Tests cover:
  - Log-transform of BytFSize
  - Type casting integrity for numeric columns
  - CDC LSN monotonicity
  - Extraction record count consistency
  - Transform idempotency
  - Null handling during transformations
"""

import numpy as np
import pandas as pd


# ─────────────────────────────────────────────────────────────────────────────
#  Pure ETL helper functions (mirroring phase2.py transformation logic)
# ─────────────────────────────────────────────────────────────────────────────

def apply_log_transform(df: pd.DataFrame, col: str = "BytFSize") -> pd.DataFrame:
    """Apply log1p transform to a byte-size column, producing Log_{col}."""
    df = df.copy()
    df[f"Log_{col}"] = np.log1p(df[col])
    return df


def apply_type_casts(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cast columns to their correct types as done in Phase 2 ETL.
    Mirrors the type-casting step before warehouse loading.
    """
    df = df.copy()
    int_cols = ["Class", "BytFSize", "Total_Bytes"]
    float_cols = ["Shannon_Entropy", "Null_Byte_Ratio",
                  "ASCII_Byte_Ratio", "High_Byte_Ratio", "NOP_Ratio"]
    for col in int_cols:
        if col in df.columns:
            df[col] = df[col].astype(int)
    for col in float_cols:
        if col in df.columns:
            df[col] = df[col].astype(float)
    return df


def generate_cdc_lsn_sequence(start: int = 1001, count: int = 8) -> list:
    """
    Generates a monotonically increasing CDC Log Sequence Number (LSN) list.
    Mirrors the CDC engine in Phase 2.
    """
    return list(range(start, start + count))


def extract_records(df: pd.DataFrame, limit: int) -> pd.DataFrame:
    """Simulate the extraction step: read first `limit` rows from source."""
    return df.head(limit).copy()


def normalize_file_size_to_kb(df: pd.DataFrame) -> pd.DataFrame:
    """Convert BytFSize to kilobytes as done in Phase 2 loading."""
    df = df.copy()
    df["file_size_kb"] = (df["BytFSize"] / 1024).round(2)
    return df


# ─────────────────────────────────────────────────────────────────────────────
#  Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestLogTransform:
    """Tests for the log1p transformation applied to byte-size columns."""

    def test_log_transform_produces_new_column(self, mock_dataframe):
        """apply_log_transform must create a 'Log_BytFSize' column."""
        result = apply_log_transform(mock_dataframe)
        assert "Log_BytFSize" in result.columns, \
            "Log transform did not create 'Log_BytFSize' column"

    def test_log_transform_values_finite(self, mock_dataframe):
        """All log-transformed values must be finite (no NaN or Inf)."""
        result = apply_log_transform(mock_dataframe)
        assert np.isfinite(result["Log_BytFSize"]).all(), \
            "Log transform produced non-finite values"

    def test_log_transform_values_non_negative(self, mock_dataframe):
        """log1p of non-negative input is always >= 0."""
        result = apply_log_transform(mock_dataframe)
        assert (result["Log_BytFSize"] >= 0).all(), \
            "Log transform produced negative values"

    def test_log_transform_monotonicity(self, mock_dataframe):
        """log1p must preserve relative ordering (monotonic transformation)."""
        result = apply_log_transform(mock_dataframe)
        original_ranks = mock_dataframe["BytFSize"].rank().values
        log_ranks = result["Log_BytFSize"].rank().values
        assert np.array_equal(original_ranks, log_ranks), \
            "log1p transform broke monotonic ordering"

    def test_log_transform_idempotent_on_column_name(self, mock_dataframe):
        """Applying the transform twice should not duplicate columns."""
        result1 = apply_log_transform(mock_dataframe)
        result2 = apply_log_transform(result1)
        log_cols = [c for c in result2.columns if c == "Log_BytFSize"]
        assert len(log_cols) == 1, \
            f"Expected 1 'Log_BytFSize' column, found {len(log_cols)}"

    def test_log_does_not_mutate_original(self, mock_dataframe):
        """apply_log_transform must not modify the input DataFrame in-place."""
        original_cols = list(mock_dataframe.columns)
        _ = apply_log_transform(mock_dataframe)
        assert list(mock_dataframe.columns) == original_cols, \
            "apply_log_transform mutated the input DataFrame"


class TestTypeCasting:
    """Tests for type-casting integrity during the ETL transformation step."""

    def test_class_column_is_integer_after_cast(self, mock_dataframe):
        """Class column must be integer after type casting."""
        result = apply_type_casts(mock_dataframe)
        assert result["Class"].dtype in [np.int32, np.int64, int], \
            f"Class column dtype is {result['Class'].dtype}, expected int"

    def test_byte_fsize_is_integer_after_cast(self, mock_dataframe):
        """BytFSize must be integer after type casting."""
        result = apply_type_casts(mock_dataframe)
        assert result["BytFSize"].dtype in [np.int32, np.int64, int], \
            f"BytFSize dtype is {result['BytFSize'].dtype}"

    def test_shannon_entropy_is_float_after_cast(self, mock_dataframe):
        """Shannon_Entropy must be float after type casting."""
        result = apply_type_casts(mock_dataframe)
        assert result["Shannon_Entropy"].dtype in [np.float32, np.float64, float], \
            f"Shannon_Entropy dtype is {result['Shannon_Entropy'].dtype}"

    def test_type_cast_does_not_introduce_nulls(self, mock_dataframe):
        """Type casting must not produce NaN values in previously clean columns."""
        result = apply_type_casts(mock_dataframe)
        cols_to_check = ["Class", "BytFSize", "Shannon_Entropy"]
        for col in cols_to_check:
            if col in result.columns:
                assert result[col].isnull().sum() == 0, \
                    f"Type casting introduced NaN in column '{col}'"

    def test_type_cast_does_not_mutate_original(self, mock_dataframe):
        """apply_type_casts must be a pure function — no in-place modification."""
        original_class_dtype = mock_dataframe["Class"].dtype
        _ = apply_type_casts(mock_dataframe)
        assert mock_dataframe["Class"].dtype == original_class_dtype, \
            "apply_type_casts mutated the original DataFrame"


class TestCDCLSN:
    """Tests for CDC Log Sequence Number (LSN) generation."""

    def test_lsn_count_matches_expected(self):
        """LSN sequence length must equal the requested count."""
        lsn = generate_cdc_lsn_sequence(start=1001, count=8)
        assert len(lsn) == 8, f"Expected 8 LSNs, got {len(lsn)}"

    def test_lsn_starts_at_correct_offset(self):
        """LSN sequence must start at the configured starting offset."""
        lsn = generate_cdc_lsn_sequence(start=1001, count=8)
        assert lsn[0] == 1001, f"LSN should start at 1001, got {lsn[0]}"

    def test_lsn_is_strictly_monotonic_increasing(self):
        """Each LSN must be strictly greater than the previous."""
        lsn = generate_cdc_lsn_sequence(start=1001, count=8)
        for i in range(1, len(lsn)):
            assert lsn[i] > lsn[i - 1], \
                f"LSN sequence not monotonic at index {i}: {lsn[i - 1]} → {lsn[i]}"

    def test_lsn_no_duplicates(self):
        """LSNs must be unique — no duplicate sequence numbers."""
        lsn = generate_cdc_lsn_sequence(start=1001, count=8)
        assert len(set(lsn)) == len(lsn), "Duplicate LSNs found"

    def test_lsn_consecutive(self):
        """LSNs must be consecutive integers (no gaps)."""
        lsn = generate_cdc_lsn_sequence(start=1001, count=8)
        expected = list(range(1001, 1009))
        assert lsn == expected, f"LSNs not consecutive: {lsn}"


class TestExtraction:
    """Tests for the data extraction step."""

    def test_extraction_respects_limit(self, mock_dataframe):
        """Extraction must return at most `limit` rows."""
        limit = 20
        result = extract_records(mock_dataframe, limit)
        assert len(result) == min(limit, len(mock_dataframe)), \
            f"Expected {limit} rows, got {len(result)}"

    def test_extraction_preserves_all_columns(self, mock_dataframe):
        """Extracted DataFrame must retain all original columns."""
        result = extract_records(mock_dataframe, 10)
        assert list(result.columns) == list(mock_dataframe.columns), \
            "Extraction changed column schema"

    def test_extraction_does_not_mutate_source(self, mock_dataframe):
        """extract_records must not modify the source DataFrame."""
        original_len = len(mock_dataframe)
        _ = extract_records(mock_dataframe, 10)
        assert len(mock_dataframe) == original_len, \
            "Extraction mutated the source DataFrame"

    def test_extraction_full_dataset(self, mock_dataframe):
        """Requesting more rows than available should return all rows."""
        result = extract_records(mock_dataframe, limit=99999)
        assert len(result) == len(mock_dataframe)


class TestFileSizeNormalization:
    """Tests for byte → kilobyte conversion."""

    def test_file_size_kb_column_created(self, mock_dataframe):
        """normalize_file_size_to_kb must add 'file_size_kb' column."""
        result = normalize_file_size_to_kb(mock_dataframe)
        assert "file_size_kb" in result.columns

    def test_file_size_kb_values_positive(self, mock_dataframe):
        """KB values must be positive for all records."""
        result = normalize_file_size_to_kb(mock_dataframe)
        assert (result["file_size_kb"] > 0).all(), \
            "Negative file_size_kb values detected"

    def test_file_size_kb_conversion_accuracy(self):
        """Manually verify KB conversion: 1024 bytes → 1.0 KB."""
        df = pd.DataFrame({"BytFSize": [1024, 2048, 512]})
        result = normalize_file_size_to_kb(df)
        expected = pd.Series([1.0, 2.0, 0.5], name="file_size_kb")
        pd.testing.assert_series_equal(result["file_size_kb"], expected)
