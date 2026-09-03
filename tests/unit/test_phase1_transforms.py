"""
test_phase1_transforms.py — Unit tests for Phase 1 feature engineering logic.

Tests cover:
  - Shannon entropy range validation
  - Min-max normalization correctness
  - Class distribution completeness
  - Missing value absence
  - Byte-frequency column variance
  - Engineered feature column presence
  - Log byte-size feature construction
"""

import numpy as np
import pandas as pd

# ─────────────────────────────────────────────────────────────────────────────
#  Helpers extracted from phase1.py logic (pure functions, no Flask required)
# ─────────────────────────────────────────────────────────────────────────────

EXPECTED_FAMILIES = {
    "Ramnit", "Lollipop", "Kelihos_ver3", "Vundo",
    "Tracur", "Kelihos_ver1", "Obfuscator.ACY", "Gatak", "Simda",
}

REQUIRED_FEATURE_COLS = [
    "Shannon_Entropy", "Null_Byte_Ratio", "ASCII_Byte_Ratio",
    "High_Byte_Ratio", "NOP_Ratio", "BytFSize", "Total_Bytes",
    "PCA1", "PCA2", "tSNE1", "tSNE2",
]


def compute_shannon_entropy(byte_freq_row: np.ndarray) -> float:
    """
    Pure implementation of Shannon entropy:  H = -Σ p(b) * log2(p(b))
    Mirrors the logic used during Phase 1 feature engineering.
    """
    total = byte_freq_row.sum()
    if total == 0:
        return 0.0
    probs = byte_freq_row / total
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def minmax_normalize(series: pd.Series) -> pd.Series:
    """Min-max normalisation as applied in Phase 1."""
    min_val, max_val = series.min(), series.max()
    return (series - min_val) / (max_val - min_val + 1e-9)


def compute_log_byte_fsize(series: pd.Series) -> pd.Series:
    """Log-transform applied to BytFSize in Phase 2 ETL (tested here for reuse)."""
    return np.log1p(series)


# ─────────────────────────────────────────────────────────────────────────────
#  Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestShannonEntropy:
    """Tests for the Shannon entropy computation."""

    def test_entropy_in_valid_range(self, mock_dataframe):
        """All Shannon_Entropy values must lie in the theoretical [0, 8] range."""
        col = mock_dataframe["Shannon_Entropy"]
        assert col.between(0.0, 8.0).all(), (
            f"Found entropy values outside [0, 8]: {col[~col.between(0.0, 8.0)].values}"
        )

    def test_entropy_not_all_zero(self, mock_dataframe):
        """Entropy column must not be a trivial constant-zero column."""
        assert mock_dataframe["Shannon_Entropy"].std() > 0, \
            "Shannon_Entropy has zero variance — likely a data error"

    def test_entropy_computation_uniform_dist(self):
        """Uniform byte distribution → max entropy ≈ 8 bits (256 bytes)."""
        uniform = np.ones(256)
        entropy = compute_shannon_entropy(uniform)
        assert abs(entropy - 8.0) < 0.01, f"Expected ~8.0, got {entropy}"

    def test_entropy_computation_single_byte(self):
        """Single non-zero byte → entropy = 0 (perfectly predictable)."""
        single = np.zeros(256)
        single[0] = 1000
        entropy = compute_shannon_entropy(single)
        assert entropy == 0.0, f"Expected 0.0, got {entropy}"

    def test_entropy_computation_empty_row(self):
        """All-zero row → entropy = 0 (no bytes, no information)."""
        empty = np.zeros(256)
        entropy = compute_shannon_entropy(empty)
        assert entropy == 0.0


class TestNormalization:
    """Tests for min-max normalisation applied in Phase 1."""

    def test_normalized_range_zero_to_one(self, mock_dataframe):
        """Normalized BytFSize must be in [0, 1]."""
        normalized = minmax_normalize(mock_dataframe["BytFSize"])
        assert normalized.min() >= 0.0, "Normalized min < 0"
        assert normalized.max() <= 1.0 + 1e-6, "Normalized max > 1"

    def test_normalized_values_not_all_same(self, mock_dataframe):
        """Normalization of a varied column must preserve variance."""
        normalized = minmax_normalize(mock_dataframe["Shannon_Entropy"])
        assert normalized.std() > 0, "Normalization produced a constant column"

    def test_normalization_preserves_order(self, mock_dataframe):
        """Normalization must be monotonically order-preserving."""
        raw = mock_dataframe["BytFSize"].values
        normalized = minmax_normalize(mock_dataframe["BytFSize"]).values
        # Ranks of original and normalized should be identical
        assert list(np.argsort(raw)) == list(np.argsort(normalized)), \
            "Min-max normalization changed relative ordering of values"

    def test_normalization_ratio_columns(self, mock_dataframe):
        """All ratio features (already in [0, 1]) must normalize within [0, 1]."""
        ratio_cols = ["Null_Byte_Ratio", "ASCII_Byte_Ratio",
                      "High_Byte_Ratio", "NOP_Ratio"]
        for col in ratio_cols:
            norm = minmax_normalize(mock_dataframe[col])
            assert norm.min() >= 0.0 and norm.max() <= 1.0 + 1e-6, \
                f"{col}: normalized values outside [0, 1]"


class TestClassDistribution:
    """Tests for malware class/family presence and completeness."""

    def test_all_nine_families_present(self, mock_dataframe):
        """All 9 malware families must appear in the dataset."""
        found = set(mock_dataframe["Family_Name"].unique())
        missing = EXPECTED_FAMILIES - found
        assert not missing, f"Missing families: {missing}"

    def test_class_ids_match_families(self, mock_dataframe):
        """Class integer IDs must be in range [1, 9]."""
        classes = mock_dataframe["Class"].unique()
        assert set(classes).issubset(set(range(1, 10))), \
            f"Unexpected class IDs: {set(classes) - set(range(1, 10))}"

    def test_no_unknown_families(self, mock_dataframe):
        """No Family_Name value should be outside the known 9 families."""
        unknown = set(mock_dataframe["Family_Name"].unique()) - EXPECTED_FAMILIES
        assert not unknown, f"Unknown family labels found: {unknown}"

    def test_family_distribution_balanced(self, mock_dataframe):
        """Each family should have at least 1 sample (no zero-count families)."""
        counts = mock_dataframe["Family_Name"].value_counts()
        assert (counts > 0).all(), "Some families have 0 samples"


class TestMissingValues:
    """Tests for data completeness — zero missing values policy."""

    def test_no_null_in_required_columns(self, mock_dataframe):
        """Required feature columns must have zero nulls."""
        cols_present = [c for c in REQUIRED_FEATURE_COLS if c in mock_dataframe.columns]
        null_counts = mock_dataframe[cols_present].isnull().sum()
        assert null_counts.sum() == 0, \
            f"Null values found:\n{null_counts[null_counts > 0]}"

    def test_no_null_in_id_column(self, mock_dataframe):
        """Id column (primary key) must never be null."""
        assert mock_dataframe["Id"].isnull().sum() == 0

    def test_no_duplicate_ids(self, mock_dataframe):
        """Sample IDs must be unique — no duplicate records."""
        assert mock_dataframe["Id"].duplicated().sum() == 0, \
            "Duplicate sample IDs detected"

    def test_no_infinite_values_in_numerics(self, mock_dataframe):
        """Numeric columns must not contain ±Inf values."""
        numeric_df = mock_dataframe.select_dtypes(include=[np.number])
        inf_mask = np.isinf(numeric_df.values)
        assert not inf_mask.any(), \
            "Infinite values found in numeric columns"


class TestFeatureEngineering:
    """Tests for engineered feature correctness."""

    def test_required_feature_columns_exist(self, mock_dataframe):
        """All required engineered feature columns must exist in the DataFrame."""
        for col in REQUIRED_FEATURE_COLS:
            assert col in mock_dataframe.columns, \
                f"Missing required feature column: '{col}'"

    def test_byte_frequency_cols_positive(self, mock_dataframe):
        """Byte-frequency values (hex cols) must be non-negative counts."""
        hex_cols = [c for c in mock_dataframe.columns
                    if len(c) == 2 and all(x in "0123456789abcdef" for x in c)]
        assert hex_cols, "No hex byte-frequency columns found"
        for col in hex_cols:
            assert (mock_dataframe[col] >= 0).all(), \
                f"Negative values in hex column '{col}'"

    def test_byte_frequency_cols_nonzero_variance(self, mock_dataframe):
        """Byte-frequency columns must not be constants (zero variance)."""
        hex_cols = [c for c in mock_dataframe.columns
                    if len(c) == 2 and all(x in "0123456789abcdef" for x in c)]
        zero_var = [c for c in hex_cols if mock_dataframe[c].std() == 0]
        assert not zero_var, \
            f"Zero-variance hex columns (constant): {zero_var}"

    def test_log_byte_fsize_transform(self, mock_dataframe):
        """log1p transform of BytFSize must produce finite, positive values."""
        log_col = compute_log_byte_fsize(mock_dataframe["BytFSize"])
        assert log_col.notna().all(), "log1p produced NaN values"
        assert (log_col >= 0).all(), "log1p produced negative values"
        assert np.isfinite(log_col).all(), "log1p produced Inf values"

    def test_pca_components_are_numeric(self, mock_dataframe):
        """PCA1 and PCA2 must be finite floating point values."""
        for col in ["PCA1", "PCA2"]:
            assert mock_dataframe[col].dtype in [np.float32, np.float64, float], \
                f"{col} is not float dtype"
            assert np.isfinite(mock_dataframe[col]).all(), \
                f"{col} contains non-finite values"
