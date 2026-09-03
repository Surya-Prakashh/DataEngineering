"""
Malware Analysis Dashboard — Centralized Dynamic Dataset Manager
Handles live dataset mutation, CSV upload, and mock row injection (+50 rows).
"""

import os
import pandas as pd
import numpy as np
import hashlib
import random
import time
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.preprocessing import StandardScaler

BASE_DIR = os.path.dirname(__file__)
ORIGINAL_CSV = os.path.join(BASE_DIR, "train_processed.csv")
ACTIVE_CSV   = os.path.join(BASE_DIR, "active_dataset.csv")

# Global DataFrame cache
_active_df   = None
_col_schema  = None          # column schema read from original CSV once

# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────
def _get_schema():
    """Return column list + HEX_COLS from original CSV (read once)."""
    global _col_schema
    if _col_schema is None:
        df_orig = pd.read_csv(ORIGINAL_CSV, nrows=2)
        hex_cols = [c for c in df_orig.columns if len(c)==2 and all(x in "0123456789abcdef" for x in c)]
        _col_schema = {"columns": list(df_orig.columns), "hex_cols": hex_cols}
    return _col_schema


def _recompute_pca_tsne(df: pd.DataFrame) -> pd.DataFrame:
    """Re-run PCA & t-SNE on the full dataframe so all rows have PCA1/PCA2/tSNE1/tSNE2."""
    schema   = _get_schema()
    hex_cols = schema["hex_cols"]
    avail    = [c for c in hex_cols if c in df.columns]
    if not avail:
        return df

    X = df[avail].fillna(0).values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    # PCA
    pca = PCA(n_components=2, random_state=42)
    pca_coords = pca.fit_transform(Xs)
    df = df.copy()
    df["PCA1"] = np.round(pca_coords[:, 0], 4)
    df["PCA2"] = np.round(pca_coords[:, 1], 4)

    # t-SNE (cap at 3000 rows to keep it fast)
    n = min(len(df), 3000)
    idx = df.index[:n]
    perp = min(30, n - 1)
    tsne = TSNE(n_components=2, perplexity=perp, random_state=42, n_iter=300)
    tsne_coords = tsne.fit_transform(Xs[:n])
    df.loc[idx, "tSNE1"] = np.round(tsne_coords[:, 0], 4)
    df.loc[idx, "tSNE2"] = np.round(tsne_coords[:, 1], 4)
    # rows beyond cap: copy PCA coords as fallback
    if n < len(df):
        df.loc[df.index[n:], "tSNE1"] = df.loc[df.index[n:], "PCA1"]
        df.loc[df.index[n:], "tSNE2"] = df.loc[df.index[n:], "PCA2"]

    return df


# ──────────────────────────────────────────────
#  Core init / get
# ──────────────────────────────────────────────
def init_active_dataset():
    global _active_df
    if not os.path.exists(ACTIVE_CSV):
        df_orig = pd.read_csv(ORIGINAL_CSV)
        df_orig.to_csv(ACTIVE_CSV, index=False)
        _active_df = df_orig
    else:
        _active_df = pd.read_csv(ACTIVE_CSV)
    return _active_df


def get_dataset() -> pd.DataFrame:
    global _active_df
    if _active_df is None:
        return init_active_dataset()
    return _active_df


# ──────────────────────────────────────────────
#  Mock data injection
# ──────────────────────────────────────────────
FAMILIES = ["Ramnit", "Lollipop", "Kelihos_ver3", "Vundo",
            "Tracur", "Kelihos_ver1", "Obfuscator.ACY", "Gatak", "Simda"]

FAMILY_CLASS = {f: i+1 for i, f in enumerate(FAMILIES)}

def add_mock_data_rows(count: int = 50):
    """Generates and appends N mock malware sample rows to the active dataset."""
    global _active_df
    df_curr  = get_dataset()
    schema   = _get_schema()
    hex_cols = schema["hex_cols"]

    # Use a real row as a template so every column exists
    template = df_curr.iloc[0].to_dict()

    mock_rows = []
    for i in range(count):
        row = template.copy()
        fam = random.choice(FAMILIES)

        uid = hashlib.sha256(
            f"MOCK_{time.time()}_{i}_{random.randint(0,999999)}".encode()
        ).hexdigest()[:20]

        size_bytes = random.randint(150_000, 12_000_000)
        entropy    = round(random.uniform(5.2, 7.95), 6)

        # Identity / label columns — use EXACT column names from real CSV
        row["Id"]               = uid
        row["Class"]            = FAMILY_CLASS[fam]
        row["Family_Name"]      = fam          # ← was wrongly "Class_Name" before

        # Numeric feature columns
        row["BytFSize"]         = size_bytes
        row["Total_Bytes"]      = size_bytes
        row["Shannon_Entropy"]  = entropy
        row["Null_Byte_Ratio"]  = round(random.uniform(0.01, 0.40), 6)
        row["ASCII_Byte_Ratio"] = round(random.uniform(0.30, 0.80), 6)
        row["High_Byte_Ratio"]  = round(random.uniform(0.01, 0.30), 6)

        # NOP column — original CSV uses "NOP_Ratio"
        nop_val = round(random.uniform(0.0001, 0.05), 6)
        if "NOP_Ratio" in template:
            row["NOP_Ratio"] = nop_val
        if "NOP_Instruction_Ratio" in template:
            row["NOP_Instruction_Ratio"] = nop_val

        # Randomise hex byte frequencies around realistic values
        base_dist = df_curr[hex_cols].mean() if hex_cols else []
        for h in hex_cols:
            row[h] = max(0, round(float(base_dist[h]) + random.gauss(0, 0.5), 2))

        # PCA / tSNE placeholders — will be recomputed below
        row["PCA1"]  = round(random.uniform(-5, 5), 4)
        row["PCA2"]  = round(random.uniform(-5, 5), 4)
        row["tSNE1"] = round(random.uniform(-20, 20), 4)
        row["tSNE2"] = round(random.uniform(-20, 20), 4)

        mock_rows.append(row)

    df_new   = pd.DataFrame(mock_rows, columns=df_curr.columns)
    _active_df = pd.concat([df_curr, df_new], ignore_index=True)

    # Recompute PCA/t-SNE so EDA scatter charts show sensible projections
    try:
        _active_df = _recompute_pca_tsne(_active_df)
    except Exception as e:
        print(f"[dataset_manager] PCA/tSNE recompute skipped: {e}")

    _active_df.to_csv(ACTIVE_CSV, index=False)
    return len(_active_df), count


# ──────────────────────────────────────────────
#  CSV upload
# ──────────────────────────────────────────────
def upload_custom_csv(file_storage):
    """Processes uploaded CSV file and merges with active dataset."""
    global _active_df
    try:
        df_uploaded = pd.read_csv(file_storage)
        df_curr     = get_dataset()

        # If uploaded CSV has same structure — concat
        _active_df = pd.concat([df_curr, df_uploaded], ignore_index=True)

        # Try recomputing PCA/tSNE
        try:
            _active_df = _recompute_pca_tsne(_active_df)
        except Exception as e:
            print(f"[dataset_manager] PCA/tSNE recompute skipped after upload: {e}")

        _active_df.to_csv(ACTIVE_CSV, index=False)
        return True, len(_active_df)
    except Exception as e:
        return False, str(e)


# ──────────────────────────────────────────────
#  Reset
# ──────────────────────────────────────────────
def reset_dataset_to_baseline():
    """Resets dataset back to original baseline rows."""
    global _active_df
    df_orig    = pd.read_csv(ORIGINAL_CSV)
    df_orig.to_csv(ACTIVE_CSV, index=False)
    _active_df = df_orig
    return len(_active_df)


# Initialize on module load
init_active_dataset()
