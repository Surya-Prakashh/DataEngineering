# Git Branching Strategy for Data Engineering Teams
## MalwareScope Project — Version Control Playbook

---

## 📌 Overview

This document defines the official Git branching strategy for the MalwareScope data engineering project. It is adapted from **Git Flow** and tuned specifically for data pipeline development, where code changes often involve both application logic and data transformation logic.

---

## 🌳 Branch Hierarchy

```
main
 └── develop
      ├── feature/phase1-ingestion
      ├── feature/phase2-etl-cdc
      ├── feature/phase3-olap-warehouse
      ├── feature/phase4-kafka-staging
      ├── hotfix/fix-entropy-dq-bounds
      └── release/v1.2.0
```

---

## 🔱 Branch Definitions

### `main` — Production Branch
- **Purpose**: Always contains the **production-ready, tested** version of the pipeline.
- **Rules**:
  - 🔒 **Protected** — no direct commits allowed.
  - All merges via **Pull Request** only, requiring ≥1 reviewer approval.
  - CI/CD must pass 100% before merge.
  - Every merge creates a **tagged release** (e.g., `v1.0.0`).

### `develop` — Integration Branch
- **Purpose**: The living integration branch where all completed features land.
- **Rules**:
  - Merges from `feature/*` branches via Pull Request.
  - CI runs on every push.
  - Should always be in a **deployable state**.

### `feature/<phase>-<description>` — Feature Branches
- **Purpose**: Isolated development of a specific pipeline phase or capability.
- **Naming Convention**:
  ```
  feature/phase1-shannon-entropy-fix
  feature/phase2-cdc-lsn-refactor
  feature/phase3-dim-time-partitioning
  feature/phase4-dlq-retry-logic
  feature/cicd-github-actions-setup
  ```
- **Lifecycle**:
  1. Branch from `develop`
  2. Develop + write unit tests
  3. Open PR → `develop`
  4. Reviewer approves → Squash merge
  5. Delete branch after merge

### `hotfix/<description>` — Emergency Patches
- **Purpose**: Critical production bug fixes that cannot wait for a sprint cycle.
- **Rules**:
  - Branch directly from `main`.
  - Must include a regression test for the bug.
  - Merged into **both** `main` AND `develop`.
  - Triggers an immediate patch release (e.g., `v1.0.1`).
- **Example**: `hotfix/fix-negative-file-size-dq`

### `release/<version>` — Release Candidates
- **Purpose**: Stabilization and QA before production deployment.
- **Rules**:
  - Branch from `develop` when sprint is feature-complete.
  - Only **bug fixes** and **documentation** allowed here (no new features).
  - Merged into `main` (tagged) AND back into `develop`.
- **Example**: `release/v1.2.0`

---

## 📝 Commit Message Convention

We follow the **Conventional Commits** specification:

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

### Types
| Type | When to Use |
|------|------------|
| `feat` | New pipeline feature or endpoint |
| `fix` | Bug fix in transformation or DQ logic |
| `test` | Adding or fixing tests |
| `refactor` | Code restructure without behavior change |
| `docs` | Documentation updates |
| `ci` | Changes to GitHub Actions workflows |
| `chore` | Dependency updates, config changes |
| `perf` | Performance improvements |

### Examples
```bash
feat(phase2): add LSN monotonic validation to CDC pipeline
fix(phase4): clamp file_size_bytes to reject zero-byte records
test(phase1): add normalization min-max boundary tests
ci: add coverage gate of 70% to GitHub Actions workflow
docs: update GIT_BRANCHING_STRATEGY with hotfix procedure
```

---

## 🔄 Workflow — Day-to-Day

### Starting a Feature
```bash
git checkout develop
git pull origin develop
git checkout -b feature/phase2-log-transform-validation
```

### During Development
```bash
# After making changes
git add .
git commit -m "feat(phase2): add log-transform unit test for BytFSize column"

# Push and open PR
git push origin feature/phase2-log-transform-validation
```

### Finishing a Feature
1. Open Pull Request → `develop`
2. CI must pass (lint + unit tests + coverage)
3. At least 1 team reviewer approves
4. **Squash merge** to keep `develop` history clean
5. Delete feature branch

### Emergency Hotfix
```bash
git checkout main
git pull origin main
git checkout -b hotfix/fix-entropy-out-of-range
# ... make fix + add regression test ...
git commit -m "fix(phase4): reject entropy > 8.0 before staging upsert"
git push origin hotfix/fix-entropy-out-of-range
# PR → main, then cherry-pick or merge → develop
```

---

## 🏷️ Release Tagging

```bash
# After merging release branch to main
git checkout main
git pull origin main
git tag -a v1.0.0 -m "Release v1.0.0: Initial pipeline with Phases 1-4"
git push origin v1.0.0
```

---

## ✅ Branch Protection Rules (GitHub Settings)

| Branch | Required Reviews | Required CI | Allow Direct Push |
|--------|-----------------|-------------|-------------------|
| `main` | 1 | ✅ All checks pass | ❌ No |
| `develop` | 0 | ✅ Lint + unit tests | ❌ No |
| `feature/*` | 0 | ❌ Optional | ✅ Yes |
| `hotfix/*` | 1 | ✅ All checks pass | ❌ No |

---

## 📁 Data-Specific Conventions

Unlike pure software projects, data engineering pipelines have extra considerations:

1. **Never commit large files**: CSV datasets, trained models, and SQLite DBs are in `.gitignore`. Use DVC or cloud storage for large datasets.
2. **Schema changes need migration notes**: Any change to OLTP/OLAP table schema must include a `MIGRATION.md` note in the PR.
3. **Transformation changes need tests**: Every change to a transformation function (`phase1.py` – `phase4.py`) must be accompanied by a unit test update.
4. **Config changes go through PR**: Changes to `configs/pipeline_config.yaml` and environment configs require review.
5. **CI gates data quality**: The CI pipeline includes DQ validation checks — a pipeline that fails DQ is treated the same as a failing test.
