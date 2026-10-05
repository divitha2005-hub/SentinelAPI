# SentinelAPI — Data Preprocessing, EDA & Visualisation

**Vellore Institute of Technology — Software Metrics**

| Register Number | Student Name |
|:---|:---|
| 23mis0166 | Gondu Divitha |
| 23mis0158 | Devarla Sowmya Rai |
| 23mis0185 | K Meghana |
| 23mis0057 | Thatavarthi V S S M M Nagasri Kavya |

---

## What this folder contains

```
visualization/
├── SentinelAPI_Data_Analysis.ipynb   <-- MAIN DELIVERABLE (open this first)
├── README.md                          this file
│
├── data/
│   ├── cleaned_api_endpoints.zip         <-- SHARE THIS ONE with the team
│   ├── cleaned_api_endpoints.csv.gz      same data, gzipped (the notebook reads this)
│   ├── raw_api_endpoints.csv.gz          154,145 rows — before preprocessing
│   └── model_ready_api_endpoints.csv.gz  encoded + scaled, ready for ML
│
├── figures/                           34 exported charts (PNG, 150 dpi)
│   ├── 01_missing_values.png          ... 34_diverging_bar.png
│                                       (15_summary_dashboard.png is the one-page overview)
│
└── scripts/
    └── build_dataset.py               the parser that created the raw dataset
```

**Start with `SentinelAPI_Data_Analysis.ipynb`.** Every cell is already executed, so all
tables and charts are visible without running anything.

### The dataset to share with the team

**`data/cleaned_api_endpoints.zip`** — this is the final dataset that all the
preprocessing, EDA and visualisation in the notebook was performed on.

- **103,379 rows x 48 columns** — one row per unique API endpoint
- Missing values handled, duplicates removed, outliers capped, 9 features engineered,
  `FUZZ_RISK` target added
- Zipped it is ~1.5 MB; unzipped it is a normal 25 MB CSV that opens in Excel, pandas, R
  or anything else

```python
import pandas as pd
df = pd.read_csv("cleaned_api_endpoints.csv")     # after unzipping
df = pd.read_csv("cleaned_api_endpoints.csv.gz")  # or read the gzip directly
```

The other data files are the raw extract (before preprocessing) and a fully encoded,
Min-Max-scaled version for anyone who wants to train a model without redoing the prep.

---

## The project

**SentinelAPI** is an automated quality-assurance and security-fuzzing framework for REST
APIs. It reads an API's OpenAPI/Swagger specification, generates hostile and edge-case
inputs using boundary-value heuristics plus LLM prompting, fires them concurrently at the
live API, and reports schema violations, business-logic bypasses and security flaws
(SQL Injection, XSS, Path Traversal).

## The dataset — and why it fits

The first thing SentinelAPI reads is an **OpenAPI specification**. So the dataset used
here is the **APIs.guru OpenAPI Directory** — an open collection of machine-readable
specifications for real, publicly deployed APIs (Stripe, Slack, GitHub, Azure, Twilio and
hundreds more). It is exactly the input format the tool consumes.

The directory is a repository of 4,138 YAML files, not a table. `scripts/build_dataset.py`
was written to flatten it into an endpoint-level dataset:

```
4,138 OpenAPI specifications  ->  154,145 endpoint records  ->  36 measured features
```

One row = one API endpoint (one URL path + one HTTP method, e.g. `POST /v1/customers`).

**Source:** https://github.com/APIs-guru/openapi-directory (open source, CC0)

---

## What was done

### 1. Data Preprocessing
- Missing-value detection, visualisation and imputation (no rows dropped)
- Duplicate removal on provider + path + method
- Outlier detection using the IQR rule, treated by **capping**, not deletion
- 9 engineered ratio features (validation coverage, unvalidated ratio, etc.)
- Construction of the `FUZZ_RISK` target variable — a weighted, documented risk index
- Ordinal encoding (risk levels) and one-hot encoding (HTTP method, spec version)
- Min-Max normalisation of 19 numeric features

### 2. Exploratory Data Analysis
Descriptive statistics, univariate and bivariate analysis, cross-tabulation, group
profiling by risk band, correlation analysis, and provider-level ranking.

### 3. Correlation Analysis (Section 6)
Full Pearson matrix across all 37 numeric features, Pearson vs Spearman comparison with a
difference map, features ranked by correlation with the target, a hierarchically clustered
correlation map, a VIF multicollinearity check, and a pair plot.

### 4. Visualisation (Section 7)
**34 figures in total**, covering the full range of chart types:

| Purpose | Charts |
|:--|:--|
| Distribution | histogram, KDE, violin, boxen, box, ECDF, ridge |
| Category comparison | bar, horizontal bar, grouped bar, stacked bar, 100% stacked, count, lollipop, Pareto, diverging bar, donut, pie, treemap |
| Relationship | scatter, hexbin, joint plot, bubble, regression with confidence band, dual-axis |
| Composition | stacked area, 100% stacked bar |
| Matrix | correlation heatmap, clustermap, pivot heatmap, missing-value map |
| Multivariate | radar chart, parallel coordinates, pair plot, facet grid |
| Summary | composite dashboard |

---

## Main findings

| Finding | Figure |
|:---|:---|
| **78% of all API parameters carry no validation rule at all** | `09_validation_coverage.png` |
| **51% of endpoints have zero validated parameters** | `09_validation_coverage.png` |
| Mean validation coverage per endpoint is only **21%** | `15_summary_dashboard.png` |
| A large share of endpoints declare **no 4xx error response** | `10_auth_and_errors.png` |
| Around **20% of endpoints change data without requiring authentication** | `10_auth_and_errors.png` |
| **41% of endpoints fall in the High fuzz-risk band** | `04_target_variable.png` |

**Why this matters for the project:** an unvalidated string parameter will accept an SQL
injection or XSS payload exactly as readily as legitimate input. The scale of the problem
found here — hundreds of thousands of unvalidated parameters across 685 real API
providers — is the direct justification for building an automated fuzzer instead of
testing by hand.

The `fuzz_risk_score` produced in the notebook is directly usable as SentinelAPI's
**scheduling metric**: it turns "test everything" into "test these endpoints first".

---

## Honest limitations

- `FUZZ_RISK` is a **rule-based index derived from the specification itself**, not an
  observed test outcome. It ranks endpoints by priority; it does not confirm
  vulnerabilities. Relationships between the score and its own input features are
  expected by construction.
- A specification describes *intent*. An API may validate input in code without declaring
  it in the spec. This analysis measures **contract quality** — which is what SentinelAPI
  actually parses — not runtime behaviour.
- APIs.guru is skewed toward large, well-documented public APIs. Private and internal APIs
  are likely documented worse, so these figures are probably optimistic.

---

## Running it yourself

```bash
pip install pandas numpy matplotlib seaborn squarify jupyter
jupyter notebook SentinelAPI_Data_Analysis.ipynb
```

One extra package is used, for the treemap:

```bash
pip install squarify
```

Run all cells. The notebook regenerates every cleaned dataset and every file in `figures/`
from `data/raw_api_endpoints.csv.gz`.

To rebuild the raw dataset from scratch:

```bash
git clone --depth 1 https://github.com/APIs-guru/openapi-directory.git
python scripts/build_dataset.py
```
