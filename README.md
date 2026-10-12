# Assignment 5 — SQL Injection and Phishing Detection

Dataset: https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning

The original uploaded CSV is included as `data/phishing.csv`. Dataset contains 10,000 rows, 48 features, and target `CLASS_LABEL`.

## Run
1. Install Python 3.10+ and run `pip install -r requirements.txt`.
2. Run `python analysis.py` or open `02_Phishing_Analysis.ipynb` and run its code cell.
3. Outputs are saved in `figures/` including `metrics.csv`, class chart, correlation chart, ROC curves, confusion matrices, and feature importance.
4. Run `python 05_SQL_Injection_Lab.py` for the separate controlled local SQLite example.

## Verified experiment
Cleaned rows: 9,581 after removing 419 duplicates ignoring ID; no missing values. 80/20 stratified split with random_state=42. Logistic Regression accuracy: 95.20%; Random Forest accuracy: 98.38%. These are results from the supplied CSV, not fabricated estimates.

## Included deliverables
Proposal, notebook, analysis script, final report, presentation, SQL injection lab and explanation, dataset, figures, requirements, and this README. Cite Kaggle and document your own verification and interpretation.
