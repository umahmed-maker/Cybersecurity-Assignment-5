from pathlib import Path
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'data'
OUT = ROOT / 'results'
OUT.mkdir(exist_ok=True)
files = list(DATA.glob('*.csv'))
if not files:
    raise SystemExit('Put Wednesday-workingHours.pcap_ISCX.csv and Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv in the data folder, then rerun.')
frames = []
for file in files:
    df = pd.read_csv(file, low_memory=False)
    df.columns = df.columns.str.strip()
    if 'Label' not in df.columns:
        print('Skipping', file.name, '(missing Label)')
        continue
    df['Label'] = df['Label'].astype(str).str.strip()
    df = df[df['Label'].eq('BENIGN') | df['Label'].str.startswith('DoS ') | df['Label'].eq('DDoS')].copy()
    df['source_file'] = file.name
    frames.append(df)
if not frames:
    raise SystemExit('No BENIGN, DoS, or DDoS records found.')
df = pd.concat(frames, ignore_index=True)
df = df.drop_duplicates()
df['Traffic Class'] = np.where(df['Label'].eq('BENIGN'), 'Normal', np.where(df['Label'].eq('DDoS'), 'DDoS', 'DoS'))
features = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Flow Bytes/s', 'Flow Packets/s', 'Packet Length Mean', 'SYN Flag Count', 'ACK Flag Count']
features = [x for x in features if x in df.columns]
if len(features) < 3:
    raise SystemExit('Not enough expected numeric features in CSV.')
for feature in features:
    df[feature] = pd.to_numeric(df[feature], errors='coerce').replace([np.inf, -np.inf], np.nan)
# Impute only after splitting to avoid leaking test-set statistics.
counts = df['Traffic Class'].value_counts().reindex(['Normal','DoS','DDoS'], fill_value=0)
counts.to_csv(OUT/'class_counts.csv', header=['flows'])
fig, ax = plt.subplots(figsize=(7,4)); counts.plot.bar(ax=ax); ax.set_ylabel('Network flow records'); ax.set_title('Normal vs DoS vs DDoS'); fig.tight_layout(); fig.savefig(OUT/'traffic_distribution.png', dpi=160); plt.close(fig)
for feature, filename in [('Flow Packets/s','packets_per_second.png'), ('Flow Bytes/s','bytes_per_second.png')]:
    if feature in features:
        fig, ax = plt.subplots(figsize=(7,4))
        groups = [df.loc[df['Traffic Class'].eq(c), feature].dropna().clip(lower=0) for c in ['Normal','DoS','DDoS']]
        ax.boxplot([np.log1p(g.to_numpy()) for g in groups], tick_labels=['Normal','DoS','DDoS'], showfliers=False)
        ax.set_ylabel('log(1 + value)'); ax.set_title(feature + ' by traffic class')
        fig.tight_layout(); fig.savefig(OUT/filename, dpi=160); plt.close(fig)
summary = df.groupby('Traffic Class')[features].median().round(3)
summary.to_csv(OUT/'median_features.csv')
X = df[features]; y = df['Traffic Class']
if y.nunique() < 2 or y.value_counts().min() < 2:
    raise SystemExit('Need at least two classes with at least two rows each for model training.')
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=.2, random_state=42, stratify=y)
medians = X_train.median().fillna(0)
X_train = X_train.fillna(medians); X_test = X_test.fillna(medians)
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced_subsample', max_depth=16)
model.fit(X_train, y_train)
pred = model.predict(X_test)
labels = [c for c in ['Normal','DoS','DDoS'] if c in y.unique()]
report = classification_report(y_test, pred, labels=labels, output_dict=True, zero_division=0)
(OUT/'classification_report.json').write_text(json.dumps(report, indent=2))
pd.DataFrame(report).transpose().to_csv(OUT/'classification_report.csv')
fig, ax = plt.subplots(figsize=(6,5)); ConfusionMatrixDisplay(confusion_matrix(y_test,pred,labels=labels),display_labels=labels).plot(ax=ax, cmap='Blues', values_format='d', colorbar=False); fig.tight_layout(); fig.savefig(OUT/'confusion_matrix.png',dpi=160); plt.close(fig)
importance = pd.Series(model.feature_importances_, index=features).sort_values(ascending=True)
fig, ax = plt.subplots(figsize=(8,5)); importance.plot.barh(ax=ax); ax.set_title('Random Forest feature importance'); fig.tight_layout(); fig.savefig(OUT/'feature_importance.png',dpi=160); plt.close(fig)
summary_text = {'records_after_deduplication':len(df), 'class_counts':counts.to_dict(), 'features':features, 'test_records':len(y_test), 'accuracy':report['accuracy'], 'macro_f1':report['macro avg']['f1-score'], 'caveat':'Random flow split from a historical dataset; performance may not generalize to new networks or attack campaigns.'}
(OUT/'summary.json').write_text(json.dumps(summary_text,indent=2))
print(json.dumps(summary_text,indent=2))
print('Saved results in',OUT)
