from pathlib import Path
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, ConfusionMatrixDisplay, RocCurveDisplay, classification_report

DATA = Path('data/phishing.csv')
OUT = Path('figures'); OUT.mkdir(exist_ok=True)
if not DATA.exists():
    raise FileNotFoundError('Download Phishing_Legitimate_full.csv from Kaggle and save as data/phishing.csv (see README).')
df = pd.read_csv(DATA)
print('Raw rows, columns:', df.shape)
print('Missing cells:', int(df.isna().sum().sum()))
print('Duplicate rows excluding ID:', int(df.drop(columns=['id'],errors='ignore').duplicated().sum()))
print(df.head().to_string())
assert 'CLASS_LABEL' in df.columns, 'Unexpected dataset schema'
print('Class counts (1 = phishing, 0 = legitimate):\n', df.CLASS_LABEL.value_counts().sort_index())
# Remove exact duplicate observations (ignoring arbitrary ID) before splitting.
df = df.drop(columns=['id'], errors='ignore').drop_duplicates().copy()
y = df.pop('CLASS_LABEL').astype(int)
X = df.select_dtypes(include='number').copy()
print('Cleaned rows:', len(X), 'Features:', X.shape[1]);print('Excluded nonnumeric columns:', list(set(df.columns)-set(X.columns)))
print('Top missing features:\n',X.isna().sum().sort_values(ascending=False).head(10))
fig, ax=plt.subplots(figsize=(5,3.3));y.value_counts().sort_index().plot.bar(ax=ax);ax.set_xticklabels(['Legitimate (0)','Phishing (1)'],rotation=0);ax.set_title('Class distribution');ax.set_ylabel('Websites');fig.tight_layout();fig.savefig(OUT/'class_distribution.png',dpi=160);plt.close(fig)
fig,ax=plt.subplots(figsize=(7,5));cols=X.corr().abs().mean().sort_values(ascending=False).head(12).index;im=ax.imshow(X[cols].corr(),vmin=-1,vmax=1,cmap='coolwarm');ax.set_xticks(range(len(cols)),cols,rotation=90,fontsize=7);ax.set_yticks(range(len(cols)),cols,fontsize=7);fig.colorbar(im,ax=ax);fig.tight_layout();fig.savefig(OUT/'correlation.png',dpi=160);plt.close(fig)
print('Selected feature summary:\n',X[['UrlLength','NumDots','SubdomainLevel']].describe().to_string())
X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=.20,random_state=42,stratify=y)
models={
 'Logistic Regression':Pipeline([('imputer',SimpleImputer(strategy='median')),('scale',StandardScaler()),('model',LogisticRegression(max_iter=1500,random_state=42))]),
 'Random Forest':Pipeline([('imputer',SimpleImputer(strategy='median')),('model',RandomForestClassifier(n_estimators=200,random_state=42,n_jobs=-1,min_samples_leaf=2))])}
rows=[]
for name,model in models.items():
 model.fit(X_train,y_train)
 pred=model.predict(X_test); prob=model.predict_proba(X_test)[:,1]
 cm=confusion_matrix(y_test,pred,labels=[0,1]);tn,fp,fn,tp=cm.ravel()
 result={'model':name,'accuracy':accuracy_score(y_test,pred),'precision':precision_score(y_test,pred,zero_division=0),'recall':recall_score(y_test,pred,zero_division=0),'f1':f1_score(y_test,pred,zero_division=0),'roc_auc':roc_auc_score(y_test,prob),'false_positives':int(fp),'false_negatives':int(fn),'fpr':float(fp/(fp+tn)),'fnr':float(fn/(fn+tp))}
 rows.append(result)
 print('\n',name,'\n',classification_report(y_test,pred,target_names=['Legitimate','Phishing']))
 fig,ax=plt.subplots(figsize=(5,4));ConfusionMatrixDisplay(cm,display_labels=['Legitimate','Phishing']).plot(ax=ax,colorbar=False);ax.set_title(name);fig.tight_layout();fig.savefig(OUT/(name.lower().replace(' ','_')+'_confusion.png'),dpi=160);plt.close(fig)
 fig,ax=plt.subplots(figsize=(5,4));RocCurveDisplay.from_predictions(y_test,prob,ax=ax);ax.set_title(name+' ROC');fig.tight_layout();fig.savefig(OUT/(name.lower().replace(' ','_')+'_roc.png'),dpi=160);plt.close(fig)
 if name=='Random Forest':
  importances=pd.Series(model.named_steps['model'].feature_importances_,index=X.columns).sort_values(ascending=False).head(12)
  print('Top features:\n',importances.to_string());fig,ax=plt.subplots(figsize=(7,4));importances.sort_values().plot.barh(ax=ax);ax.set_title('Random Forest feature importance');fig.tight_layout();fig.savefig(OUT/'feature_importance.png',dpi=160);plt.close(fig)
metrics=pd.DataFrame(rows);metrics.to_csv(OUT/'metrics.csv',index=False)
print('\nMODEL COMPARISON\n',metrics.to_string(index=False))
print('Files saved in figures/')
