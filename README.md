# Assignment 7 — DoS/DDoS Attacks and Website Availability

## What this package contains
- `analysis.py`: runs actual CSV analysis and a Random Forest classifier.
- `assignment7.html`: a standalone page to add to your EXISTING GitHub Pages repository.
- `requirements.txt`: Python packages.
- `data/`: place source CSV files here (not included).
- `results/`: created by running the analysis.

## 1. Download data
Download these two CIC-IDS2017 CSV files from https://huggingface.co/datasets/c01dsnap/CIC-IDS2017 (or the official source https://www.unb.ca/cic/datasets/ids-2017.html):
- `Wednesday-workingHours.pcap_ISCX.csv`
- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
Put both files inside `data/`.

## 2. Run analysis
From the Assignment7_Project folder:
```
python -m pip install -r requirements.txt
python analysis.py
```
This creates `results/*.png`, `results/*.csv` and `results/*.json` from REAL dataset values.

## 3. Update research findings
Open `results/summary.json`, `results/classification_report.csv` and `results/median_features.csv`. Replace the "Results pending execution" paragraph in `assignment7.html` with the measured values and explain false positives / missed attacks. Check the chart interpretations against actual plots.

## 4. Create Google Flow video
Use https://labs.google/fx/tools/flow to create an educational movie about website availability and attack detection. Download the video and name it `assignment7-movie.mp4` (MP4 format), place it next to `assignment7.html`. No video is included yet.

## 5. Add to EXISTING GitHub Pages website
In your current GitHub Pages repository, upload `assignment7.html`, the `results/` folder, and `assignment7-movie.mp4` to the same directory as `index.html`. Add this link to the existing homepage:
```
<a href="assignment7.html">Assignment 7 — DoS/DDoS Detection</a>
```
Commit changes. Visit your existing GitHub Pages URL followed by `/assignment7.html`. Check charts and play the movie before submitting the website URL.

## Limitations
- Random stratified splitting is a baseline and may overestimate deployment performance due to related network flows in both sets.
- Class distribution is flow counts, NOT actual HTTP requests per second or downtime.
- The analysis is entirely offline; do not generate attack traffic.
