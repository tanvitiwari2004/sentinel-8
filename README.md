---
title: Sentinel-8
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: streamlit
app_file: app.py
pinned: false
---

# 🛡️ Sentinel-8

### AI-Based Cybersecurity Threat Detection System

> Aligned with Australia's Essential Eight Framework (ACSC)



!\[Python](https://img.shields.io/badge/Python-3.11-blue)

!\[XGBoost](https://img.shields.io/badge/Model-XGBoost-orange)

!\[Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red)

!\[Accuracy](https://img.shields.io/badge/Accuracy-99.29%25-brightgreen)



---



## Overview

Sentinel-8 is a two-stage machine learning pipeline that analyses network logs, detects cybersecurity threats, and maps every finding to the Australian Government's Essential Eight controls — automatically.



## Live Demo

🔗 \[sentinel-8 on Hugging Face](https://huggingface.co/spaces/tanvitiwari2004/sentinel-8)



## Architecture

!\[Architecture](reports/architecture.png)



## Results

|      Model       | Metric  | Score |

|------------------|---------|-------|

| Isolation Forest | ROC-AUC | 0.9467 |

| XGBoost Classifier | Accuracy | 99.29% |

| XGBoost Classifier | Attack F1 | 0.97 |

| Pipeline Speed | Records/sec | 91,342 |



## Pipeline

```

Raw Logs → Preprocessing → Anomaly Detection → Threat Classification → E8 Mapper → LLM Report → Dashboard

```



## Essential Eight Controls Monitored

\- #1 Application Control

\- #2 Patch Applications

\- #5 Restrict Admin Privileges

\- #7 Multi-Factor Authentication



## Tech Stack

\- **ML:** Isolation Forest, XGBoost, SHAP

\- **LLM:** Groq API (Llama 3.1)

\- **Dashboard:** Streamlit + Plotly

\- **Data:** UNSW-NB15, CICIDS2017



## Setup

```bash

git clone https://github.com/tanvitiwari2004/sentinel-8.git

cd sentinel-8

python -m venv venv

venv\\Scripts\\activate

pip install -r requirements.txt

cd dashboard

streamlit run app.py

```



## Project Structure

```

sentinel-8/

├── data/

│   ├── raw/          # Downloaded datasets

│   └── processed/    # Cleaned train/test splits

├── models/           # Saved ML models

├── notebooks/        # EDA and modelling notebooks

├── dashboard/        # Streamlit app

│   ├── app.py

│   ├── compliance\_mapper.py

│   └── llm\_reporter.py

└── reports/          # SHAP plots, EDA charts, architecture diagram

```



## Dataset

\- **UNSW-NB15** — 2.5M records, UNSW Sydney (Australian origin)

\- **CICIDS2017** — 2.8M records, Canadian Institute for Cybersecurity



## Limitations

Model trained on UNSW-NB15 features. Direct generalisation to CICIDS2017 is limited due to dataset shift — different feature extraction methods between datasets. A production system would require retraining on target dataset features.



## Authors

Tanvi Tiwari, Lavanya Singh, Angel Bhandari

Final Year Data Science Capstone — 2026

