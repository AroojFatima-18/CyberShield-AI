# CyberShield AI
## Intelligent Cybercrime Detection and Investigation System

**University-level AI project** combining ML classification, NLP analysis,
graph-based search algorithms, and a professional Streamlit dashboard.

---

## Project Structure

```
cybershield_ai/
├── app.py                        # Main Streamlit application
├── requirements.txt
├── modules/
│   ├── ml_pipeline.py            # TF-IDF + Ensemble ML, training, prediction
│   ├── search_algorithms.py      # BFS, DFS, A* on investigation graph
│   ├── nlp_analyzer.py           # Threat lexicon, entity extraction, highlighting
│   └── visualizer.py             # Plotly/Matplotlib charts and graph renderer
├── data/
│   └── dataset_builder.py        # Synthetic dataset generator (feature-pattern based)
├── database/
│   └── db_manager.py             # SQLite: complaints, threat logs, investigation logs
├── models/                       # Trained model artifacts (auto-generated)
└── utils/
```

---

## Setup Instructions

### 1. Install dependencies
```bash
cd cybershield_ai
pip install -r requirements.txt
```

### 2. Run the application
```bash
streamlit run app.py
```

---

## How to Use

### Step 1 — Train the ML Model
1. Navigate to **ML Pipeline** in the sidebar
2. Set samples per class (40 recommended)
3. Click **Build Dataset & Train Model**
4. Review confusion matrix, F1 scores, and cross-validation results

### Step 2 — Analyze a Threat
1. Navigate to **Threat Analyzer**
2. Paste any suspicious message, email content, or URL
3. Click **Analyze Threat**
4. Review: classification label, confidence, threat score gauge,
   flagged keywords, probability radar, extracted entities

### Step 3 — Run Graph Investigation
1. Navigate to **Investigation Graph**
2. Select a source node (suspect) and target node (victim)
3. Click **Run All Search Algorithms**
4. Compare BFS / DFS / A* paths and visualize the attack network

### Step 4 — Review Records
- **Case Records**: all logged complaints, threat alerts, investigation runs
- **Analytics**: threat score distribution, urgency breakdown, source channels

---

## AI Concepts Explained

### Machine Learning Pipeline
- **TF-IDF Vectorization**: converts raw text into numerical feature vectors
  using term frequency-inverse document frequency with bigram support.
  Sublinear TF scaling reduces the dominance of high-frequency terms.
- **Ensemble Classifier**: combines Random Forest (120 decision trees with
  bootstrap aggregation) and Logistic Regression (multinomial softmax) via
  soft voting — averaging predicted class probabilities.
- **Evaluation**: 5-fold stratified cross-validation, per-class F1 score,
  confusion matrix, weighted macro-average metrics.

### NLP Threat Analysis
- **Threat Lexicon**: 6 semantic categories weighted by criminological severity
  (financial coercion, urgency pressure, credential theft, threat language,
  impersonation, privacy violation).
- **Entity Extraction**: regex-based detection of URLs, IP addresses, money
  references, crypto mentions, and email addresses.
- **Threat Score Fusion**: blends ML confidence with rule-based signal count
  for a calibrated 0-100 composite threat score.

### Search Algorithms on Investigation Graph
| Algorithm | Strategy | Time Complexity | Investigation Use |
|-----------|----------|-----------------|-------------------|
| BFS | Level-by-level expansion | O(V + E) | Shortest hop path; minimum relay chain |
| DFS | Recursive depth-first | O(V + E) | Full chain; nested network discovery |
| A* | Heuristic-guided cost | O(E log V) | Optimal cost path via threat heuristic |

**Graph semantics:**
- **Nodes** = digital entities: IP addresses, user accounts, devices, servers, wallets
- **Edges** = observed communications/transactions, weighted by suspicion score (1–10)
- **A* heuristic** = absolute difference in risk scores between current and target node;
  admissible because it never overestimates the true cost to reach the target

---

## Tech Stack
| Component | Technology |
|-----------|-----------|
| UI Framework | Streamlit 1.32+ |
| ML / AI | Scikit-learn (TF-IDF, RF, LR, SVM) |
| Graph Algorithms | NetworkX |
| Visualization | Plotly, Matplotlib |
| NLP | Custom lexicon + regex pipeline |
| Database | SQLite (via sqlite3) |
| Language | Python 3.10+ |

---

*CyberShield AI — Academic demonstration project for AI/cybersecurity coursework.*
