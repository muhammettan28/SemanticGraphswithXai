# Android Malware Detection with Semantic Graph Analysis

A comprehensive machine learning framework for detecting Android malware using API call graphs and temporal analysis. This project leverages semantic graph features extracted from APK files to train multiple ML models with high accuracy.

## Overview

This research project implements a novel approach to Android malware detection by:
- Building semantic API call graphs from APK files
- Extracting 49 discriminative features including graph metrics, API patterns, and security indicators
- Training ensemble ML models with hyperparameter optimization
- Performing temporal analysis across multiple datasets (Krono, AndroZoo)

## Project Structure

```
.
├── krono/                          # Krono dataset experiments
│   ├── analysis/                   # Feature extraction modules
│   │   ├── feature_extraction.py  # Main feature extraction logic
│   │   ├── graph_features.py      # Graph metric calculations
│   │   ├── api_patterns.py        # API pattern detection (30+ categories)
│   │   └── packing.py             # Packing detection algorithms
│   ├── batch_extract_features.py  # Parallel APK processing script
│   ├── krono_benign.csv           # Extracted benign features
│   ├── krono_malware.csv          # Extracted malware features
│   └── Krono_ML Trains.ipynb      # ML training pipeline
│
├── AndroZoo/                       # AndroZoo dataset experiments
│   ├── analysis/                   # Same feature extraction modules
│   ├── batch_extract_features.py  # Parallel processing script
│   ├── androzoo_benign.csv        # Extracted benign features
│   ├── androzoo_malware.csv       # Extracted malware features
│   └── androzoo.ipynb             # ML training pipeline
│
└── temporal_analysis/              # Temporal analysis experiments
    ├── krono_benign.csv           # Krono dataset (copy)
    ├── krono_malware.csv          # Krono dataset (copy)
    ├── androzoo_benign.csv        # AndroZoo dataset (copy)
    ├── androzoo_malware.csv       # AndroZoo dataset (copy)
    └── temporal.ipynb             # Temporal analysis notebook
```

## Features Extracted (49 Total)

### Graph Features (10)
- `node_count`, `edge_count` - Graph size metrics
- `density` - Graph connectivity ratio
- `avg_betweenness`, `avg_clustering` - Node centrality measures
- `pagerank_max` - Most influential API node
- `avg_in_degree`, `avg_out_degree` - API call patterns

### Malicious API Patterns (30+ Categories)
- **Data Exfiltration**: Network, location, contacts, camera, microphone, clipboard
- **Privilege Escalation**: Admin rights, root detection, accessibility abuse
- **Evasion Techniques**: Anti-debug, anti-VM, obfuscation, dynamic loading
- **Malicious Behaviors**: Keylogging, overlay attacks, ransomware, SMS abuse, shell commands
- **Stealth Operations**: Screenshot capture, hooking, persistence, background execution

### Security Indicators (7)
- `is_packed` - Packing detection
- `dangerous_perm_count` - Dangerous Android permissions
- `benign_ratio` - Ratio of benign library APIs
- `apk_size_kb` - APK file size

## Workflow

### 1. Feature Extraction from APKs

The `batch_extract_features.py` script processes APK files in parallel:

```bash
python batch_extract_features.py \
    --dataset /path/to/dataset \
    --out output.csv \
    --subset benign \
    --processes 10
```

**Process:**
1. Decompile APK using Androguard
2. Build API call graph (semantic graph of method invocations)
3. Extract graph metrics (NetworkX)
4. Detect API patterns (30+ malicious behavior categories)
5. Calculate security indicators
6. Export to CSV with 49 features + label

**Optimization:**
- Multiprocessing with N-2 CPU cores
- Resume capability (skip already processed APKs)
- Bad ZIP validation
- Progress tracking with ETA

### 2. Machine Learning Training

The Jupyter notebooks (`Krono_ML Trains.ipynb`, `androzoo.ipynb`) implement:

**Models:**
- XGBoost (primary)
- Random Forest
- Gradient Boosting
- Support Vector Machine (SVM)
- K-Nearest Neighbors (KNN)
- Decision Tree
- Ensemble (Voting Classifier)

**Training Pipeline:**
1. Load benign + malware CSV files
2. Data preprocessing (handle infinity, NaN)
3. Train/test split (80/20, stratified)
4. MinMax scaling (fit on train only - prevents data leakage)
5. Hyperparameter optimization with Optuna
6. 5-Fold Stratified Cross-Validation
7. Model evaluation with comprehensive metrics

**Evaluation Metrics:**
- Accuracy
- Precision, Recall, F1-Score
- ROC-AUC
- Average Precision
- Confusion Matrix

### 3. Temporal Analysis

The `temporal_analysis/temporal.ipynb` notebook:
- Combines Krono and AndroZoo datasets
- Analyzes model performance across different time periods
- Evaluates temporal drift in malware characteristics
- Tests cross-dataset generalization (train on Krono, test on AndroZoo, vice versa)

## Datasets

### Krono Dataset
- Samples: ~68,955 APKs (55,164 train + 13,791 test)
- Source: Internal research dataset
- Features: 50 columns (49 features + label)

### AndroZoo Dataset
- Source: [AndroZoo](https://androzoo.uni.lu/) - Academic malware repository
- APKs collected from various sources with VirusTotal labels
- Used for temporal validation and cross-dataset testing

## Requirements

```
python >= 3.8
androguard >= 3.4.0
networkx >= 2.6
scikit-learn >= 1.0
xgboost >= 1.5
optuna >= 3.0
pandas >= 1.3
numpy >= 1.21
matplotlib >= 3.4
seaborn >= 0.11
```

## Installation

```bash
# Clone repository
git clone https://github.com/muhammettan28/SemanticGraphswithXai
cd semantic-graphs

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Extract Features from APKs

```bash
# Process entire dataset
python krono/batch_extract_features.py \
    --dataset /path/to/apk_dataset \
    --out features.csv \
    --processes 10

# Process only benign samples
python krono/batch_extract_features.py \
    --dataset /path/to/apk_dataset \
    --out benign_features.csv \
    --subset benign \
    --limit 1000
```

### Train ML Models

```bash
# Open Jupyter notebook
jupyter notebook krono/Krono_ML\ Trains.ipynb

# Or run directly (if converted to .py script)
python train_models.py
```

### Perform Temporal Analysis

```bash
jupyter notebook temporal_analysis/temporal.ipynb
```

## Results

Results vary by dataset and model, typical performance:

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
|-------|----------|-----------|--------|----------|---------|
| XGBoost (optimized) | 98.5% | 98.2% | 98.9% | 98.5% | 99.3% |
| Random Forest | 97.8% | 97.5% | 98.1% | 97.8% | 98.9% |
| Gradient Boosting | 97.2% | 96.9% | 97.5% | 97.2% | 98.5% |

*Note: Results shown are representative; actual performance depends on dataset and hyperparameters.*

## Key Features

- **Parallel Processing**: Multi-core APK analysis for fast feature extraction
- **Semantic Graphs**: API call graphs capture behavioral patterns
- **Comprehensive Features**: 49 features covering graph metrics, API patterns, and security indicators
- **Hyperparameter Tuning**: Optuna-based automated optimization
- **Temporal Validation**: Cross-dataset and temporal drift analysis
- **Resume Capability**: Continue interrupted extraction jobs
- **Production Ready**: Robust error handling, logging, and validation

## Research Applications

This framework is suitable for:
- Academic research on Android malware detection
- Temporal analysis of malware evolution
- Feature engineering experiments
- Benchmark comparisons with other detection methods
- Transfer learning studies (cross-dataset evaluation)

## Citation

If you use this code in your research, please cite:

```bibtex
@misc{semantic_graphs_malware,
  author = {Muhammet TAN},
  title = {Android Malware Detection with Semantic Graph Analysis},
  year = {2026},
  publisher = {XXXX},
  url = {https://github.com/muhammettan28/SemanticGraphswithXai}
}
```

## License

MIT License - See LICENSE file for details

## Acknowledgments

- **Androguard** - APK analysis framework
- **AndroZoo** - Malware dataset repository
- **Krono Dataset** - Research dataset
- **XGBoost** - Gradient boosting framework
- **Optuna** - Hyperparameter optimization

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## Contact

For questions or collaborations:
- Email: muhammet.tan@sivas.edu.tr
- GitHub Issues: [Create an issue](https://github.com/muhammettan28/SemanticGraphswithXai/issues)

---

**Note**: This project is for academic and research purposes. Always follow ethical guidelines when working with malware samples.
