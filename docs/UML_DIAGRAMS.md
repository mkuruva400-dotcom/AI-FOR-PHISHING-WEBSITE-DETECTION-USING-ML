# UML Diagrams Specification

This document provides formal Unified Modeling Language (UML) structural and behavioral diagrams for the **AI for Phishing Website Detection System**.

---

## 1. Use-Case Diagram
Represents user and system actor interactions within the security detection framework.

```mermaid
flowchart TD
    User([Security Analyst / End User])
    System([PhishShield AI Engine])
    DB[(SQLite Audit Database)]

    User --> UC1[Submit URL for Real-Time Analysis]
    User --> UC2[Upload QR Code for Quishing Scan]
    User --> UC3[Upload Screenshot for Visual Similarity]
    User --> UC4[View Analytics Dashboard & KPIs]
    User --> UC5[Compare ML & DL Model Benchmarks]
    User --> UC6[Search & Filter Scan Audit Logs]
    User --> UC7[Export Incident Reports as CSV/JSON]

    UC1 --> System
    UC2 --> System
    UC3 --> System
    System --> UC8[Extract 24 Structural URL Features]
    System --> UC9[Execute Multi-Model AI Inference]
    System --> UC10[Compute SHAP Feature Explanations]
    System --> UC11[Perform Safe Headless DOM Inspection]
    System --> UC12[Calculate 0-100 Composite Risk Score]
    
    UC12 --> DB
    UC6 --> DB
    UC7 --> DB
```

---

## 2. Class Diagram
Represents the modular object-oriented architecture of the platform.

```mermaid
classDiagram
    class URLExtractor {
        +list FEATURE_NAMES
        +set SHORTENING_SERVICES
        +set SUSPICIOUS_TLDS
        +extract_url_features(url: str) dict
        +calculate_entropy(text: str) float
        +is_ip_address(domain: str) int
        +features_to_vector(features: dict) list
    }

    class ModelManager {
        -dict models
        -StandardScaler scaler
        -dict metrics
        -str best_model_name
        +get_instance() ModelManager
        +load_artifacts() void
        +predict(url: str, model_choice: str) dict
    }

    class ShapExplainerManager {
        -TreeExplainer explainer
        -BaseEstimator model
        +get_instance() ShapExplainerManager
        +explain_url_features(feature_vector: list, feature_names: list) dict
    }

    class ContentAnalyzer {
        +dict KNOWN_BRANDS
        +analyze_page_content(url: str, html_content: str, timeout: int) dict
    }

    class VisualSimilarity {
        +calculate_dhash(image, hash_size: int) int
        +hamming_distance(hash1: int, hash2: int) int
        +calculate_hist_similarity(img1, img2) float
        +compare_screenshot_with_brands(image_path: str, domain: str) dict
    }

    class QRDetector {
        +decode_qr_code(image_path: str, image_bytes: bytes) dict
        +generate_qr_image(url: str, output_path: str) str
    }

    class RiskScorer {
        +calculate_url_heuristic_risk(features: dict) dict
        +compute_composite_risk(ml_prob: float, url_features: dict, content_res: dict, visual_res: dict) dict
    }

    class DatabaseManager {
        +init_db(db_path: str) void
        +add_scan_record(...) int
        +get_recent_scans(...) list
        +get_scan_by_id(scan_id: int) dict
        +get_dashboard_analytics() dict
    }

    ModelManager --> URLExtractor : uses
    ModelManager --> ShapExplainerManager : delegates explanation
    RiskScorer --> ContentAnalyzer : incorporates
    RiskScorer --> VisualSimilarity : incorporates
    QRDetector --> URLExtractor : supplies decoded URL
    DatabaseManager ..> RiskScorer : logs results
```

---

## 3. Sequence Diagram (Real-Time URL Scan Lifecycle)
Illustrates chronological execution across frontend, web controllers, feature extractors, AI engines, and database.

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Analyst
    participant UI as Web Frontend (Browser)
    participant Flask as Flask Controller (app.py)
    participant Extractor as URL Extractor
    participant ML as ModelManager (AI/DL)
    participant SHAP as SHAP Explainer
    participant DOM as Safe DOM Analyzer
    participant Scorer as Composite Risk Engine
    participant DB as SQLite History DB

    User->>UI: Enter Target URL & Select Model
    UI->>Flask: POST /api/scan {url, model, enable_content}
    
    Flask->>Extractor: extract_url_features(url)
    Extractor-->>Flask: 24 Numerical Features Dictionary

    par AI Inference & Explainability
        Flask->>ML: predict(url, model_choice)
        ML->>ML: Apply StandardScaler & Model Probabilities
        ML-->>Flask: Phishing Probability (0.0 - 1.0)
        Flask->>SHAP: explain_url_features(vector, names)
        SHAP-->>Flask: Shapley Feature Contribution Values
    and Safe DOM Inspection
        Flask->>DOM: analyze_page_content(url, timeout=3)
        DOM-->>Flask: Form actions, Hidden iframes, Content Risk
    end

    Flask->>Scorer: compute_composite_risk(ml_prob, features, content_res)
    Scorer-->>Flask: Risk Score (0-100), Verdict, Warnings, Prevention Tips

    Flask->>DB: add_scan_record(url, verdict, risk_score, latency, ...)
    DB-->>Flask: Record ID

    Flask-->>UI: JSON {success, risk_score, verdict, shap, breakdown, warnings}
    UI->>User: Animate Risk Meter, Render SHAP Chart & Warnings
```

---

## 4. State Machine Diagram (Scan State Lifecycle)
Depicts the state transitions of a scan operation from initiation to report generation.

```mermaid
stateDiagram-v2
    [*] --> Idle: Platform Ready

    Idle --> Ingestion: Receive URL / QR Code Upload
    Ingestion --> Preprocessing: Format Sanitization & Protocol Validation
    
    state Preprocessing {
        [*] --> DecodeQR: If QR Input
        DecodeQR --> ExtractURL: Valid Matrix
        DecodeQR --> Error: Invalid QR
        [*] --> NormalizeURL: If Direct URL
        NormalizeURL --> ExtractURL
        ExtractURL --> VectorizeFeatures: 24 Features
    }

    Preprocessing --> ParallelAnalysis: Feature Vector Ready

    state ParallelAnalysis {
        [*] --> ML_Inference: Model Probability Computation
        [*] --> DOM_Probe: Headless Stream Inspection
        [*] --> Visual_Match: Perceptual Hash Comparison
        ML_Inference --> SHAP_Explanation: Calculate Shapley Values
    }

    ParallelAnalysis --> RiskScoring: Aggregate Intelligence
    RiskScoring --> VerdictEvaluation: Compute Composite Score (0-100)

    state VerdictEvaluation {
        [*] --> SafeState: Score < 30
        [*] --> SuspiciousState: 30 <= Score < 70
        [*] --> PhishingState: Score >= 70
    }

    VerdictEvaluation --> Persistence: Write to SQLite Audit DB
    Persistence --> UI_Render: Transmit JSON Payload & Animate Charts
    UI_Render --> Idle: User Interaction Complete
```

---

## 5. Component Diagram
Illustrates physical and logical module dependencies across the tech stack.

```mermaid
flowchart TD
    subgraph Client_Tier [Client Presentation Layer]
        Browser[Modern Web Browser]
        HTML_CSS[HTML5 / Glassmorphism CSS]
        ChartJS[Chart.js 4.4 Engine]
        Bootstrap[Bootstrap 5 UI Framework]
    end

    subgraph Application_Tier [Application & Control Layer]
        WSGI[Flask 3.1 WSGI Framework]
        Router[REST API Endpoints & Page Controllers]
        Config[App Configuration & Policies]
    end

    subgraph Intelligence_Tier [Core Security & AI Layer]
        FeatureEng[core.url_extractor: 24 Structural Metrics]
        ModelMngr[ml_engine.model_manager: 6 AI Classifiers]
        KerasANN[TensorFlow / Keras Deep Neural Network]
        XGBoostEng[XGBoost Gradient Boosted Trees]
        ShapEngine[core.explainable_ai: SHAP TreeExplainer]
        DOMAnalyzer[core.content_analyzer: Safe BeautifulSoup DOM]
        CVEngine[core.visual_similarity & qr_detector: OpenCV]
        RiskEngine[core.risk_scorer: Dynamic Weighting Formula]
    end

    subgraph Data_Tier [Data Storage Layer]
        SQLite[(instance/phishing_history.db)]
        ModelsDir[(ml_engine/saved_models/*.pkl, *.keras)]
        UploadsDir[(instance/uploads/)]
    end

    Browser <--> HTML_CSS
    HTML_CSS <--> ChartJS
    HTML_CSS <--> Bootstrap
    Browser <--> WSGI
    WSGI --> Router
    Router --> FeatureEng
    Router --> ModelMngr
    Router --> DOMAnalyzer
    Router --> CVEngine
    Router --> RiskEngine

    ModelMngr --> KerasANN
    ModelMngr --> XGBoostEng
    ModelMngr --> ShapEngine
    ModelMngr <--> ModelsDir

    Router <--> SQLite
    CVEngine <--> UploadsDir
```
