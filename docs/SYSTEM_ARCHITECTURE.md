# System Architecture Document

## Project Title
**AI for Phishing Website Detection Using Machine Learning and Deep Learning Technologies**

---

## 1. Executive Summary
The AI-Based Phishing Website Detection System is an enterprise-grade cybersecurity platform that proactively protects end-users and organizational networks from zero-day phishing attacks, credential harvesting, visual brand spoofing, and Quishing (QR code phishing).

Unlike legacy threat detection approaches that depend on static URL blacklists with lag times of 4 to 24 hours, this platform employs a multi-tiered defense-in-depth architecture. It evaluates lexical URL characteristics, deep neural network representations, safe isolated HTML/DOM inspection, OpenCV visual matching, and game-theoretic Explainable AI (SHAP) in under 100 milliseconds.

---

## 2. Multi-Tiered Defense-in-Depth Architecture

```
                                  +-----------------------------+
                                  | User Request / Web Traffic  |
                                  +--------------+--------------+
                                                 |
                                                 v
                       +-------------------------------------------------+
                       |             Input Ingestion Layer               |
                       |  - Direct URL Submission                        |
                       |  - Quishing (QR Code Image via OpenCV Detector) |
                       |  - Website Screenshot Upload                    |
                       +-------------------------+-----------------------+
                                                 |
                                                 v
        +----------------------------------------+----------------------------------------+
        |                                        |                                        |
        v                                        v                                        v
+-------------------------------+  +-------------------------------+  +-------------------------------+
|    Tier 1: URL Intelligence   |  |   Tier 2: Safe DOM Crawler    |  | Tier 3: Visual Matching Engine|
|  - 24 Lexical/Structural Feats|  |  - Isolated Stream (Max 1MB)  |  |  - OpenCV Perceptual dHash   |
|  - Shannon Entropy Calculator |  |  - Form Target / Action Check |  |  - HSV Color Histograms       |
|  - Subdomain & TLD Risk Engine|  |  - Hidden Iframes & Scripts   |  |  - Brand Impersonation Rules  |
|  - Punycode / IDN Homographs  |  |  - External Hyperlink Ratios  |  |  - Template Matching Base     |
+---------------+---------------+  +---------------+---------------+  +---------------+---------------+
                |                                  |                                  |
                v                                  |                                  |
+-------------------------------+                  |                                  |
|     Ensemble AI / DL Engine   |                  |                                  |
|  - Random Forest (150 Trees)  |                  |                                  |
|  - Extreme Gradient Boosting  |                  |                                  |
|  - Keras Deep Learning ANN    |                  |                                  |
|  - SVM (RBF) & Logistic Reg.  |                  |                                  |
|  - Decision Tree Baseline     |                  |                                  |
+---------------+---------------+                  |                                  |
                |                                  |                                  |
                v                                  |                                  |
+-------------------------------+                  |                                  |
|   Explainable AI Engine       |                  |                                  |
|  - SHAP TreeExplainer         |                  |                                  |
|  - Shapley Value Calculation  |                  |                                  |
|  - Marginal Feature Impact    |                  |                                  |
+---------------+---------------+                  |                                  |
                |                                  |                                  |
                +----------------------------------+----------------------------------+
                                                 |
                                                 v
                       +-------------------------------------------------+
                       |       Composite AI Risk Engine (0 - 100)        |
                       |  - Dynamic Weighted Fusion Formula              |
                       |  - Classification: SAFE, SUSPICIOUS, PHISHING   |
                       |  - Security Warning Indicator Generation        |
                       |  - Actionable Remediation Guidance Generator    |
                       +-------------------------+-----------------------+
                                                 |
                                                 v
        +----------------------------------------+----------------------------------------+
        |                                                                                 |
        v                                                                                 v
+-------------------------------+                                         +-------------------------------+
|   Persistent SQLite Audit DB  |                                         |  Modern Web UI / Dashboard    |
|  - Timestamped Incidents      |                                         |  - Real-time Circular Gauge   |
|  - Full Feature Vectors       |                                         |  - Chart.js Visualizations    |
|  - SHAP Explanations          |                                         |  - Interactive Model Matrix   |
|  - CSV / JSON Export Engine   |                                         |  - Audit Log Filtering        |
+-------------------------------+                                         +-------------------------------+
```

---

## 3. Detailed Component Descriptions

### 3.1 Input Ingestion & Quishing Subsystem
- **QR Code Matrix Decoder**: Utilizes OpenCV `cv2.QRCodeDetector` accompanied by Otsu binary thresholding to detect and decode physical or digital QR codes.
- **Payload Sanitization**: Confirms protocol schemes (`http`, `https`), prevents URI injection, and extracts target domain.

### 3.2 Tier 1: URL Feature Engineering Subsystem
Extracts 24 distinct statistical and lexical features:
1. `url_length`: Overall character length.
2. `domain_length`: Hostname length.
3. `is_ip`: Detection of raw IPv4/IPv6 addresses bypassing DNS.
4. `count_dots`: Subdomain nesting frequency.
5. `count_hyphens`: Brand-squatting token separator frequency.
6. `count_at`: `@` symbol obfuscation indicator.
7. `count_question`: Query parameter initiation.
8. `count_and`: Chained parameter count.
9. `count_equal`: Key-value pair density.
10. `count_slash`: Directory depth separator.
11. `count_percent`: Hex encoding percentage.
12. `count_digits`: Numeric concentration.
13. `count_subdomains`: Depth of subdomain hierarchy.
14. `has_https`: Protocol encryption status.
15. `https_in_domain`: Hostname deception indicator.
16. `is_shortened`: Link-shortening redirection flag.
17. `has_suspicious_keyword`: Presence of authentication tokens (e.g. `login`, `verify`, `update`).
18. `path_depth`: Directory tree depth.
19. `prefix_suffix_hyphen`: Hyphen separated brand tokens in hostname.
20. `entropy`: Shannon entropy measuring randomness across the entire URL.
21. `domain_entropy`: Shannon entropy isolated to the registered hostname.
22. `tld_risk`: Flag for high-abuse TLDs (`.tk`, `.xyz`, `.top`, `.ml`, `.cf`, etc.).
23. `punycode`: Internationalized Domain Name (IDN) homograph attack indicator (`xn--`).
24. `special_char_ratio`: Density of non-alphanumeric punctuation.

### 3.3 Tier 2: Machine Learning & Deep Learning Inference
- **Random Forest**: Ensemble of 150 randomized decision trees operating via bootstrap aggregating (bagging) to optimize variance.
- **Extreme Gradient Boosting (XGBoost)**: Gradient-boosted decision trees optimizing pseudo-residuals with regularization ($L_1, L_2$) to prevent overfitting.
- **Deep Learning Artificial Neural Network (ANN)**: 4-layer feedforward Multi-Layer Perceptron (MLP) built in Keras:
  - Input Layer (24 features)
  - Dense Layer 1 (64 neurons, ReLU) + BatchNormalization + Dropout (0.25)
  - Dense Layer 2 (32 neurons, ReLU) + BatchNormalization + Dropout (0.20)
  - Dense Layer 3 (16 neurons, ReLU)
  - Output Layer (1 neuron, Sigmoid activation)
  - Optimizer: Adam ($\eta = 0.002$), Loss: Binary Crossentropy.
- **Support Vector Machine (SVM)**: Maximum-margin hyperplane classifier utilizing a Radial Basis Function (RBF) kernel with Platt scaling.
- **Decision Tree & Logistic Regression**: Interpretable linear and rule-based baselines.
- **Ensemble Fusion**: Weighted consensus voting prioritizing top empirical performers.

### 3.4 Tier 3: Isolated DOM & Content Inspection
- **Isolated HTTP Session**: Headless backend GET request executed with custom security-audit headers, a 3-second strict timeout, and a 1 MB stream cap.
- **Form Action Auditing**: Evaluates whether credential forms post to empty targets (`#`, `about:blank`, `javascript:void(0)`) or submit passwords to unauthorized third-party domains.
- **Hyperlink Distribution**: Measures percentage of external links versus internal links. Phishing pages frequently clone legitimate style assets and outbound links while redirecting only authentication targets.
- **Invisible Iframes**: Detects hidden or 0-pixel iframes used for clickjacking or covert payload injection.
- **Anti-Analysis Scripts**: Detects client-side JavaScript disabling right-click context menus (`event.button == 2`) or source inspection.

### 3.5 Tier 4: Visual Similarity & Brand Impersonation Engine
- **Difference Hash (dHash)**: Computes a 64-bit structural perceptual hash by scaling images to $9 \times 8$ grayscale and comparing adjacent horizontal pixel intensities.
- **Color Histogram Matching**: Evaluates normalized 2D HSV color distributions using the Bhattacharyya distance / correlation metric.
- **Deception Evaluation**: If an uploaded screenshot matches a protected brand template (e.g., PayPal, Google, Microsoft, Amazon, Netflix) with $\ge 50\%$ visual correlation, but the target domain is unauthorized, a critical visual impersonation alert is triggered.

### 3.6 Explainable AI (SHAP) Subsystem
- **Shapley Additive exPlanations**: Employs `shap.TreeExplainer` rooted in cooperative game theory:
  $$\phi_i(v) = \sum_{S \subseteq N \setminus \{i\}} \frac{|S|!(|N| - |S| - 1)!}{|N|!} (v(S \cup \{i\}) - v(S))$$
- Produces local explanations revealing which exact URL features pushed the model's confidence toward phishing ($+$) or benign ($-$).
- Formats feature contribution data into bar and waterfall charts rendered dynamically via Chart.js.

### 3.7 Composite Risk Engine (0 - 100)
Calculates a fused risk score:
$$\text{Risk Score} = w_1 S_{\text{ML}} + w_2 S_{\text{URL}} + w_3 S_{\text{Content}} + w_4 S_{\text{Visual}}$$
- Score categorization:
  - **0 - 29**: SAFE (Low Risk, Emerald Green)
  - **30 - 69**: SUSPICIOUS (Medium Risk, Amber Orange)
  - **70 - 100**: PHISHING (High Risk Malicious, Crimson Red)
- Generates context-specific remediation instructions and security indicators.
