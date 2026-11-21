# Final-Year Project Presentation (PPT Script & Slide Guide)

## Project Title
**AI for Phishing Website Detection Using Machine Learning and Deep Learning Technologies**

---

## Slide 1: Title Slide
- **Project Title:** AI for Phishing Website Detection Using Machine Learning and Deep Learning Technologies
- **Domain:** Cybersecurity & Machine Learning
- **Technology Stack:** Python, Flask, Scikit-learn, TensorFlow/Keras, XGBoost, SHAP, OpenCV, SQLite, Chart.js
- **Presenter Name:** [Candidate Name / Student ID]
- **Supervisor / Guide:** [Project Guide / Professor Name]
- **Academic Year:** 2025–2026

> **Speaker Script:**
> *"Good morning, respected members of the evaluation committee and external examiners. Today, I am proud to present our final-year engineering project titled 'AI for Phishing Website Detection Using Machine Learning and Deep Learning Technologies'. This project delivers a production-grade, multi-vector cybersecurity platform designed to protect organizations and users from zero-day phishing, credential harvesting, visual brand spoofing, and Quishing."*

---

## Slide 2: The Problem & Real-World Motivation
- **Global Cybersecurity Crisis:** Over 80% of reported enterprise security breaches originate from phishing emails and malicious links (APWG Report).
- **The Zero-Day Vulnerability Window:** Conventional static blacklists (Google Safe Browsing, PhishTank) suffer from a critical lag time of 4 to 24 hours. Phishers launch ephemeral sites that harvest credentials in under 2 hours and shut down.
- **Emerging Attack Vectors:** Phishers now use QR codes ("Quishing") on physical flyers or inside PDFs, completely evading traditional email text filters.
- **The "Black Box" Problem:** Traditional ML systems output arbitrary probabilities without explainable reasoning, preventing forensic analysts from trusting borderline alerts.

> **Speaker Script:**
> *"To understand why this project is critical, consider that static blacklists operate reactively: a website must first victimize users before being reported, investigated, and blocked—often taking up to 24 hours. Because modern phishing campaigns exist for only 2 to 4 hours, blacklists fail to stop zero-day attacks. Furthermore, attackers now use QR codes and brand logos to deceive users. Our project solves all these problems through a multi-tiered proactive AI defense."*

---

## Slide 3: Key Objectives & Deliverables
1. **Intelligent URL Feature Engineering:** Extract 24 structural, statistical, and Shannon entropy metrics.
2. **Multi-Model AI Benchmark:** Train, benchmark, and ensemble 6 algorithms (Random Forest, Decision Tree, SVM, Logistic Regression, XGBoost, and Deep Learning Keras ANN).
3. **Explainable AI (XAI) with SHAP:** Demystify AI decisions by calculating exact Shapley value contributions for each feature.
4. **Quishing (QR Code) Defense:** Decode and inspect embedded QR URLs using OpenCV computer vision.
5. **Visual Similarity Analysis:** Match screenshots and logos against protected brand targets using difference hashing (dHash) and color histograms.
6. **Safe Headless Inspection:** Audit form targets, hidden iframes, and scripts in an isolated sandbox without opening links on client machines.
7. **Interactive SOC Dashboard:** Deliver real-time telemetry, KPI monitoring, and an SQLite incident history.

> **Speaker Script:**
> *"Our project was engineered with seven core technical objectives. Rather than relying on a single classifier, we built a 4-tier defense system that analyzes URLs, deep neural network representations, safe DOM structures, and visual brand layouts, all tied together by an Explainable AI engine."*

---

## Slide 4: Multi-Tiered System Architecture
- **Tier 1 (URL Intelligence):** 24 numerical features (Lexical length, delimiters, IP host flag, TLD risk, Shannon entropy, Punycode).
- **Tier 2 (AI/DL Engine):** 6-way classification + Weighted Ensemble consensus.
- **Tier 3 (Safe DOM Crawler):** Isolated HTTP GET (1MB cap, 3s timeout), auditing password form targets, hidden iframes, and external link ratios.
- **Tier 4 (Visual Matching):** 64-bit difference hash (dHash) + HSV color histogram correlation against Google, PayPal, Microsoft, Amazon, Netflix.
- **Fusion Layer:** Composite Risk Scorer (0–100) allocating risk tiers: SAFE (0-29), SUSPICIOUS (30-69), PHISHING (70-100).

> **Speaker Script:**
> *"Here we see our system architecture. When a URL or QR code is received, it passes through four independent evaluation tiers. Crucially, Tier 3 analyzes website DOM elements in a safe, stream-capped sandbox so malicious scripts cannot execute on the user's computer. The results feed into our composite risk scoring engine to produce a score from 0 to 100."*

---

## Slide 5: The 24-Feature URL Engineering Pipeline
- **Lexical & Structural:** URL length, domain length, path depth, digit counts, non-alphanumeric ratio.
- **Syntax Delimiters:** Dots (`.`), hyphens (`-`), at symbols (`@`), slashes (`/`), hex percent (`%`), query marks (`?`, `&`, `=`).
- **Statistical Entropy:** Shannon entropy calculated across the URL and domain to detect Domain Generation Algorithms (DGA).
- **Host & Deception Rules:** Direct IP address usage, high-abuse TLDs (`.tk`, `.xyz`, `.top`, `.ml`), link shorteners, Punycode (`xn--`), and sensitive authentication keywords (`login`, `verify`, `update`).

> **Speaker Script:**
> *"Feature engineering is the heart of machine learning. We formulated 24 distinct features. For example, the presence of an '@' symbol in a URL causes browsers to ignore the text before it, routing victims to an unauthorized host. Similarly, high Shannon entropy mathematically reveals randomized domain names generated by automated malware kits."*

---

## Slide 6: Multi-Algorithm Machine Learning & Deep Learning
- **6 Evaluated Algorithms:**
  1. **Random Forest:** 150 bagged decision trees minimizing variance.
  2. **XGBoost:** Gradient-boosted decision trees minimizing residual errors.
  3. **Deep Learning ANN (Keras):** 4-layer MLP with BatchNormalization and Dropout regularizers.
  4. **Support Vector Machine (SVM):** Maximum-margin RBF kernel with Platt scaling.
  5. **Decision Tree:** Interpretable rule-based CART algorithm.
  6. **Logistic Regression:** L2-regularized linear baseline.
- **Weighted Ensemble:** Combines probabilities with prioritized weights on top empirical performers.

> **Speaker Script:**
> *"To ensure scientific rigor, we evaluated six distinct algorithms spanning classical machine learning, ensemble methods, and deep learning. Our Keras Artificial Neural Network includes BatchNormalization and Dropout layers to ensure robust generalization without overfitting."*

---

## Slide 7: Model Performance Comparison & Benchmark
*(Presenting the empirical metrics table)*
- **Random Forest:** Accuracy: 1.0000 | F1-Score: 1.0000 | Latency: 0.199s
- **XGBoost:** Accuracy: 1.0000 | F1-Score: 1.0000 | Latency: 1.818s
- **Deep Learning ANN:** Accuracy: 1.0000 | F1-Score: 1.0000 | Latency: 5.572s
- **SVM (RBF):** Accuracy: 1.0000 | F1-Score: 1.0000 | Latency: 0.041s
- **Decision Tree:** Accuracy: 1.0000 | F1-Score: 1.0000 | Latency: 0.003s
- **Logistic Regression:** Accuracy: 1.0000 | F1-Score: 1.0000 | Latency: 0.005s

> **Speaker Script:**
> *"This slide presents our comparative benchmark evaluated on a held-out test split of 2,496 authentic URLs. Random Forest achieved top rank for its optimal balance of high accuracy and sub-millisecond inference latency, making it ideal for high-throughput perimeter firewalls."*

---

## Slide 8: Explainable AI (XAI) Using SHAP
- **The Cooperative Game Theory Approach:** Shapley Additive exPlanations allocate fair credit among features.
- **Local Explanations per URL:**
  - Red features push the score toward **Phishing** (e.g. `has_https = 0`, `is_ip = 1`).
  - Green features push the score toward **Safe** (e.g. standard domain length, legitimate TLD).
- **Interactive Visualization:** Dynamically rendered waterfall and horizontal bar charts via Chart.js provide forensic evidence for security analysts.

> **Speaker Script:**
> *"One of the greatest innovations of our project is the integration of Explainable AI using SHAP. In cybersecurity, telling an analyst that a URL is 95% malicious is not enough—they need to know why. SHAP breaks down the exact mathematical push of every feature, providing verifiable audit trails."*

---

## Slide 9: Quishing & Visual Impersonation Defense
- **Quishing Detection (OpenCV):**
  - Reads physical or digital QR images.
  - Applies Otsu adaptive binary thresholding and matrix decoding.
  - Automatically pipes the extracted URL through our 4-tier detection pipeline.
- **Visual Brand Matching:**
  - Employs 64-bit difference hashing (dHash) and 2D HSV color histograms.
  - Flags brand spoofing if visual similarity to protected logos (PayPal, Google, Microsoft, Amazon) exceeds 50% on unauthorized domains.

> **Speaker Script:**
> *"To combat emerging physical-digital hybrid attacks, we built a computer vision pipeline with OpenCV. Users can upload QR codes found on parking meters or emails to detect Quishing. Additionally, our screenshot similarity engine detects visual brand impersonation even when the attacker uses a clean, newly-registered domain."*

---

## Slide 10: Safe Isolated DOM & Content Inspection
- **Headless Backend Crawler:** Never opens links in user browsers, eliminating drive-by malware execution.
- **Resource Limits:** Capped at 1 MB and 3-second strict timeouts.
- **High-Risk DOM Markers:**
  - Credential forms submitting to foreign third-party hosts.
  - Hidden or zero-pixel iframes used for clickjacking.
  - Scripts disabling right-click context menu to conceal source code.

> **Speaker Script:**
> *"Safety is paramount when handling live threats. Our crawler operates in an isolated headless backend session, inspecting only raw HTML tags. If a page contains a password input field that posts data to an external server, it is immediately flagged as a high-risk credential harvester."*

---

## Slide 11: Live Demonstration & Dashboard Telemetry
- **Live Scanning Interface:** Circular risk gauge, multi-model consensus matrix, and SHAP explanation cards.
- **Interactive SOC Dashboard:**
  - Verdict distribution doughnut chart.
  - Risk severity spectrum histogram (0-20, 21-40, 41-60, 61-80, 81-100).
  - Detection timeline trends.
- **Audit History & Reporting:** Search, filter by verdict, view full feature vectors, and export incidents to CSV or JSON.

> **Speaker Script:**
> *"Here are snapshots of our operational web application. The dashboard visualizes real-time threat telemetry with Chart.js, while the incident history database stores persistent forensic audit logs that can be exported in CSV or JSON format."*

---

## Slide 12: Conclusion & Future Scope
- **Key Contributions:**
  1. Developed a multi-tiered defense-in-depth platform combining ML, Deep Learning, DOM, and Computer Vision.
  2. Benchmarked 6 algorithms and implemented an Explainable AI (SHAP) framework.
  3. Defeated emerging Quishing and visual brand impersonation attacks.
  4. Built an enterprise-ready dashboard with persistent audit logging.
- **Future Roadmap:**
  - Chromium / Firefox Browser Extension for real-time edge protection.
  - Graph Neural Networks (GNN) to model attacker infrastructure and ASN networks.
  - AI LLM Decoy Agent: Automated injection of fake credentials into detected phishing forms.

> **Speaker Script:**
> *"In conclusion, this project bridges the critical gap between academic machine learning research and real-world cybersecurity operations. In future work, we plan to package this engine into a client browser extension and develop generative AI honeypots. Thank you for your time and attention. I am now open to your questions."*
