# Visual Studio Code Setup & Execution Guide

## Project Title
**AI for Phishing Website Detection Using Machine Learning and Deep Learning Technologies**

This guide provides clear, step-by-step instructions to open, configure, test, and run the complete project inside **Visual Studio Code (VS Code)** on Windows.

---

## 1. Prerequisites
Ensure you have the following installed on your system:
- **Visual Studio Code:** [Download VS Code](https://code.visualstudio.com/)
- **Python 3.10 – 3.14:** Installed and added to system PATH.
- **VS Code Python Extension:** "Python" extension by Microsoft (Identifier: `ms-python.python`).

---

## 2. Step-by-Step Execution in VS Code

### Step 1: Open the Project Directory
1. Launch **Visual Studio Code**.
2. Click **File** on the top menu bar, then click **Open Folder...** (or press <kbd>Ctrl + K</kbd>, <kbd>Ctrl + O</kbd>).
3. Navigate to and select the project folder:
   ```
   C:\Users\THRINADH\OneDrive\Desktop\AI For Phishing
   ```
4. Click **Select Folder**.

---

### Step 2: Select the Python Interpreter
1. Press <kbd>Ctrl + Shift + P</kbd> to open the VS Code Command Palette.
2. Type and select: `Python: Select Interpreter`.
3. Choose the installed Python environment (e.g., `Python 3.14.x` or your preferred virtual environment).
4. Verify the selected interpreter appears in the bottom-right corner of the VS Code status bar.

---

### Step 3: Open the Integrated Terminal
1. Press <kbd>Ctrl + `</kbd> (backtick) or select **Terminal > New Terminal** from the top menu.
2. Ensure the terminal opens in PowerShell or Command Prompt at the project root:
   ```powershell
   PS C:\Users\THRINADH\OneDrive\Desktop\AI For Phishing>
   ```

---

### Step 4: Verify or Install Dependencies
All dependencies are already installed in your environment. If you ever set up on a new computer, run:
```powershell
python -m pip install -r requirements.txt
```

---

### Step 5: Run Automated Unit Tests
Before launching the server, verify that all core modules pass unit testing:
```powershell
python -m unittest discover tests
```
**Expected Output:**
```
Ran 14 tests in 2.40s
OK
```
All 14 tests across feature extraction, ML models, ANN, risk scoring, safe DOM inspection, and QR decoding should pass cleanly.

---

### Step 6: (Optional) Re-Train Models & Generate New Plots
The pre-trained models (`.pkl`, `.keras`) and benchmark charts are already generated and saved in `ml_engine/saved_models/`.

If you wish to re-train the models from scratch during demonstration:
```powershell
python ml_engine/train_models.py
```
This trains all 6 algorithms (Random Forest, Decision Tree, SVM, Logistic Regression, XGBoost, and Keras Deep Learning ANN), logs performance metrics, updates `model_metrics.json`, and re-generates publication charts in `ml_engine/saved_models/plots/`.

---

### Step 7: Launch the Flask Web Application
To start the cybersecurity web application, run:
```powershell
python app.py
```
**Terminal Output:**
```
================================================================
   AI PHISHING DETECTION SYSTEM - FULL-STACK ENGINE ACTIVATED   
   Access Web Application at: http://127.0.0.1:5000            
================================================================
 * Serving Flask app 'app'
 * Running on http://127.0.0.1:5000
```

---

### Step 8: Open the Web Application
1. Open your web browser (Chrome, Edge, Firefox, or Brave).
2. Navigate to:
   ```
   http://127.0.0.1:5000
   ```
3. You will see the futuristic cybersecurity dark-mode UI with:
   - **Live Scanner:** Test any URL, click quick sample buttons, or select algorithm.
   - **Quishing Scanner:** Upload a QR code image to decode and inspect embedded links.
   - **Screenshot Similarity:** Upload a website screenshot to check visual brand impersonation.
   - **Analytics Dashboard:** Navigate to `/dashboard` to view interactive Chart.js visualizations.
   - **Model Comparison:** Navigate to `/models` to inspect the 6-algorithm benchmark matrix and confusion matrices.
   - **Detection History:** Navigate to `/history` to review, search, filter, and export incident logs to CSV or JSON.
   - **Embedded Documentation:** Navigate to `/docs` to view architecture, UML diagrams, and viva answers.

---

### Step 9: Stopping the Application
To stop the server when done, click into the VS Code terminal window and press <kbd>Ctrl + C</kbd>.

---

## 3. Alternative 1-Click Launch Method
You can also launch the application directly without typing commands:
1. Open Windows File Explorer.
2. Navigate to: `C:\Users\THRINADH\OneDrive\Desktop\AI For Phishing`.
3. Double-click **`run_app.bat`**.
4. The batch script verifies Python, checks the database, ensures models are present, and launches the server automatically.
