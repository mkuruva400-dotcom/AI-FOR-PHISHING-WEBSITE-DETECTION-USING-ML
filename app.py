import os
import time
import json
import csv
import io
from flask import Flask, render_template, request, jsonify, Response, send_file
from werkzeug.utils import secure_filename

from config import Config
from core.database import (
    init_db, add_scan_record, get_recent_scans,
    get_scan_by_id, delete_scan, clear_all_scans, get_dashboard_analytics
)
from core.url_extractor import extract_url_features
from core.content_analyzer import analyze_page_content
from core.visual_similarity import compare_screenshot_with_brands
from core.qr_detector import decode_qr_code
from core.risk_scorer import compute_composite_risk
from ml_engine.model_manager import get_model_manager

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config.from_object(Config)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.dirname(app.config['DATABASE_PATH']), exist_ok=True)

# Initialize SQLite database
init_db(app.config['DATABASE_PATH'])

# Load AI Model Manager
model_manager = get_model_manager()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# ---------------------------------------------------------
# Web Page Routes
# ---------------------------------------------------------

@app.route('/')
def index():
    """Main Real-Time Phishing & Quishing Detection Center."""
    metrics = model_manager.metrics.get('models', {})
    best_model = model_manager.best_model_name
    return render_template('index.html', models=metrics, best_model=best_model)


@app.route('/dashboard')
def dashboard():
    """Interactive Analytics Dashboard with Chart.js."""
    analytics = get_dashboard_analytics(app.config['DATABASE_PATH'])
    return render_template('dashboard.html', analytics=analytics)


@app.route('/models')
def models_comparison():
    """ML and Deep Learning Performance Comparison Benchmark."""
    metrics = model_manager.metrics
    return render_template('models.html', metrics=metrics)


@app.route('/history')
def history():
    """Detection History Table with Filters and Details."""
    scans = get_recent_scans(limit=100, db_path=app.config['DATABASE_PATH'])
    return render_template('history.html', scans=scans)


@app.route('/docs')
def documentation():
    """System Architecture, UML Diagrams, and Technical Viva Guide."""
    return render_template('docs.html')


# ---------------------------------------------------------
# REST API Endpoints
# ---------------------------------------------------------

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """
    Main real-time URL scanning API.
    Performs AI inference, URL heuristic analysis, isolated safe content check,
    SHAP explanation, and composite risk scoring.
    """
    t0 = time.time()
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    model_choice = data.get('model', 'Ensemble')
    enable_content = data.get('enable_content', True)

    if not url:
        return jsonify({'error': 'Please provide a valid URL string to analyze.'}), 400

    try:
        # 1. AI Machine Learning & Deep Learning Inference + SHAP
        ml_result = model_manager.predict(url, model_choice=model_choice)
        ml_prob = ml_result['phishing_probability']

        # 2. Safe Isolated Content Analysis (Does NOT open in user's browser)
        content_result = None
        if enable_content:
            content_result = analyze_page_content(url, timeout=3)

        # 3. Visual Similarity Check (Optional if simulated or uploaded)
        visual_result = None

        # 4. Composite AI Risk Scoring
        risk_result = compute_composite_risk(
            ml_probability=ml_prob,
            url_features=ml_result['features'],
            content_result=content_result,
            visual_result=visual_result
        )

        latency_ms = round((time.time() - t0) * 1000, 1)

        # 5. Store record in database
        scan_id = add_scan_record(
            target_url=url,
            source_type='URL',
            model_name=ml_result['model_used'],
            verdict=risk_result['verdict'],
            risk_score=risk_result['risk_score'],
            ml_probability=ml_prob,
            response_time_ms=latency_ms,
            breakdown=risk_result['breakdown'],
            warnings=risk_result['warnings'],
            features=ml_result['features'],
            db_path=app.config['DATABASE_PATH']
        )

        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'url': url,
            'model_used': ml_result['model_used'],
            'latency_ms': latency_ms,
            'risk_score': risk_result['risk_score'],
            'verdict': risk_result['verdict'],
            'verdict_label': risk_result.get('verdict_label', risk_result['verdict']),
            'verdict_title': risk_result.get('verdict_title', f"VERDICT: {risk_result['verdict']}"),
            'verdict_desc': risk_result.get('verdict_desc', ''),
            'risk_level': risk_result['risk_level'],
            'color': risk_result['color'],
            'badge_class': risk_result['badge_class'],
            'breakdown': risk_result['breakdown'],
            'all_model_probabilities': ml_result['all_model_probabilities'],
            'warnings': risk_result['warnings'],
            'prevention_tips': risk_result['prevention_tips'],
            'shap': ml_result['shap_explanation'],
            'features': ml_result['features'],
            'content_analysis': content_result
        })

    except Exception as e:
        return jsonify({'error': f"Analysis encountered an error: {str(e)}"}), 500


@app.route('/api/scan-qr', methods=['POST'])
def api_scan_qr():
    """
    Decodes uploaded QR code image (Quishing Detection) and routes extracted URL
    through the multi-engine AI detection pipeline.
    """
    t0 = time.time()
    if 'qr_image' not in request.files:
        return jsonify({'error': 'No QR image file uploaded.'}), 400

    file = request.files['qr_image']
    if file.filename == '':
        return jsonify({'error': 'No selected file.'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Unsupported file format. Please upload PNG, JPG, or WebP.'}), 400

    try:
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], f"qr_{int(time.time())}_{filename}")
        file.save(save_path)

        # Decode QR code
        qr_res = decode_qr_code(image_path=save_path)
        if not qr_res['success']:
            return jsonify({'error': qr_res['error'] or 'Failed to decode QR code.'}), 400

        if not qr_res['is_url']:
            return jsonify({
                'success': True,
                'is_url': False,
                'decoded_text': qr_res['decoded_text'],
                'message': 'Decoded QR code is plain text/data, not a website URL.'
            })

        target_url = qr_res['url']
        model_choice = request.form.get('model', 'Ensemble')

        # Run AI detection on the extracted URL
        ml_result = model_manager.predict(target_url, model_choice=model_choice)
        ml_prob = ml_result['phishing_probability']

        # Isolated content analysis
        content_result = analyze_page_content(target_url, timeout=3)

        # Composite risk scoring
        risk_result = compute_composite_risk(
            ml_probability=ml_prob,
            url_features=ml_result['features'],
            content_result=content_result
        )

        # Add Quishing indicators to warnings
        risk_result['warnings'].extend(qr_res.get('quishing_indicators', []))

        latency_ms = round((time.time() - t0) * 1000, 1)

        # Store record in database
        scan_id = add_scan_record(
            target_url=target_url,
            source_type='QR_CODE',
            model_name=ml_result['model_used'],
            verdict=risk_result['verdict'],
            risk_score=risk_result['risk_score'],
            ml_probability=ml_prob,
            response_time_ms=latency_ms,
            breakdown=risk_result['breakdown'],
            warnings=risk_result['warnings'],
            features=ml_result['features'],
            db_path=app.config['DATABASE_PATH']
        )

        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'source_type': 'QR_CODE',
            'url': target_url,
            'qr_details': qr_res,
            'model_used': ml_result['model_used'],
            'latency_ms': latency_ms,
            'risk_score': risk_result['risk_score'],
            'verdict': risk_result['verdict'],
            'verdict_label': risk_result.get('verdict_label', risk_result['verdict']),
            'verdict_title': risk_result.get('verdict_title', f"VERDICT: {risk_result['verdict']}"),
            'verdict_desc': risk_result.get('verdict_desc', ''),
            'risk_level': risk_result['risk_level'],
            'color': risk_result['color'],
            'badge_class': risk_result['badge_class'],
            'breakdown': risk_result['breakdown'],
            'all_model_probabilities': ml_result['all_model_probabilities'],
            'warnings': risk_result['warnings'],
            'prevention_tips': risk_result['prevention_tips'],
            'shap': ml_result['shap_explanation'],
            'features': ml_result['features'],
            'content_analysis': content_result
        })

    except Exception as e:
        return jsonify({'error': f"QR analysis exception: {str(e)}"}), 500


@app.route('/api/scan-screenshot', methods=['POST'])
def api_scan_screenshot():
    """
    Performs Visual Phishing & Brand Impersonation similarity analysis
    using OpenCV perceptual hashing and color histogram matching.
    """
    if 'screenshot' not in request.files:
        return jsonify({'error': 'No screenshot file provided.'}), 400

    file = request.files['screenshot']
    target_domain = request.form.get('domain', '').strip()

    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid image file provided.'}), 400

    try:
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], f"ss_{int(time.time())}_{filename}")
        file.save(save_path)

        visual_res = compare_screenshot_with_brands(image_path=save_path, domain=target_domain)
        return jsonify({'success': True, 'visual_result': visual_res})
    except Exception as e:
        return jsonify({'error': f"Screenshot similarity error: {str(e)}"}), 500


@app.route('/api/analytics')
def api_analytics():
    """JSON API for real-time dashboard updates."""
    data = get_dashboard_analytics(app.config['DATABASE_PATH'])
    return jsonify(data)


@app.route('/api/history')
def api_history():
    """JSON API for scan history records."""
    search = request.args.get('search')
    verdict = request.args.get('verdict')
    limit = int(request.args.get('limit', 50))
    scans = get_recent_scans(limit=limit, search=search, verdict_filter=verdict, db_path=app.config['DATABASE_PATH'])
    return jsonify(scans)


@app.route('/api/history/<int:scan_id>', methods=['GET'])
def api_history_item(scan_id):
    """Retrieve details for a single scan."""
    scan = get_scan_by_id(scan_id, db_path=app.config['DATABASE_PATH'])
    if not scan:
        return jsonify({'error': 'Record not found'}), 404
    return jsonify(scan)


@app.route('/api/history/<int:scan_id>', methods=['DELETE'])
def api_delete_history(scan_id):
    """Delete a scan record."""
    deleted = delete_scan(scan_id, db_path=app.config['DATABASE_PATH'])
    return jsonify({'success': deleted})


@app.route('/api/history/clear', methods=['POST'])
def api_clear_history():
    """Clear all history records."""
    clear_all_scans(db_path=app.config['DATABASE_PATH'])
    return jsonify({'success': True})


@app.route('/export/history/csv')
def export_csv():
    """Export scan history as downloadable CSV file."""
    scans = get_recent_scans(limit=1000, db_path=app.config['DATABASE_PATH'])
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['Scan ID', 'Timestamp', 'Target URL', 'Source', 'Model', 'Verdict', 'Risk Score', 'ML Probability', 'Latency (ms)'])
    for s in scans:
        writer.writerow([s['id'], s['timestamp'], s['target_url'], s['source_type'], s['model_name'], s['verdict'], s['risk_score'], s['ml_probability'], s['response_time_ms']])

    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=phishing_scan_history.csv"}
    )


@app.route('/export/history/json')
def export_json():
    """Export scan history as downloadable JSON file."""
    scans = get_recent_scans(limit=1000, db_path=app.config['DATABASE_PATH'])
    return Response(
        json.dumps(scans, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=phishing_scan_history.json"}
    )


if __name__ == '__main__':
    print("================================================================")
    print("   AI PHISHING DETECTION SYSTEM - FULL-STACK ENGINE ACTIVATED   ")
    print("   Access Web Application at: http://127.0.0.1:5000            ")
    print("================================================================")
    app.run(host='0.0.0.0', port=5000, debug=False)
