// ===================================================================
// AI PHISHING DETECTION - MAIN INTERACTION & CHART CONTROLLER
// ===================================================================

let shapChartInstance = null;

document.addEventListener('DOMContentLoaded', () => {
    initFormHandlers();
    initSampleButtons();
});

function initFormHandlers() {
    // 1. URL Scan Form
    const urlForm = document.getElementById('urlScanForm');
    if (urlForm) {
        urlForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const url = document.getElementById('targetUrl').value.trim();
            const model = document.getElementById('modelSelect').value;
            const enableContent = document.getElementById('enableContentScan').checked;

            if (!url) return;
            showLoading(true);

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url, model: model, enable_content: enableContent })
                });
                const result = await response.json();
                showLoading(false);

                if (!response.ok) {
                    alert(result.error || 'Failed to scan URL');
                    return;
                }
                renderResults(result);
            } catch (err) {
                showLoading(false);
                alert('Connection error while submitting scan.');
                console.error(err);
            }
        });
    }

    // 2. QR Code Form (Quishing)
    const qrForm = document.getElementById('qrScanForm');
    if (qrForm) {
        qrForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const fileInput = document.getElementById('qrFileInput');
            const model = document.getElementById('qrModelSelect').value;

            if (!fileInput.files.length) {
                alert('Please select a QR code image.');
                return;
            }

            const formData = new FormData();
            formData.append('qr_image', fileInput.files[0]);
            formData.append('model', model);

            showLoading(true);
            try {
                const response = await fetch('/api/scan-qr', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                showLoading(false);

                if (!response.ok) {
                    alert(result.error || 'Failed to scan QR code');
                    return;
                }

                if (result.is_url === false) {
                    alert(`QR Code Decoded: "${result.decoded_text}" (Not a URL)`);
                    return;
                }

                renderResults(result);
            } catch (err) {
                showLoading(false);
                alert('Connection error during QR scanning.');
                console.error(err);
            }
        });
    }

    // 3. Screenshot Similarity Form
    const visualForm = document.getElementById('visualScanForm');
    if (visualForm) {
        visualForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const fileInput = document.getElementById('screenshotFileInput');
            const domain = document.getElementById('screenshotDomain').value.trim();

            if (!fileInput.files.length || !domain) {
                alert('Please choose an image and provide the website domain.');
                return;
            }

            const formData = new FormData();
            formData.append('screenshot', fileInput.files[0]);
            formData.append('domain', domain);

            showLoading(true);
            try {
                const response = await fetch('/api/scan-screenshot', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                showLoading(false);

                if (!response.ok) {
                    alert(result.error || 'Failed to analyze screenshot');
                    return;
                }

                const v = result.visual_result;
                let msg = `Visual Analysis Results:\n\n`;
                msg += `Matched Brand: ${v.matched_brand || 'None'}\n`;
                msg += `Similarity Score: ${(v.similarity_score * 100).toFixed(1)}%\n`;
                msg += `Deceptive Impersonation: ${v.is_impersonation ? 'YES (CRITICAL)' : 'No'}\n`;
                msg += `Visual Threat Score: ${v.visual_risk_score}/100\n\n`;
                if (v.details.length) {
                    msg += `Details:\n- ` + v.details.join('\n- ');
                }
                alert(msg);
            } catch (err) {
                showLoading(false);
                alert('Visual analysis error.');
                console.error(err);
            }
        });
    }
}

function initSampleButtons() {
    document.querySelectorAll('.sample-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const urlInput = document.getElementById('targetUrl');
            if (urlInput) {
                urlInput.value = btn.getAttribute('data-url');
                document.getElementById('scanBtn').click();
            }
        });
    });
}

function showLoading(show) {
    const loading = document.getElementById('loadingState');
    const results = document.getElementById('resultsContainer');
    if (show) {
        loading.classList.remove('d-none');
        results.classList.add('d-none');
    } else {
        loading.classList.add('d-none');
    }
}

function renderResults(data) {
    const resultsContainer = document.getElementById('resultsContainer');
    resultsContainer.classList.remove('d-none');

    const isPhishing = data.verdict === 'PHISHING';
    const isSafe = (data.verdict === 'LEGITIMATE' || data.verdict === 'SAFE');

    // 0. Render Top Master Prominent Verdict Banner
    const masterBanner = document.getElementById('masterVerdictBanner');
    if (masterBanner) {
        if (isPhishing) {
            masterBanner.innerHTML = `
                <div class="verdict-banner-phishing d-flex align-items-center gap-3">
                    <div class="fs-1 text-danger"><i class="fa-solid fa-triangle-exclamation"></i></div>
                    <div>
                        <div class="badge bg-danger bg-opacity-25 text-danger border border-danger mb-1 px-3 py-1 fw-bold">HIGH RISK THREAT DETECTED</div>
                        <h2 class="fw-bold text-danger mb-1">VERDICT: PHISHING WEBSITE</h2>
                        <p class="text-light mb-0 small">CRITICAL WARNING: This target has been identified as a <strong>FRAUDULENT PHISHING SITE</strong>. It is designed to harvest credentials, passwords, or personal data. Do NOT proceed.</p>
                    </div>
                </div>
            `;
        } else {
            masterBanner.innerHTML = `
                <div class="verdict-banner-legitimate d-flex align-items-center gap-3">
                    <div class="fs-1 text-success"><i class="fa-solid fa-circle-check"></i></div>
                    <div>
                        <div class="badge bg-success bg-opacity-25 text-success border border-success mb-1 px-3 py-1 fw-bold">SAFE VERIFIED</div>
                        <h2 class="fw-bold text-success mb-1">VERDICT: LEGITIMATE WEBSITE</h2>
                        <p class="text-light mb-0 small">AUTHENTIC WEBSITE: This target has been analyzed across 24 lexical features, deep learning models, and content markers. It is classified as <strong>GENUINE &amp; LEGITIMATE</strong>.</p>
                    </div>
                </div>
            `;
        }
    }

    // 1. Text & Latency info
    document.getElementById('targetUrlDisplay').innerText = data.url;
    document.getElementById('latencyVal').innerText = data.latency_ms;
    document.getElementById('modelUsedVal').innerText = data.model_used;
    document.getElementById('riskScoreVal').innerText = data.risk_score;

    // 2. Verdict Badge & Card Glow
    const verdictBadge = document.getElementById('verdictBadge');
    if (isPhishing) {
        verdictBadge.innerHTML = '<i class="fa-solid fa-ban me-1"></i> PHISHING';
        verdictBadge.className = 'badge-verdict badge-danger';
    } else {
        verdictBadge.innerHTML = '<i class="fa-solid fa-circle-check me-1"></i> LEGITIMATE';
        verdictBadge.className = 'badge-verdict badge-safe';
    }

    // Update risk summary text
    const riskSummaryElem = document.getElementById('riskSummaryText');
    if (riskSummaryElem) {
        riskSummaryElem.innerHTML = `
            Status: <strong style="color: ${data.color}; font-size: 1.05rem;">${isPhishing ? 'PHISHING WEBSITE DETECTED' : 'LEGITIMATE WEBSITE (SAFE)'}</strong> &bull;
            Composite Threat Score: <strong class="text-white">${data.risk_score}/100</strong> &bull;
            Model Probability: <strong class="text-white">${data.breakdown.ml_score || 0}%</strong>
        `;
    }

    const bannerCard = document.getElementById('verdictBannerCard');
    bannerCard.style.boxShadow = `0 10px 30px ${data.color}25`;
    bannerCard.style.borderColor = `${data.color}60`;

    // 3. Breakdown scores
    const bd = data.breakdown || {};
    document.getElementById('scoreML').innerText = `${bd.ml_score || 0}%`;
    document.getElementById('scoreURL').innerText = `${bd.url_heuristic_score || 0}/100`;
    document.getElementById('scoreContent').innerText = bd.content_score !== null ? `${bd.content_score}/100` : 'N/A (Skipped)';
    document.getElementById('scoreVisual').innerText = bd.visual_score !== null ? `${bd.visual_score}/100` : '0/100';

    // 4. Draw Risk Gauge Canvas
    drawRiskGauge(data.risk_score, data.color);

    // 5. Render SHAP Chart
    renderShapChart(data.shap);

    // 6. Key Influencing Factors
    const factorsList = document.getElementById('shapFactorsList');
    factorsList.innerHTML = '';
    const topFactors = data.shap ? data.shap.top_phishing_factors : [];
    if (topFactors && topFactors.length > 0) {
        topFactors.forEach(f => {
            const item = document.createElement('div');
            item.className = 'd-flex justify-content-between align-items-center p-2 mb-1 rounded';
            item.style.background = 'rgba(239, 68, 68, 0.08)';
            item.style.borderLeft = '3px solid #ef4444';
            item.innerHTML = `
                <div>
                    <span class="text-white small fw-bold">${f.feature.replace(/_/g, ' ').toUpperCase()}</span>
                    <div class="text-secondary" style="font-size:0.75rem">${f.description}</div>
                </div>
                <span class="badge bg-danger bg-opacity-25 text-danger font-monospace">+${f.shap_value.toFixed(3)}</span>
            `;
            factorsList.appendChild(item);
        });
    } else {
        factorsList.innerHTML = '<div class="text-secondary small">No strong malicious push factors detected. Features align with benign standards.</div>';
    }

    // 7. Security Warnings
    const warningsList = document.getElementById('warningsList');
    warningsList.innerHTML = '';
    if (data.warnings && data.warnings.length > 0) {
        data.warnings.forEach(w => {
            const div = document.createElement('div');
            div.className = 'warning-item';
            div.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-danger"></i> <span>${w}</span>`;
            warningsList.appendChild(div);
        });
    } else {
        warningsList.innerHTML = '<div class="text-success small p-2"><i class="fa-solid fa-check-circle me-1"></i> No threat flags or heuristic anomalies triggered.</div>';
    }

    // 8. Prevention Tips
    const prevList = document.getElementById('preventionList');
    prevList.innerHTML = '';
    if (data.prevention_tips && data.prevention_tips.length > 0) {
        data.prevention_tips.forEach(t => {
            const div = document.createElement('div');
            div.className = 'advice-item';
            div.innerHTML = `<i class="fa-solid fa-shield-halved text-info"></i> <span>${t}</span>`;
            prevList.appendChild(div);
        });
    }

    // 9. Multi-Algorithm Agreement Row
    const modelsRow = document.getElementById('allModelsRow');
    modelsRow.innerHTML = '';
    const allProbs = data.all_model_probabilities || {};
    for (const [mName, prob] of Object.entries(allProbs)) {
        const col = document.createElement('div');
        col.className = 'col-md-4 col-sm-6';
        const pPct = Math.round(prob * 100);
        const pColor = pPct >= 70 ? '#ef4444' : (pPct >= 30 ? '#f59e0b' : '#10b981');
        col.innerHTML = `
            <div class="p-3 rounded h-100" style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-color);">
                <div class="d-flex justify-content-between align-items-center mb-1">
                    <span class="small fw-bold text-white">${mName}</span>
                    <span class="badge" style="background:${pColor}20; color:${pColor}; border:1px solid ${pColor}40">${pPct}%</span>
                </div>
                <div class="progress" style="height: 6px; background: rgba(255,255,255,0.08);">
                    <div class="progress-bar" role="progressbar" style="width: ${pPct}%; background-color: ${pColor};"></div>
                </div>
            </div>
        `;
        modelsRow.appendChild(col);
    }

    // 10. Populate Extracted Features Table
    const fBody = document.getElementById('featuresTableBody');
    fBody.innerHTML = '';
    const feats = data.features || {};
    for (const [k, v] of Object.entries(feats)) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td class="font-monospace text-info">${k}</td>
            <td class="fw-bold">${v}</td>
            <td class="text-secondary small">${getFeatureDesc(k)}</td>
        `;
        fBody.appendChild(tr);
    }

    // Smooth scroll down to results
    resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function drawRiskGauge(score, color) {
    const canvas = document.getElementById('riskGaugeCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = 68;

    ctx.clearRect(0, 0, width, height);

    // Background track circle
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0.75 * Math.PI, 2.25 * Math.PI, false);
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
    ctx.lineWidth = 10;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Foreground filled arc based on score (0 to 100)
    const startAngle = 0.75 * Math.PI;
    const totalAngle = 1.5 * Math.PI;
    const endAngle = startAngle + (score / 100.0) * totalAngle;

    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, startAngle, endAngle, false);
    ctx.strokeStyle = color;
    ctx.lineWidth = 10;
    ctx.lineCap = 'round';
    ctx.shadowBlur = 12;
    ctx.shadowColor = color;
    ctx.stroke();
    ctx.shadowBlur = 0;
}

function renderShapChart(shapData) {
    const canvas = document.getElementById('shapChartCanvas');
    if (!canvas || !shapData || !shapData.chart_data) return;

    if (shapChartInstance) {
        shapChartInstance.destroy();
    }

    const cData = shapData.chart_data;

    shapChartInstance = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: cData.labels,
            datasets: [{
                label: 'SHAP Value Contribution',
                data: cData.values,
                backgroundColor: cData.colors,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: (ctx) => ` Impact: ${ctx.parsed.x > 0 ? '+' : ''}${ctx.parsed.x.toFixed(4)} (${ctx.parsed.x > 0 ? 'Phishing' : 'Benign'})`
                    }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.06)' },
                    ticks: { color: '#9ca3af', font: { family: 'JetBrains Mono' } }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#e5e7eb', font: { size: 11 } }
                }
            }
        }
    });
}

function getFeatureDesc(name) {
    const descMap = {
        'url_length': 'Total characters in full URL',
        'domain_length': 'Length of target hostname',
        'is_ip': 'Binary flag: 1 if raw IP address is used',
        'count_dots': 'Count of dot (.) separators',
        'count_hyphens': 'Hyphens (-) in URL',
        'count_at': 'At (@) characters',
        'count_question': 'Query string questions (?)',
        'count_and': 'Parameter ampersands (&)',
        'count_equal': 'Parameter equals (=)',
        'count_slash': 'Forward slashes (/) path separators',
        'count_percent': 'Hex encoded symbols (%)',
        'count_digits': 'Count of numeric digits',
        'count_subdomains': 'Subdomain levels',
        'has_https': 'Encrypted protocol indicator',
        'https_in_domain': 'Deceptive https in hostname',
        'is_shortened': 'Known URL shortener service',
        'has_suspicious_keyword': 'Phishing sensitive keywords',
        'path_depth': 'Subdirectory depth count',
        'prefix_suffix_hyphen': 'Prefix/Suffix hyphen in domain',
        'entropy': 'Shannon character randomness',
        'domain_entropy': 'Domain entropy',
        'tld_risk': 'High risk top-level domain',
        'punycode': 'Punycode (xn--) or homographs',
        'special_char_ratio': 'Ratio of non-alphanumeric chars'
    };
    return descMap[name] || 'URL structural metric';
}
