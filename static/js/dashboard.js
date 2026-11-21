// ===================================================================
// AI PHISHING DETECTION - DASHBOARD ANALYTICS CHART CONTROLLER
// ===================================================================

let verdictChart = null;
let riskDistChart = null;
let timelineChart = null;
let modelUsageChart = null;

document.addEventListener('DOMContentLoaded', () => {
    const rawDataElem = document.getElementById('analyticsData');
    if (rawDataElem) {
        try {
            const data = JSON.parse(rawDataElem.textContent);
            renderDashboardCharts(data);
        } catch (e) {
            console.error('Error parsing initial analytics data:', e);
        }
    }

    const refreshBtn = document.getElementById('refreshDashboardBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', async () => {
            refreshBtn.disabled = true;
            refreshBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-1"></i> Updating...';
            try {
                const res = await fetch('/api/analytics');
                const data = await res.json();
                updateKpis(data);
                renderDashboardCharts(data);
            } catch (err) {
                console.error('Failed to refresh dashboard data:', err);
            } finally {
                refreshBtn.disabled = false;
                refreshBtn.innerHTML = '<i class="fa-solid fa-arrows-rotate me-1"></i> Refresh Live Data';
            }
        });
    }
});

function updateKpis(data) {
    document.getElementById('kpiTotal').innerText = data.total_scans;
    document.getElementById('kpiPhishing').innerText = data.phishing_count;
    document.getElementById('kpiSafe').innerText = data.safe_count;
    document.getElementById('kpiAvgScore').innerText = data.avg_risk_score;
    document.getElementById('kpiLatency').innerText = `${data.avg_latency_ms} ms`;
}

function renderDashboardCharts(data) {
    // 1. Verdict Doughnut Chart
    const vCtx = document.getElementById('verdictChartCanvas');
    if (vCtx) {
        if (verdictChart) verdictChart.destroy();
        const vData = data.verdict_distribution || { 'Phishing': 0, 'Legitimate': 0 };
        verdictChart = new Chart(vCtx, {
            type: 'doughnut',
            data: {
                labels: ['Phishing (High Risk)', 'Legitimate (Safe)'],
                datasets: [{
                    data: [vData['Phishing'] || 0, vData['Legitimate'] || 0],
                    backgroundColor: [
                        'rgba(239, 68, 68, 0.85)',
                        'rgba(16, 185, 129, 0.85)'
                    ],
                    borderColor: '#111827',
                    borderWidth: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#9ca3af', font: { family: 'Inter', size: 11 } }
                    }
                },
                cutout: '65%'
            }
        });
    }

    // 2. Risk Distribution Histogram
    const rCtx = document.getElementById('riskDistChartCanvas');
    if (rCtx) {
        if (riskDistChart) riskDistChart.destroy();
        const rData = data.risk_distribution || [0, 0, 0, 0, 0];
        riskDistChart = new Chart(rCtx, {
            type: 'bar',
            data: {
                labels: ['0-20 (Very Low)', '21-40 (Low)', '41-60 (Medium)', '61-80 (Elevated)', '81-100 (Critical)'],
                datasets: [{
                    label: 'Scan Frequency',
                    data: rData,
                    backgroundColor: [
                        'rgba(16, 185, 129, 0.75)',
                        'rgba(52, 211, 153, 0.75)',
                        'rgba(245, 158, 11, 0.75)',
                        'rgba(249, 115, 22, 0.75)',
                        'rgba(239, 68, 68, 0.85)'
                    ],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#9ca3af', font: { size: 10 } }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#9ca3af', precision: 0 }
                    }
                }
            }
        });
    }

    // 3. Timeline Trends
    const tCtx = document.getElementById('timelineChartCanvas');
    if (tCtx) {
        if (timelineChart) timelineChart.destroy();
        const tData = data.timeline || { dates: [], total: [], phishing: [] };
        timelineChart = new Chart(tCtx, {
            type: 'line',
            data: {
                labels: tData.dates.length ? tData.dates : ['Today'],
                datasets: [
                    {
                        label: 'Total Scans',
                        data: tData.total.length ? tData.total : [data.total_scans],
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.12)',
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2
                    },
                    {
                        label: 'Phishing Detected',
                        data: tData.phishing.length ? tData.phishing : [data.phishing_count],
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.12)',
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { color: '#9ca3af' }
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#9ca3af' }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#9ca3af', precision: 0 }
                    }
                }
            }
        });
    }

    // 4. Algorithm Utilization Share
    const mCtx = document.getElementById('modelUsageChartCanvas');
    if (mCtx) {
        if (modelUsageChart) modelUsageChart.destroy();
        const mUsage = data.model_usage || {};
        const labels = Object.keys(mUsage);
        const counts = Object.values(mUsage);

        modelUsageChart = new Chart(mCtx, {
            type: 'bar',
            data: {
                labels: labels.length ? labels : ['Ensemble'],
                datasets: [{
                    label: 'Inferences',
                    data: counts.length ? counts : [data.total_scans],
                    backgroundColor: 'rgba(139, 92, 246, 0.75)',
                    borderRadius: 6
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#9ca3af', precision: 0 }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#e5e7eb', font: { size: 10 } }
                    }
                }
            }
        });
    }
}
