// ===================================================================
// AI PHISHING DETECTION - MODEL BENCHMARK CHART CONTROLLER
// ===================================================================

document.addEventListener('DOMContentLoaded', () => {
    const rawDataElem = document.getElementById('modelMetricsData');
    if (!rawDataElem) return;

    try {
        const metrics = JSON.parse(rawDataElem.textContent);
        renderComparisonCharts(metrics);
    } catch (e) {
        console.error('Failed to parse model metrics data:', e);
    }
});

function renderComparisonCharts(metrics) {
    const models = metrics.models || {};
    const modelNames = Object.keys(models);

    // 1. Radar Chart across 5 metrics
    const radarCtx = document.getElementById('modelRadarChart');
    if (radarCtx && modelNames.length > 0) {
        const colors = [
            'rgba(6, 182, 212, 0.7)',
            'rgba(139, 92, 246, 0.7)',
            'rgba(239, 68, 68, 0.7)',
            'rgba(16, 185, 129, 0.7)',
            'rgba(245, 158, 11, 0.7)',
            'rgba(59, 130, 246, 0.7)'
        ];

        const datasets = modelNames.map((name, idx) => {
            const m = models[name];
            const c = colors[idx % colors.length];
            return {
                label: name,
                data: [m.accuracy, m.precision, m.recall, m.f1_score, m.roc_auc],
                borderColor: c,
                backgroundColor: c.replace('0.7', '0.15'),
                pointBackgroundColor: c,
                borderWidth: 2
            };
        });

        new Chart(radarCtx, {
            type: 'radar',
            data: {
                labels: ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC'],
                datasets: datasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#9ca3af', font: { size: 10 } }
                    }
                },
                scales: {
                    r: {
                        angleLines: { color: 'rgba(255, 255, 255, 0.1)' },
                        grid: { color: 'rgba(255, 255, 255, 0.08)' },
                        pointLabels: { color: '#e5e7eb', font: { size: 11, weight: 'bold' } },
                        ticks: {
                            color: '#9ca3af',
                            backdropColor: 'transparent',
                            min: 0.8,
                            max: 1.0
                        }
                    }
                }
            }
        });
    }

    // 2. Bar Chart: Accuracy vs F1-Score
    const barCtx = document.getElementById('modelBarChart');
    if (barCtx && modelNames.length > 0) {
        const accuracies = modelNames.map(n => models[n].accuracy);
        const f1s = modelNames.map(n => models[n].f1_score);

        new Chart(barCtx, {
            type: 'bar',
            data: {
                labels: modelNames,
                datasets: [
                    {
                        label: 'Accuracy',
                        data: accuracies,
                        backgroundColor: 'rgba(6, 182, 212, 0.8)',
                        borderRadius: 4
                    },
                    {
                        label: 'F1-Score',
                        data: f1s,
                        backgroundColor: 'rgba(139, 92, 246, 0.8)',
                        borderRadius: 4
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
                        grid: { display: false },
                        ticks: { color: '#9ca3af', font: { size: 10 } }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#9ca3af' },
                        min: 0.85,
                        max: 1.02
                    }
                }
            }
        });
    }
}
