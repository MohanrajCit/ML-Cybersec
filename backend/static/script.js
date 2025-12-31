document.addEventListener('DOMContentLoaded', () => {
    const descInput = document.getElementById('descInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const resultGrid = document.getElementById('resultGrid');
    const resultsContainer = document.getElementById('resultsContainer');
    const fetchLatestBtn = document.getElementById('fetchLatestBtn');
    const latestList = document.getElementById('latestList');

    // Analyze Single Description
    analyzeBtn.addEventListener('click', async () => {
        const description = descInput.value.trim();
        if (!description) {
            alert('Please enter a description');
            return;
        }

        setLoading(analyzeBtn, true);
        
        try {
            const response = await fetch('/predict', {
                method: 'POST',
                body: JSON.stringify({ description }),
                headers: { 'Content-Type': 'application/json' }
            });
            const data = await response.json();
            
            showResults(data);
        } catch (error) {
            console.error(error);
            alert('Error analyzing description');
        } finally {
            setLoading(analyzeBtn, false);
        }
    });

    // Fetch Latest CVEs
    fetchLatestBtn.addEventListener('click', async () => {
        setLoading(fetchLatestBtn, true);
        latestList.innerHTML = '<div style="text-align:center; padding: 1rem; color: var(--text-secondary)">Loading latest CVEs from NVD...</div>';
        
        try {
            const response = await fetch('/predict/latest-cves');
            const data = await response.json();
            
            if (data.error) throw new Error(data.error);
            
            latestList.innerHTML = '';
            data.predictions.forEach(item => {
                latestList.appendChild(createCveItem(item));
            });
            
            if (data.predictions.length === 0) {
                latestList.innerHTML = '<div style="text-align:center; padding: 1rem;">No recent CVEs found.</div>';
            }

        } catch (error) {
            console.error(error);
            latestList.innerHTML = `<div style="text-align:center; padding: 1rem; color: var(--danger)">Error: ${error.message}</div>`;
        } finally {
            setLoading(fetchLatestBtn, false);
        }
    });

    function showResults(data) {
        resultGrid.classList.add('active');
        
        // Criticality
        const critTag = document.getElementById('critTag');
        critTag.textContent = data.is_critical ? 'CRITICAL RISK' : 'LOW RISK';
        critTag.className = `tag ${data.is_critical ? 'critical' : 'safe'}`;
        
        // Confidence
        document.getElementById('confValue').textContent = `${(data.classification_confidence * 100).toFixed(1)}%`;
        
        // Anomaly
        const anomTag = document.getElementById('anomTag');
        anomTag.textContent = data.is_anomalous ? 'ANOMALY DETECTED' : 'NORMAL PATTERN';
        anomTag.className = `tag ${data.is_anomalous ? 'anomaly' : 'normal'}`;
        
        // Score
        document.getElementById('scoreValue').textContent = data.anomaly_score.toFixed(4);
    }

    function createCveItem(data) {
        const div = document.createElement('div');
        div.className = 'cve-item';
        
        const isCritical = data.is_critical;
        const isAnomaly = data.is_anomalous;
        
        div.innerHTML = `
            <div class="cve-header">
                <span class="cve-id">${data.cve_id}</span>
                <div style="display:flex; gap: 0.5rem">
                    <span class="tag ${isCritical ? 'critical' : 'safe'}" style="font-size: 0.75rem">${isCritical ? 'CRITICAL' : 'LOW'}</span>
                    ${isAnomaly ? '<span class="tag anomaly" style="font-size: 0.75rem">ANOMALY</span>' : ''}
                </div>
            </div>
            <div class="cve-desc">${data.description_preview}</div>
        `;
        return div;
    }

    function setLoading(btn, isLoading) {
        if (isLoading) {
            btn.dataset.originalText = btn.textContent; // Store original
            // btn.textContent = 'Processing...'; 
            // Instead of text replacement, just add loader class
            btn.classList.add('btn-loading');
            btn.disabled = true;
        } else {
            // btn.textContent = btn.dataset.originalText;
            btn.classList.remove('btn-loading');
            btn.disabled = false;
        }
    }
});
