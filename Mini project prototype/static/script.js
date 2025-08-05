// Global variables for storing current state

// Get current device status 
async function updateStatus() { 
    try { 
        const response = await fetch('/api/current-status'); 
        const status = await response.json(); 
        
        if (response.ok) { 
            // Update UI elements 
            document.getElementById('motion-status').textContent = status.motion; 
            document.getElementById('light-level').textContent = status.light_level; 
            document.getElementById('light-state').textContent = status.light_state; 
            document.getElementById('fan-state').textContent = status.fan_state; 
            
            // Update toggle switches 
            document.getElementById('auto-mode').checked = status.auto_mode; 
        } 
    } catch (error) { 
        console.error('Error fetching status:', error); 
    } 
} 

// Control devices 
async function controlDevice(device, action, value = null) { 
    try { 
        const data = { device, action };
        if (value !== null) {
            data.value = value;
        }
        
        const response = await fetch('/api/device-control', { 
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' }, 
            body: JSON.stringify(data) 
        }); 
        
        if (response.ok) { 
            updateStatus(); // Refresh status 
            return await response.json(); // Return response data
        } 
    } catch (error) { 
        console.error('Error controlling device:', error); 
        return { error: 'Failed to control device' };
    } 
} 

// Update preferences 
async function updatePreferences() { 
    const prefs = { 
        motion_timeout: document.getElementById('timeout').value, 
        light_threshold: document.getElementById('threshold').value, 
        auto_mode: document.getElementById('auto-mode').checked 
    }; 
    
    try { 
        await fetch('/api/preferences', { 
            method: 'PUT', 
            headers: { 'Content-Type': 'application/json' }, 
            body: JSON.stringify(prefs) 
        }); 
        updateStatus(); // Refresh status 
    } catch (error) { 
        console.error('Error updating preferences:', error); 
    } 
} 

// Periodically update status 
setInterval(updateStatus, 5000); 
updateStatus(); // Initial load
let currentPreferences = null;
let updateInterval = null;

// Fetch and update sensor data
async function updateSensorData() {
    try {
        const response = await fetch('/api/sensor-data');
        const data = await response.json();
        
        if (data.length > 0) {
            const latest = data[0];
            
            // Update history table if it exists
            const tbody = document.getElementById('historyTableBody');
            if (tbody) {
                tbody.innerHTML = data.map(entry => `
                    <tr>
                        <td>${new Date(entry.timestamp).toLocaleString()}</td>
                        <td>${entry.motion_detected ? 'Yes' : 'No'}</td>
                        <td>${entry.light_level.toFixed(1)}%</td>
                        <td>${entry.device_status.toUpperCase()}</td>
                    </tr>
                `).join('');
            }
        }
    } catch (error) {
        console.error('Error fetching sensor data:', error);
    }
}

// Fetch and display user preferences
async function loadPreferences() {
    try {
        const response = await fetch('/api/preferences');
        currentPreferences = await response.json();
        
        // Update form values
        document.getElementById('motionTimeout').value = currentPreferences.motion_timeout;
        document.getElementById('lightThreshold').value = currentPreferences.light_threshold;
        document.getElementById('autoMode').checked = currentPreferences.auto_mode;
    } catch (error) {
        console.error('Error loading preferences:', error);
    }
}

// Save updated preferences
async function savePreferences(event) {
    event.preventDefault();
    
    const newPreferences = {
        motion_timeout: parseInt(document.getElementById('motionTimeout').value),
        light_threshold: parseFloat(document.getElementById('lightThreshold').value),
        auto_mode: document.getElementById('autoMode').checked
    };
    
    try {
        const response = await fetch('/api/preferences', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(newPreferences)
        });
        
        if (response.ok) {
            alert('Settings saved successfully!');
            currentPreferences = newPreferences;
        } else {
            alert('Failed to save settings. Please try again.');
        }
    } catch (error) {
        console.error('Error saving preferences:', error);
        alert('Error saving settings. Please check your connection.');
    }
}

// Simulate sensor data (for development)
async function simulateSensorData() {
    const mockData = {
        motion_detected: Math.random() > 0.5,
        light_level: Math.random() * 100,
        device_status: Math.random() > 0.3 ? 'on' : 'off'
    };
    
    try {
        await fetch('/api/sensor-data', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(mockData)
        });
    } catch (error) {
        console.error('Error simulating sensor data:', error);
    }
}

// Initialize the dashboard
function initializeDashboard() {
    // Load initial data
    loadPreferences();
    updateSensorData();
    
    // Set up form submission handler
    document.getElementById('settingsForm').addEventListener('submit', savePreferences);
    
    // Set up periodic updates
    updateInterval = setInterval(() => {
        simulateSensorData();
        updateSensorData();
    }, 5000); // Update every 5 seconds
}

// Start the dashboard when the page loads
window.addEventListener('load', initializeDashboard);

// Clean up when the page is closed
window.addEventListener('unload', () => {
    if (updateInterval) {
        clearInterval(updateInterval);
    }
});