// offline.js

// Function to check if the browser is online
function isOnline() {
    return navigator.onLine;
}

// Function to generate a unique ID for offline submissions
function generateUniqueId() {
    return 'offline_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

// Function to save form data to localStorage
function saveFormDataLocally(formData) {
    const formDataObj = {};
    formData.forEach((value, key) => {
        formDataObj[key] = value;
    });

    // Add a unique ID and timestamp
    formDataObj.id = generateUniqueId();
    formDataObj.timestamp = new Date().toISOString();

    // Retrieve existing offline submissions or initialize an empty array
    let offlineSubmissions = JSON.parse(localStorage.getItem('offlineSubmissions') || '[]');
    offlineSubmissions.push(formDataObj);
    localStorage.setItem('offlineSubmissions', JSON.stringify(offlineSubmissions));

    console.log('Form data saved to localStorage:', formDataObj);
}

// Function to sync offline submissions to the server
function syncOfflineSubmissions() {
    let offlineSubmissions = JSON.parse(localStorage.getItem('offlineSubmissions') || '[]');
    if (offlineSubmissions.length === 0) {
        console.log('No offline submissions to sync.');
        return;
    }

    console.log('Attempting to sync offline submissions:', offlineSubmissions);

    offlineSubmissions.forEach((submission, index) => {
        const formData = new FormData();
        Object.entries(submission).forEach(([key, value]) => {
            if (key !== 'id' && key !== 'timestamp') {
                formData.append(key, value);
            }
        });

        fetch(window.location.href, {
            method: 'POST',
            body: formData,
            headers: {
                'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
            }
        })
        .then(response => {
            if (response.ok) {
                console.log(`Successfully synced submission ${submission.id}`);
                // Remove the synced submission
                offlineSubmissions.splice(index, 1);
                localStorage.setItem('offlineSubmissions', JSON.stringify(offlineSubmissions));
                // Update UI to reflect successful sync
                showSyncSuccessMessage(submission.id);
            } else {
                console.error(`Failed to sync submission ${submission.id}`);
            }
        })
        .catch(error => {
            console.error(`Error syncing submission ${submission.id}:`, error);
        });
    });
}

// Function to show sync success message
function showSyncSuccessMessage(id) {
    const popup = document.createElement('div');
    popup.className = 'alert-popup';
    popup.innerHTML = `
        <div class="alert-content">
            <i class="fas fa-check-circle"></i>
            <h3>Sync Success</h3>
            <p>Offline submission ${id} has been synced to the server.</p>
            <button onclick="this.parentElement.parentElement.remove()">OK</button>
        </div>
    `;
    document.body.appendChild(popup);
    popup.style.display = 'block';
}

// Function to show offline save message
function showOfflineSaveMessage() {
    const popup = document.createElement('div');
    popup.className = 'alert-popup';
    popup.innerHTML = `
        <div class="alert-content">
            <i class="fas fa-info-circle"></i>
            <h3>Offline Mode</h3>
            <p>Your submission has been saved locally and will sync when internet is available.</p>
            <button onclick="this.parentElement.parentElement.remove()">OK</button>
        </div>
    `;
    document.body.appendChild(popup);
    popup.style.display = 'block';
}

// Initialize event listeners for online/offline events
window.addEventListener('online', () => {
    console.log('Internet connection restored. Attempting to sync offline submissions...');
    syncOfflineSubmissions();
});

window.addEventListener('offline', () => {
    console.log('Internet connection lost. Submissions will be saved locally.');
});

// Export functions for use in the main script
window.offlineUtils = {
    isOnline,
    saveFormDataLocally,
    syncOfflineSubmissions,
    showOfflineSaveMessage
};