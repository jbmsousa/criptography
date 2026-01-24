// login.js - Key checking only (Wicket handles form submission)
console.log('Login script loaded');

document.addEventListener('DOMContentLoaded', function() {
    // Clear any stale auth token when visiting login page
    localStorage.removeItem('authToken');
    console.log('Cleared auth token, checking for stored keys...');

    // Check if private keys exist in localStorage
    const ecdhKey = localStorage.getItem('ecdhPrivateKey');
    const rsaKey = localStorage.getItem('rsaPrivateKey');
    const storedUserId = localStorage.getItem('userId');

    const keyWarning = document.getElementById('keyWarning');
    const userIdField = document.getElementById('userId');

    if (!ecdhKey || !rsaKey) {
        console.warn('No private keys found in localStorage');
        if (keyWarning) {
            keyWarning.classList.remove('d-none');
            keyWarning.innerHTML = '<i class="bi bi-exclamation-triangle"></i> ' +
                '<strong>Warning:</strong> No encryption keys found in this browser. ' +
                'You must use the same browser where you registered, or <a href="/register">register a new account</a>.';
        }
    } else {
        console.log('Private keys found for user:', storedUserId);
        if (keyWarning) {
            keyWarning.classList.add('d-none');
        }
        // Pre-fill the userId if we have stored keys
        if (userIdField && storedUserId) {
            userIdField.value = storedUserId;
        }
    }
});

// Utility function for showing alerts (if needed by other scripts)
function showAlert(message, type) {
    const container = document.getElementById('alertContainer');
    if (container) {
        container.innerHTML =
            '<div class="alert alert-' + type + ' alert-dismissible fade show">' +
                message +
                '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>' +
            '</div>';
    }
}
