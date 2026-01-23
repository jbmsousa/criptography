// login.js - Key checking only (Wicket handles form submission)
console.log('Login script loaded');

document.addEventListener('DOMContentLoaded', function() {
    console.log('Checking for stored keys...');

    // Check if private keys exist in localStorage
    const ecdhKey = localStorage.getItem('ecdhPrivateKey');
    const rsaKey = localStorage.getItem('rsaPrivateKey');
    const storedUserId = localStorage.getItem('userId');

    const keyWarning = document.getElementById('keyWarning');

    if (!ecdhKey || !rsaKey) {
        console.warn('No private keys found in localStorage');
        if (keyWarning) {
            keyWarning.classList.remove('d-none');
        }
    } else {
        console.log('Private keys found for user:', storedUserId);
        if (keyWarning) {
            keyWarning.classList.add('d-none');
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
