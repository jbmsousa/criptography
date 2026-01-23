// register.js
console.log('Register script loaded!');

async function handleRegister(event) {
  console.log('handleRegister called!');

  if (event) {
    event.preventDefault();
  }

  // Get DOM elements
  const userIdField = document.getElementById('regUserId');
  const passwordField = document.getElementById('regPassword');
  const confirmField = document.getElementById('regConfirmPassword');
  const statusDiv = document.getElementById('keyGenStatus');
  const btn = document.getElementById('registerBtn');

  console.log('Fields:', {
    userId: userIdField?.value,
    password: passwordField?.value ? '***' : 'empty',
    confirm: confirmField?.value ? '***' : 'empty'
  });

  // Client-side Validation
  if (!userIdField.value || userIdField.value.trim().length < 3) {
    showAlert('User ID must be at least 3 characters.', 'danger');
    return;
  }

  if (passwordField.value !== confirmField.value) {
    showAlert('Passwords do not match!', 'danger');
    return;
  }

  if (passwordField.value.length < 8) {
    showAlert('Password must be at least 8 characters.', 'danger');
    return;
  }

  // UI Feedback
  statusDiv.classList.remove('d-none');
  btn.disabled = true;

  try {
    console.log('Generating keys...');

    // Generate ECDH (Encryption) and RSA (Signing) keys
    const ecdhPair = await window.crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveKey', 'deriveBits']
    );

    const rsaPair = await window.crypto.subtle.generateKey(
        {
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
    );

    console.log('Keys generated!');

    // Export Public Keys
    const ecdhPub = await window.crypto.subtle.exportKey('spki', ecdhPair.publicKey);
    const rsaPub = await window.crypto.subtle.exportKey('spki', rsaPair.publicKey);

    // Export Private Keys
    const ecdhPriv = await window.crypto.subtle.exportKey('pkcs8', ecdhPair.privateKey);
    const rsaPriv = await window.crypto.subtle.exportKey('pkcs8', rsaPair.privateKey);

    // Convert to Base64
    const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

    console.log('Sending to server...');

    // Send to Server
    const response = await fetch('/api/keys/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId: userIdField.value.trim(),
        password: passwordField.value,
        ecdhPublicKey: toB64(ecdhPub),
        rsaPublicKey: toB64(rsaPub)
      })
    });

    console.log('Response status:', response.status);

    if (response.ok) {
      // Store Private Keys Locally
      localStorage.setItem('ecdhPrivateKey', toB64(ecdhPriv));
      localStorage.setItem('rsaPrivateKey', toB64(rsaPriv));
      localStorage.setItem('userId', userIdField.value.trim());

      showAlert('Success! Redirecting to login...', 'success');
      setTimeout(() => window.location.href = '/login', 2000);
    } else {
      const errorData = await response.json();
      showAlert(errorData.error || 'Registration failed on server.', 'danger');
    }
  } catch (err) {
    console.error('Error:', err);
    showAlert('Cryptographic error: ' + err.message, 'danger');
  } finally {
    statusDiv.classList.add('d-none');
    btn.disabled = false;
  }
}

function showAlert(message, type) {
  const container = document.getElementById('alertContainer');
  container.innerHTML = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>`;
}

// Attach event listener
document.addEventListener('DOMContentLoaded', function() {
  console.log('DOM loaded, attaching event listener...');
  const form = document.getElementById('registerForm');
  if (form) {
    form.addEventListener('submit', handleRegister);
    console.log('Event listener attached!');
  } else {
    console.error('Form not found!');
  }
});