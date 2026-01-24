// register.js
console.log('Register script loaded!');

/**
 * Validates a Portuguese NIF (Número de Identificação Fiscal)
 * @param {string} nif - The NIF to validate (9 digits)
 * @returns {boolean} - True if valid, false otherwise
 */
function isValidNIF(nif) {
  // Must be exactly 9 digits
  if (!/^\d{9}$/.test(nif)) {
    return false;
  }

  // First digit cannot be 0 or 4
  const firstDigit = parseInt(nif.charAt(0), 10);
  if (firstDigit === 0 || firstDigit === 4) {
    return false;
  }

  // Calculate checksum using modulo 11
  let sum = 0;
  for (let i = 0; i < 8; i++) {
    sum += parseInt(nif.charAt(i), 10) * (9 - i);
  }

  const checkDigit = 11 - (sum % 11);
  const expectedDigit = checkDigit >= 10 ? 0 : checkDigit;
  const actualDigit = parseInt(nif.charAt(8), 10);

  return expectedDigit === actualDigit;
}

async function handleRegister(event) {
  console.log('handleRegister called!');

  if (event) {
    event.preventDefault();
  }

  // Get DOM elements
  const nomeField = document.getElementById('regNome');
  const nifField = document.getElementById('regNif');
  const emailField = document.getElementById('regEmail');
  const passwordField = document.getElementById('regPassword');
  const confirmField = document.getElementById('regConfirmPassword');
  const statusDiv = document.getElementById('keyGenStatus');
  const btn = document.getElementById('registerBtn');

  const nome = nomeField?.value?.trim();
  const nif = nifField?.value?.trim();
  const email = emailField?.value?.trim();

  console.log('Fields:', {
    nome: nome,
    nif: nif,
    email: email,
    password: passwordField?.value ? '***' : 'empty',
    confirm: confirmField?.value ? '***' : 'empty'
  });

  // Client-side Validation
  if (!nome || nome.length < 3) {
    showAlert('O nome deve ter pelo menos 3 caracteres.', 'danger');
    return;
  }

  if (!nif || nif.length !== 9) {
    showAlert('O NIF deve ter exatamente 9 digitos.', 'danger');
    return;
  }

  if (!isValidNIF(nif)) {
    showAlert('NIF invalido. Verifique o numero introduzido.', 'danger');
    return;
  }

  if (!email || !email.match(/^[A-Za-z0-9+_.-]+@(.+)$/)) {
    showAlert('Email invalido.', 'danger');
    return;
  }

  if (passwordField.value !== confirmField.value) {
    showAlert('As passwords nao coincidem!', 'danger');
    return;
  }

  if (passwordField.value.length < 8) {
    showAlert('A password deve ter pelo menos 8 caracteres.', 'danger');
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
        nif: nif,
        nome: nome,
        email: email,
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
      localStorage.setItem('userId', nif);
      localStorage.setItem('userName', nome);
      localStorage.setItem('userEmail', email);

      showAlert('Sucesso! A redirecionar para login...', 'success');
      setTimeout(() => window.location.href = '/login', 2000);
    } else {
      const errorData = await response.json();
      showAlert(errorData.error || 'Registo falhou no servidor.', 'danger');
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