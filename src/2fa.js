let currentUser = null;

export async function init2FA(userId) {
  currentUser = userId;
  
  const response = await fetch('/auth/generate-secret', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${localStorage.token}` }
  });
  
  const { qrCode, secret } = await response.json();
  
  document.getElementById('qr-container').innerHTML = `
    <img src="${qrCode}" alt="QR Code">
    <p>Secret: ${secret}</p>
  `;
  
  document.getElementById('2fa-modal').classList.remove('hidden');
}

export async function verify2FA() {
  const token = document.getElementById('2fa-code').value;
  
  const response = await fetch('/auth/verify-2fa', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${localStorage.token}`
    },
    body: JSON.stringify({ token })
  });
  
  const { verified } = await response.json();
  
  if (verified) {
    window.location.href = '/index.html';
  } else {
    document.getElementById('2fa-error').textContent = 'Invalid code';
  }
}
