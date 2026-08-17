const status = document.querySelector('#gate-status');
status.textContent = 'Opening the unlocked synthetic lab now.';
window.setTimeout(() => window.location.replace('./dashboard.html'), 250);
