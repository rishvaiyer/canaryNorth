const enter = document.querySelector('#enter-lab');
const artwork = document.querySelector('.pen-art');
const finePrint = document.querySelector('.fine-print');
let inkClicks = 0;
const ready = () => { enter.disabled = false; enter.classList.add('ready'); };
if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) ready();
else setTimeout(ready, 4800);
enter.addEventListener('click', () => { window.location.href = '/threat-lab.html'; });
artwork.addEventListener('click', () => {
  inkClicks += 1;
  if (inkClicks === 3) finePrint.textContent = 'Hidden ink found. It is only a playful clue, not a password or security control.';
});
