export function createInteractionFeedback() {
  let region = document.querySelector('#interaction-feedback');
  if (!region) {
    region = document.createElement('div');
    region.id = 'interaction-feedback';
    region.className = 'interaction-feedback';
    region.setAttribute('role', 'status');
    region.setAttribute('aria-live', 'polite');
    region.setAttribute('aria-atomic', 'true');
    document.body.append(region);
  }

  let hideTimer;
  return function announceInteraction(message, tone = 'info') {
    window.clearTimeout(hideTimer);
    region.classList.remove('is-visible');
    region.dataset.tone = tone;
    region.textContent = message;
    window.requestAnimationFrame(() => region.classList.add('is-visible'));
    hideTimer = window.setTimeout(() => region.classList.remove('is-visible'), 3200);
  };
}
