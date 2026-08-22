/* Runs before paint so the page never flashes the wrong theme.
   Kept as a same-origin file because the server sends script-src 'self',
   which blocks inline <script> blocks. */
(() => {
  const saved = localStorage.getItem('canarynorth-theme');
  const theme = saved === 'light' || saved === 'dark'
    ? saved
    : (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.dataset.theme = theme;
})();
