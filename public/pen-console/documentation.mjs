const input = document.querySelector('#docs-search');
const result = document.querySelector('#search-result');
const empty = document.querySelector('#no-results');
const sections = [...document.querySelectorAll('.searchable')];

function filterGuide() {
  const query = input.value.trim().toLowerCase();
  let visible = 0;
  for (const section of sections) {
    const haystack = `${section.dataset.search || ''} ${section.textContent}`.toLowerCase();
    const matches = !query || haystack.includes(query);
    section.hidden = !matches;
    if (matches) visible += 1;
  }
  empty.hidden = visible !== 0;
  result.textContent = query ? `${visible} guide section${visible === 1 ? '' : 's'} found.` : 'Showing all guide sections.';
}

input.addEventListener('input', filterGuide);
