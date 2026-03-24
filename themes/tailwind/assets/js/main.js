document.addEventListener('DOMContentLoaded', () => {
	const themeButton = document.getElementById('theme-toggle');
	const prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
	const root = document.documentElement;

		function applyTheme(mode) {
			if (mode === 'dark') root.classList.add('dark'); else root.classList.remove('dark');
			root.setAttribute('data-theme', mode);
		}

	function currentStored() { try { return localStorage.getItem('theme'); } catch (e) { return null; } }
	function storeTheme(v) { try { localStorage.setItem('theme', v); } catch (e) {} }
	function systemPref() { return prefersDark.matches ? 'dark' : 'light'; }

	applyTheme(currentStored() || systemPref());

	if (themeButton) {
		themeButton.setAttribute('aria-pressed', root.classList.contains('dark').toString());
		themeButton.addEventListener('click', () => {
			const next = root.classList.contains('dark') ? 'light' : 'dark';
			storeTheme(next);
			applyTheme(next);
			themeButton.setAttribute('aria-pressed', (next === 'dark').toString());
		});
	}

	prefersDark.addEventListener('change', (e) => {
		if (!currentStored()) {
			applyTheme(e.matches ? 'dark' : 'light');
		}
	});
});
