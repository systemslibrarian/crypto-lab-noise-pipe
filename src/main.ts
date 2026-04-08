/**
 * crypto-lab-noise-pipe — main entry point
 * Interactive demo of the Noise Protocol Framework
 */

import { initUI, renderPatternComparison, renderWireGuardPanel } from './ui';
import '../styles/main.css';

function setupThemeToggle(): void {
  const toggle = document.getElementById('theme-toggle') as HTMLButtonElement;
  if (!toggle) return;

  const theme = document.documentElement.getAttribute('data-theme') ?? 'dark';
  toggle.textContent = theme === 'dark' ? '🌙' : '☀️';
  toggle.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');

  toggle.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    toggle.textContent = next === 'dark' ? '🌙' : '☀️';
    toggle.setAttribute('aria-label', next === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  });
}

document.addEventListener('DOMContentLoaded', () => {
  setupThemeToggle();
  initUI();
  renderPatternComparison();
  renderWireGuardPanel();
});
