/**
 * crypto-lab-noise-pipe — main entry point
 * Interactive demo of the Noise Protocol Framework
 */

import { initUI, renderPatternComparison, renderWireGuardPanel } from './ui';
import '../styles/main.css';

document.addEventListener('DOMContentLoaded', () => {
  initUI();
  renderPatternComparison();
  renderWireGuardPanel();
});
