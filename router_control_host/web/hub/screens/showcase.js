import { createComponentShowcase } from '../components/index.js';
import { createStateShowcase, createProgressPanel } from '../core/states.js';
export const meta = {
  id: 'dev-showcase',
  title: 'Витрина компонентов',
  iconName: 'overview',
};

/** @param {HTMLElement} container */
export function render(container) {
  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }

  const screen = document.createElement('div');
  screen.className = 'hub-screen hub-showcase-screen';

  const header = document.createElement('header');
  header.className = 'hub-screen__header';
  const h1 = document.createElement('h1');
  h1.className = 'hub-screen__title';
  h1.textContent = 'Витрина компонентов (служебный экран)';
  header.appendChild(h1);
  screen.appendChild(header);

  screen.appendChild(createComponentShowcase());
  screen.appendChild(createStateShowcase());

  const progressDemo = document.createElement('section');
  progressDemo.className = 'hub-showcase__section';
  const progressHeading = document.createElement('h2');
  progressHeading.className = 'hub-showcase__title';
  progressHeading.textContent = 'Панель прогресса';
  progressDemo.appendChild(progressHeading);

  const progressPanel = createProgressPanel({
    mode: 'indeterminate',
    label: 'Пример длительной операции',
    elapsedMs: 4200,
    expectedMs: 15000,
  });
  progressDemo.appendChild(progressPanel);

  const progressDeterminate = createProgressPanel({
    mode: 'determinate',
    label: 'Determinate (45%)',
    progress: 0.45,
  });
  progressDemo.appendChild(progressDeterminate);
  screen.appendChild(progressDemo);

  container.appendChild(screen);
}