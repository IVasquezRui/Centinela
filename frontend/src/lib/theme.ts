export type Theme = "light" | "dark";

const STORAGE_KEY = "centinela-theme";

export function getInitialTheme(): Theme {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === "light" || stored === "dark") return stored;
  // CENTINELA es, por defecto, un panel de sala de monitoreo: oscuro es el
  // modo de origen, no una consecuencia de la preferencia del SO. La mayoría
  // de los sistemas reportan "light" de fábrica, así que respetar
  // prefers-color-scheme aquí haría que casi nadie viera el modo oscuro sin
  // buscarlo. El claro queda disponible con un clic, pero por elección.
  return "dark";
}

export function applyTheme(theme: Theme): void {
  document.documentElement.classList.toggle("dark", theme === "dark");
  localStorage.setItem(STORAGE_KEY, theme);
}
