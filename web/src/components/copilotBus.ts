type Listener = (text: string) => void;

/**
 * Lightweight event bus to drive the SOC Copilot from anywhere (the global
 * search, a view, a card). Supports multiple subscribers so the app can open
 * the Copilot and the Copilot can receive the prompt at the same time.
 */
const listeners = new Set<Listener>();

export const copilotBus = {
  subscribe(fn: Listener) {
    listeners.add(fn);
    return () => { listeners.delete(fn); };
  },
  ask(text: string) {
    listeners.forEach((fn) => fn(text));
  },
};
