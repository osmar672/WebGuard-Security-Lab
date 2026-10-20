import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  // Vitest 2 may load its own Vite 5 types beside the Vite 6 app dependency.
  // The React plugin works at runtime; cast across the duplicate type-only boundary.
  plugins: [react() as never],
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    restoreMocks: true,
  },
});
