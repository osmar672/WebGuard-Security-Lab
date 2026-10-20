import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // Keep the development server local; do not expose the security lab on the LAN by default.
  server: { host: '127.0.0.1', proxy: { '/api': { target: 'http://127.0.0.1:8000', changeOrigin: false } } },
  preview: { host: '127.0.0.1', proxy: { '/api': { target: 'http://127.0.0.1:8000', changeOrigin: false } } },
});
