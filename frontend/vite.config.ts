/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": { target: process.env.DFA_API_URL ?? "http://127.0.0.1:8000", changeOrigin: true } },
  },
  test: { environment: "jsdom", globals: true, setupFiles: ["./src/setupTests.ts"] },
});
