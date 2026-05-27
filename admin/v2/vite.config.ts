import { defineConfig } from "vite";
import preact from "@preact/preset-vite";

const adminBackend = process.env.SFTPGUY_ADMIN_BACKEND || "http://127.0.0.1:9977";

export default defineConfig({
  base: "/admin/v2/",
  plugins: [preact()],
  server: {
    proxy: {
      "/admin/api": adminBackend,
      "/admin/explorer": adminBackend
    }
  },
  build: {
    sourcemap: false,
    manifest: true,
    rollupOptions: {
      output: {
        entryFileNames: "assets/[name]-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]"
      }
    }
  }
});
