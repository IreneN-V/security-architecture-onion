import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// base "./" keeps asset paths relative, so the build works on GitHub Pages
// under /security-architecture-onion/ without hardcoding the repo name.
export default defineConfig({
  plugins: [react()],
  base: "./",
});
