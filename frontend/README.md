# JOCKY console

React 19 + Vite front end for the JOCKY API. See the [project README](../README.md) for features and setup.

```bash
npm install
npm run dev      # http://localhost:5173, talks to http://localhost:8000
npm run build    # outputs dist/, which the API serves from /
npm run lint
```

`VITE_API_BASE_URL` overrides the API origin (see `.env.example`). Only `VITE_` variables reach the browser bundle; never put secrets in them.

Layout: `src/api` (client and token storage), `src/pages`, `src/components`, `src/lib.js` (shared constants and helpers), `src/index.css` (design tokens and styles).
