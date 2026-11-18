# Sentinel

Sentinel is a standalone security-operations application. This repository contains the React web app only; it is separate from the predictive-analysis API repository and does not implement that API.

The app connects to two independently configurable services:

- The Sentinel API provides security overview, events, alerts, and audit history.
- The predictive-analysis API provides the ISO 31000 executive risk summary.

## Run locally

Requirements: Node.js 20.19+.

```powershell
Copy-Item .env.example .env
npm install
npm run dev
```

Vite serves the app at `http://localhost:5173`.

## Configure API services

Set these public frontend URLs in `.env`:

```dotenv
VITE_SENTINEL_API_BASE_URL=http://localhost:3001/api/v1
VITE_PREDICTIVE_API_BASE_URL=http://localhost:3000/api/v1
```

The Sentinel API must provide the `/security/overview`, `/security/events`, `/security/alerts`, and `/security/audit-log` routes. The separate predictive-analysis API must provide `/board/executive-summary`. Configure each service's CORS policy to allow the app origin. Do not put credentials or secrets in `VITE_*` variables; they are embedded in the browser bundle.

## Scripts

```powershell
npm run dev
npm run build
npm run preview
npm run lint
```

## Autoria e uso

**© 2026 J64D. Todos os direitos reservados sobre o código e os materiais originais deste painel.**

A publicação no GitHub serve à apresentação de portfólio. Nos termos da plataforma, o GitHub pode permitir que usuários visualizem e criem forks de repositórios públicos. Um fork não transfere a autoria nem concede autorização para usar este painel fora dos recursos e termos do GitHub, distribuir cópias independentes, incorporá-lo em outro produto ou explorá-lo comercialmente.

Qualquer utilização além do permitido pela plataforma — incluindo a venda deste painel ou de partes dele — requer autorização prévia e expressa de J64D. Dependências de terceiros continuam sujeitas às próprias licenças.
