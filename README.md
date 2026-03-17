# ACE Mission Control

Cyberpunk AI command centre for the OpenClaw agent fleet.

## Local dev

```bash
npm install
npm start
# → http://localhost:3000
```

## Deploy to Railway

1. Push this repo to GitHub
2. Go to railway.app → New Project → Deploy from GitHub repo
3. Select this repo — Railway auto-detects Node and runs `npm start`
4. Done. Live URL provided instantly.

## Workflow

Edit `public/index.html` → git commit → git push → Railway redeploys in ~30s.

## Structure

```
ace-mission-control/
├── public/
│   └── index.html     ← The entire app lives here
├── server.js          ← Express static server
├── package.json
└── .gitignore
```
