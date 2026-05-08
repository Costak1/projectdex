# Cyber Watch Suite

Cyber Watch Suite is a Docker-ready internal threat intelligence dashboard for Portainer.

## Included capabilities
- Login page with session-based authentication
- Admin-managed internal user creation
- Watchlist management
- The Hacker News RSS ingestion
- NVD CVE API 2.0 ingestion
- CISA KEV enrichment
- FIRST EPSS enrichment
- Manual and automatic refresh
- Email digest configuration and send-test action
- Report export to XLSX and PDF
- Docker and Portainer deployment files

## Default login
- Username: `admin`
- Password: `ChangeMe123!`

Change this immediately after first login by creating a new admin user and removing or disabling the default account in code or database.

## Portainer deployment
### Option 1: Upload as a stack
1. Put this folder in a Git repository or zip/extract it on the Docker host.
2. In Portainer, go to **Stacks**.
3. Choose **Add stack**.
4. Paste the contents of `docker-compose.yml` into the web editor, or point Portainer to the Git repository.
5. Deploy the stack.

### Option 2: Docker Compose locally
```bash
docker compose up -d --build
```

Then open:
- http://YOUR-HOST:8000

## Data persistence
The application stores:
- users
- watchlist
- digest settings
- generated reports

inside the mounted `./data` volume.

## Email digest
Use the UI to enter SMTP settings and send a test digest. The current build includes a manual send endpoint and can be extended to a scheduled daily digest with cron or APScheduler.

## Report export
- XLSX export: `/report/xlsx`
- PDF export: `/report/pdf`

## Notes
- The Hacker News is pulled via RSS XML.
- NVD is pulled via the published CVE 2.0 API endpoint.
- CISA KEV is pulled via the published JSON feed.
- FIRST EPSS is pulled via the public EPSS API.
