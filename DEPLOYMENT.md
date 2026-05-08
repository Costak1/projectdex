# Portainer Deployment Notes

## Recommended layout
Put this project in a Git repository and deploy it from Portainer Stacks using the compose file path:
- `portainer-stack.yml`

Portainer supports stack deployment from a Git repository and reads the compose file from the path you specify in the stack configuration.

## Steps
1. Push this project to GitHub, GitLab, Gitea, or Azure DevOps.
2. In Portainer, open **Stacks**.
3. Click **Add stack**.
4. Choose **Git repository**.
5. Set repository URL and branch.
6. Set compose path to `portainer-stack.yml`.
7. Deploy the stack.

## Persistent data
The `./data` volume stores:
- SQLite database
- users
- watchlist
- aliases
- digest settings
- generated XLSX/PDF reports

## Security actions after first start
- Log in with `admin / ChangeMe123!`
- Create a new admin account.
- Change your password.
- Disable or delete the bootstrap account after confirming another admin works.
- Configure SMTP and scheduled digest time.
