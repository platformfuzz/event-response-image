# event-response-image

Go web app for event CRUD against FastSchema. Docker image + Compose for local dev.

## Prerequisites

- **Go:** 1.21+ (for `go run` / `go build`)
- **Docker:** for image build and Compose (optional)

FastSchema must expose an **event** content schema with at least `title` (string) and `description` (string). Create it in the FastSchema dashboard if it does not exist. The list page shows a clear message if the schema or auth is missing.

## Run locally (Go)

Point at an existing FastSchema instance:

```bash
export FASTSCHEMA_URL=http://localhost:8000   # optional, default
# Optional: for API auth
export FASTSCHEMA_ADMIN_USER=admin
export FASTSCHEMA_ADMIN_PASS=changeme

go run .
```

Open <http://localhost:8080>. Use **New event** to create, **Edit** / **Delete** from the list.

## Run with Docker Compose

From the repo root:

```bash
cp .env.example .env
# Edit .env and set ADMIN_USER / ADMIN_PASS if you want API auth

docker compose up --build
```

- **Web app:** <http://localhost:8080>
- **FastSchema dashboard:** <http://localhost:8000/dash>

Compose starts the **official FastSchema image** (`ghcr.io/fastschema/fastschema:latest`) and builds only the **web app** image from this repo. Optional: set `ADMIN_USER` and `ADMIN_PASS` in `.env` so FastSchema creates an admin user and the web app can authenticate.

## Environment variables

| Variable                  | Default                 | Description                                  |
|---------------------------|-------------------------|----------------------------------------------|
| `FASTSCHEMA_URL`          | `http://localhost:8000` | FastSchema API base URL                      |
| `PORT`                    | `8080`                  | Port the web app listens on                  |
| `FASTSCHEMA_ADMIN_USER`   | (none)                  | Admin username for FastSchema API auth       |
| `FASTSCHEMA_ADMIN_PASS`   | (none)                  | Admin password for FastSchema API auth       |

## Build Docker image

Build the web image only (e.g. for ECS, Kubernetes, or your own deployment):

```bash
docker build -t event-response-image:latest .
```

Push to your registry and use the image URL in your deployment config. The app expects `FASTSCHEMA_URL` (and optionally `FASTSCHEMA_ADMIN_USER` / `FASTSCHEMA_ADMIN_PASS`) to be set at runtime.
