# Shared Configuration

This repository provides common runtime configuration files and Linux support binaries for services in the Transaction Processing platform. Applications load these files from `/home/txnproc/config` and combine them with application-specific configuration and environment variables.

## Repository contents

- `config/appsettings.json` — shared baseline settings.
- `config/appsettings.staging.json` — staging environment overrides.
- `config/appsettings.production.json` — production environment overrides.
- `syncfusion/QtBinariesLinux/` — Qt and related Linux libraries used by services that need Linux PDF or document rendering support.
- `Dockerfile` — builds the shared ASP.NET runtime image and copies the configuration and Linux binaries into it.

The configuration files use the .NET configuration JSON format. Comments are supported by the .NET configuration provider.

## Configuration files

The baseline file contains common settings for logging, service endpoints, EventStore, database connections, security, and gRPC retry behavior. Values in the environment-specific files override matching baseline values when those files are loaded after `appsettings.json`.

The shared files are defaults. Each service may add its own `appsettings*.json` files and configuration sources. Environment variables are commonly used for deployment-specific values and take precedence when added after JSON configuration. For example, the environment variable `AppSettings__ClientSecret` maps to `AppSettings:ClientSecret`.

Do not put production credentials or other secrets in committed configuration. Supply them through the deployment's secret management or environment-variable mechanism, and use service-specific overrides for values that differ between applications.

## Local use

To build the Linux runtime image from the repository root:

```sh
docker build --file Dockerfile --tag txnprocbase:local .
```

The image uses the ASP.NET runtime base image declared in `Dockerfile` and places the shared files under `/home/txnproc/`. The consuming application image or runtime is responsible for starting the application.

## Release and deployment

The GitHub Actions pull-request workflow builds the Docker image. Publishing a GitHub release builds and publishes the Linux image and packages the contents of `config/` as `sharedconfig.zip`. For non-prerelease releases, the release workflow deploys that package to `C:\home\txnproc\config` on the staging server and then the production server.

The release workflow requires Docker Hub credentials and configured staging and production Windows runners/environments. Check those workflow settings before relying on an automated release or deployment.
