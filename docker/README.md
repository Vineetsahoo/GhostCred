# Docker

This directory contains containerization resources for GhostCred.

## Overview
GhostCred can be run purely as a CLI tool locally, but for CI pipelines, sidecar injection, or background scanning, it is best deployed as a Docker container. 

## Structure
- Contains Dockerfiles or Docker Compose configurations for running GhostCred in various environments.
- Note that the primary distroless production `Dockerfile` resides in the root of the repository, but auxiliary Docker configurations and deployment manifests belong here.
