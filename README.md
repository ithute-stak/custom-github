# Custom GitHub

Local-first CI/CD and controlled deployment platform.

GitHub remains the source of truth for repositories. This project runs locally on the operator's PC, synchronizes selected GitHub repositories, executes CI pipelines locally, and only enables **Deploy Latest** for a commit whose required checks have passed.

## Core rule

Production VPS servers do not build source code. They receive pre-built, tested release artifacts/containers from the local control plane.

## MVP flow

1. Register a GitHub repository.
2. Sync/fetch its latest branch commit locally.
3. Run the local pipeline.
4. Mark the exact commit as green only when every required step passes.
5. Check target VPS CPU, memory, disk, and deployment locks.
6. Enable **Deploy Latest** only for the latest green artifact.
7. Deploy, health-check, retain the previous release, and support rollback.

The first implementation is being developed under `feature/control-plane-mvp`.
