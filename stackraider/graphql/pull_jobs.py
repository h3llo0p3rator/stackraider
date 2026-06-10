import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from stackraider.graphql import model_manager

PullState = Literal["pending", "running", "complete", "error"]


@dataclass
class PullJob:
    id: str
    name: str
    host: str
    state: PullState = "pending"
    percent: float | None = None
    status: str = "queued"
    error: str | None = None
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None


_jobs: dict[str, PullJob] = {}
_lock = asyncio.Lock()


def list_jobs() -> list[PullJob]:
    return sorted(_jobs.values(), key=lambda j: j.started_at, reverse=True)


def get_job(job_id: str) -> PullJob | None:
    return _jobs.get(job_id)


def get_job_by_name(name: str) -> PullJob | None:
    for job in _jobs.values():
        if job.name == name and job.state in ("pending", "running"):
            return job
    return None


async def start_pull(host: str, name: str) -> PullJob:
    async with _lock:
        existing = get_job_by_name(name)
        if existing:
            return existing

        job = PullJob(id=str(uuid.uuid4())[:8], name=name, host=host)
        _jobs[job.id] = job

    asyncio.create_task(_run_pull(job.id))
    return job


async def _run_pull(job_id: str) -> None:
    job = _jobs.get(job_id)
    if not job:
        return

    job.state = "running"
    job.status = "starting"

    try:
        async for progress in model_manager.pull_model(job.host, job.name):
            job.percent = progress.get("percent")
            job.status = progress.get("status") or job.status
        job.state = "complete"
        job.status = "success"
        job.percent = 100.0
        job.finished_at = datetime.utcnow()
    except Exception as e:
        job.state = "error"
        job.error = str(e)
        job.status = "failed"
        job.finished_at = datetime.utcnow()


def job_to_dict(job: PullJob) -> dict:
    return {
        "id": job.id,
        "name": job.name,
        "host": job.host,
        "state": job.state,
        "percent": job.percent,
        "status": job.status,
        "error": job.error,
        "started_at": job.started_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }
