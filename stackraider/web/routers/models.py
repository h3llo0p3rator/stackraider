from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from stackraider.graphql import model_manager, pull_jobs
from stackraider.web.config import settings
from stackraider.web.llm.shared import list_models, ollama_reachable

router = APIRouter(prefix="/api/models", tags=["models"])


class PullRequest(BaseModel):
    name: str
    ollama_host: str | None = None


@router.get("/status")
async def models_status(host: str | None = None):
    h = host or settings.ollama_host
    return {"reachable": ollama_reachable(h), "host": h}


@router.get("")
async def list_local_models(ollama_host: str | None = None):
    host = ollama_host or settings.ollama_host
    if not ollama_reachable(host):
        raise HTTPException(503, "Ollama is not reachable. Start Ollama and pull a model.")
    try:
        gql_models = await model_manager.list_models(host)
        return {"models": gql_models, "host": host}
    except Exception:
        return {"models": list_models(host), "host": host}


@router.get("/available")
async def list_available_models():
    return model_manager.get_recommended_models()


@router.get("/pulls")
async def list_pull_jobs():
    return [pull_jobs.job_to_dict(j) for j in pull_jobs.list_jobs()]


@router.get("/pulls/{job_id}")
async def get_pull_job(job_id: str):
    job = pull_jobs.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return pull_jobs.job_to_dict(job)


@router.post("/pull")
async def pull_model(body: PullRequest):
    host = body.ollama_host or settings.ollama_host
    try:
        job = await pull_jobs.start_pull(host, body.name)
        return pull_jobs.job_to_dict(job)
    except Exception as e:
        raise HTTPException(500, str(e)) from e


@router.delete("/{name:path}")
async def remove_model(name: str, ollama_host: str | None = None):
    host = ollama_host or settings.ollama_host
    try:
        await model_manager.delete_model(host, name)
        return {"deleted": name}
    except Exception as e:
        raise HTTPException(500, str(e)) from e
