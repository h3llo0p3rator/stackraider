"""Deprecated API aliases — use /api/code/* instead."""

from typing import Optional

from fastapi import APIRouter, Cookie, File, Response, UploadFile

from stackraider.web.routers import code
from stackraider.web.schemas.code import BurpConfigRequest, CodeAnalyzeRequest, ScanRequest

router = APIRouter(tags=["legacy"])


@router.post("/api/scan")
async def legacy_scan(
    scan_body: ScanRequest,
    response: Response,
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    return await code.run_scan(scan_body, response, stackraider_session, srcsniff_session)


@router.get("/api/scan/result")
async def legacy_scan_result(
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    return await code.get_scan_result(stackraider_session, srcsniff_session)


@router.get("/api/browse")
async def legacy_browse(path: Optional[str] = None, mode: str = "dirs", ext: Optional[str] = None):
    return await code.browse_directory(path, mode, ext)


@router.get("/api/burp/config")
async def legacy_burp_config(
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    return await code.get_burp_config(stackraider_session, srcsniff_session)


@router.post("/api/burp/config")
async def legacy_burp_set(
    config: BurpConfigRequest,
    response: Response,
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    return await code.set_burp_config(config, response, stackraider_session, srcsniff_session)


@router.post("/api/burp/upload")
async def legacy_burp_upload(
    response: Response,
    file: UploadFile = File(...),
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    return await code.upload_burp(response, file, stackraider_session, srcsniff_session)


@router.get("/api/burp/traffic")
async def legacy_burp_traffic(
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    return await code.get_burp_traffic(stackraider_session, srcsniff_session)


@router.post("/api/analyze")
async def legacy_analyze(
    analyze_body: CodeAnalyzeRequest,
    response: Response,
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    return await code.start_analysis(analyze_body, response, stackraider_session, srcsniff_session)


@router.get("/api/analyze/stream/{analysis_id}")
async def legacy_stream(analysis_id: str):
    return await code.stream_analysis(analysis_id)


@router.get("/api/analyze/{analysis_id}")
async def legacy_get(analysis_id: str):
    return await code.get_analysis(analysis_id)


@router.get("/api/analyze/latest")
async def legacy_latest(
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    return await code.get_latest_analysis(stackraider_session, srcsniff_session)
