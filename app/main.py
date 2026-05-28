from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.database import init_db
from app.detector import scan_content
from app.file_utils import ALLOWED_EXTENSIONS, decode_text_file, is_allowed_file
from app.schemas import ScanResponse

app = FastAPI(title="AI Secret Leakage Detector")

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.post("/scan/text", response_model=ScanResponse)
def scan_text(text: str = Form(...)):
    if not text.strip():
        raise HTTPException(status_code=400, detail="Input text cannot be empty.")

    return scan_content(input_type="text", content=text)


@app.post("/scan/file", response_model=ScanResponse)
async def scan_file(file: UploadFile = File(...)):
    if not is_allowed_file(file.filename):
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type. Allowed file types: {allowed}.",
        )

    try:
        content_bytes = await file.read()
        content = decode_text_file(content_bytes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail="File could not be read.") from exc

    if not content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file cannot be empty.")

    return scan_content(input_type="file", content=content, filename=file.filename)
