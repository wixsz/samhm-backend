from fastapi import APIRouter

router = APIRouter()


@router.get("/crash")
def crash():
    raise RuntimeError("Manual crash test")
