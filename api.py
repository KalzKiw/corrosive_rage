from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Union
from . import corrosive_rage as core
import importlib
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="CorrosiveRage API")

# Permitir CORS para desarrollo (ajustar en producción)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RunRequest(BaseModel):
    target: str
    modules: Union[List[str], str]


@app.get("/")
def read_root():
    return {"message": "CorrosiveRage API. POST /run with JSON {target, modules}."}


@app.post("/run")
def run(req: RunRequest):
    target = req.target
    modules = req.modules if isinstance(req.modules, list) else [m.strip() for m in req.modules.split(',')]
    config = core.load_config()

    results = []
    for mod in modules:
        try:
            # Importar módulo desde package.modules
            module = importlib.import_module(f".modules.{mod}", package=__package__)
            if hasattr(module, 'run'):
                res = module.run(target, config)
                results.append({'module': mod, 'result': res})
            else:
                results.append({'module': mod, 'error': "module has no 'run' function"})
        except Exception as e:
            results.append({'module': mod, 'error': str(e)})

    return {"target": target, "modules": modules, "results": results}
