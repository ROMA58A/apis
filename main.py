import os
import mysql.connector
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

from jose import jwt
from passlib.context import CryptContext
import uvicorn

# =========================================
# CONFIGURACIÓN GENERAL
# =========================================
SECRET_KEY = os.getenv("SECRET_KEY", "don_bosco_seguro_123")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

db_config = {
    "host": os.getenv("MYSQL_HOST", "localhost"),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASS", ""),
    "database": os.getenv("MYSQL_DB", "don_bosco"),
}

app = FastAPI(title="Sistema Don Bosco API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================
# UTILIDADES
# =========================================
def get_db():
    return mysql.connector.connect(**db_config)

def hash_password(pwd: str):
    return pwd_context.hash(pwd)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except:
        raise HTTPException(status_code=401, detail="Token inválido")

# =========================================
# MODELOS
# =========================================
class UsuarioCreate(BaseModel):
    usuario: str
    password: str
    rol: Optional[str] = "lider"

class LoginData(BaseModel):
    usuario: str
    password: str

class Joven(BaseModel):
    nombre: str
    whatsapp: str
    edad: int
    fecha_nacimiento: str

class AsistenciaDetalle(BaseModel):
    id_joven: int
    asistio: bool
    motivo: Optional[str] = None

class Asistencia(BaseModel):
    acta: str
    total_asistentes: int
    asistencias: List[AsistenciaDetalle]

class Finanza(BaseModel):
    tipo: str
    monto: float
    descripcion: str

# =========================================
# LOGIN / USUARIOS
# =========================================
@app.post("/login")
def login(data: LoginData):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT id, password_hash, rol FROM usuarios WHERE usuario=%s",
        (data.usuario,)
    )
    user = cursor.fetchone()
    conn.close()

    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(401, "Credenciales inválidas")

    token = create_token({
        "user_id": user["id"],
        "usuario": data.usuario,
        "rol": user["rol"]
    })

    return {"access_token": token, "token_type": "bearer"}

@app.post("/usuarios")
def crear_usuario(data: UsuarioCreate, current=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO usuarios (usuario, password_hash, rol) VALUES (%s,%s,%s)",
        (data.usuario, hash_password(data.password), data.rol)
    )
    conn.commit()
    conn.close()

    return {"success": True, "message": "Usuario creado"}

# =========================================
# JÓVENES
# =========================================
@app.get("/jovenes")
def listar_jovenes(current=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM jovenes ORDER BY nombre ASC")
    data = cursor.fetchall()
    conn.close()
    return data

@app.post("/jovenes")
def crear_joven(joven: Joven, current=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO jovenes (nombre, whatsapp, edad, fecha_nacimiento) VALUES (%s,%s,%s,%s)",
        (joven.nombre, joven.whatsapp, joven.edad, joven.fecha_nacimiento)
    )
    conn.commit()
    conn.close()

    return {"success": True}

# =========================================
# ASISTENCIA
# =========================================
@app.post("/asistencia")
def guardar_asistencia(data: Asistencia, current=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO sesiones_martes (fecha, acta_reunion, total_asistentes) VALUES (CURDATE(), %s, %s)",
        (data.acta, data.total_asistentes)
    )
    id_sesion = cursor.lastrowid

    for a in data.asistencias:
        cursor.execute(
            "INSERT INTO asistencia_detalle (id_sesion, id_joven, asistio, motivo_falta) VALUES (%s,%s,%s,%s)",
            (id_sesion, a.id_joven, a.asistio, a.motivo)
        )

    conn.commit()
    conn.close()

    return {"success": True}

# =========================================
# FINANZAS
# =========================================
@app.get("/finanzas")
def listar_finanzas(current=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM finanzas ORDER BY fecha DESC")
    data = cursor.fetchall()
    conn.close()
    return data

@app.post("/finanzas")
def crear_finanza(data: Finanza, current=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO finanzas (tipo, monto, descripcion) VALUES (%s,%s,%s)",
        (data.tipo, data.monto, data.descripcion)
    )
    conn.commit()
    conn.close()

    return {"success": True}

# =========================================
# ROOT
# =========================================
@app.get("/")
def root():
    return {"message": "Sistema Don Bosco activo ✔"}

# =========================================
# RUN
# =========================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

