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
# CONFIGURACIÓN GENERAL Y SEGURIDAD
# =========================================
SECRET_KEY = os.getenv("SECRET_KEY", "don_bosco_seguro_123")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Configuración de base de datos optimizada para Aiven/Nube
DB_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "mysql-16529156-uped-419c.e.aivencloud.com"),
    "user": os.getenv("MYSQL_USER", "avnadmin"),
    "password": os.getenv("MYSQL_PASS", "AVNS_gbkKmZWVZapTrEspfyM"), # Se recomienda configurar en Render Env Vars
    "port": int(os.getenv("MYSQL_PORT", 14086)),
    "database": os.getenv("MYSQL_DB", "don_bosco_connect"),
    "ssl_disabled": False # Aiven requiere SSL activo
}

app = FastAPI(title="Sistema Don Bosco API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================
# UTILIDADES DE BASE DE DATOS Y SEGURIDAD
# =========================================
def get_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        print(f"Error crítico de conexión: {err}")
        raise HTTPException(status_code=500, detail="No se pudo conectar a la base de datos")

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
        raise HTTPException(status_code=401, detail="Token inválido o expirado")

# =========================================
# MODELOS DE DATOS (PYDANTIC)
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
# RUTAS: LOGIN / USUARIOS
# =========================================
@app.post("/login")
def login(data: LoginData):
    """
    Login simple sin token JWT: verifica usuario y contraseña.
    """
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        # Buscar usuario en la base de datos
        cursor.execute(
            "SELECT id, password_hash, rol FROM usuarios WHERE usuario=%s",
            (data.usuario,)
        )
        user = cursor.fetchone()

        # Verificar si existe el usuario
        if not user:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")

        # Verificar contraseña
        if not verify_password(data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Contraseña incorrecta")

        # Login correcto
        return {
            "success": True,
            "usuario": data.usuario,
            "rol": user["rol"],
            "message": "Login exitoso"
        }

    except mysql.connector.Error as e:
        # Manejo de errores de base de datos
        raise HTTPException(status_code=500, detail=f"Error de base de datos: {e}")
    finally:
        cursor.close()
        conn.close()


@app.post("/usuarios")
def crear_usuario(data: UsuarioCreate):
    """
    Crea un nuevo usuario sin necesidad de estar autenticado.
    Útil para crear el primer usuario (admin inicial).
    """
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO usuarios (usuario, password_hash, rol) VALUES (%s,%s,%s)",
            (data.usuario, hash_password(data.password), data.rol)
        )
        conn.commit()
        return {"success": True, "message": f"Usuario '{data.usuario}' creado"}
    finally:
        cursor.close()
        conn.close()


# =========================================
# RUTAS: JÓVENES
# =========================================
@app.get("/jovenes")
def listar_jovenes(current=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM jovenes ORDER BY nombre ASC")
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

@app.post("/jovenes")
def crear_joven(joven: Joven, current=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO jovenes (nombre, whatsapp, edad, fecha_nacimiento) VALUES (%s,%s,%s,%s)",
            (joven.nombre, joven.whatsapp, joven.edad, joven.fecha_nacimiento)
        )
        conn.commit()
        return {"success": True}
    finally:
        cursor.close()
        conn.close()

# =========================================
# RUTAS: ASISTENCIA
# =========================================
@app.post("/asistencia")
def guardar_asistencia(data: Asistencia, current=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    try:
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
        return {"success": True}
    finally:
        cursor.close()
        conn.close()

# =========================================
# RUTAS: FINANZAS
# =========================================
@app.get("/finanzas")
def listar_finanzas(current=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM finanzas ORDER BY fecha DESC")
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

@app.post("/finanzas")
def crear_finanza(data: Finanza, current=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO finanzas (tipo, monto, descripcion) VALUES (%s,%s,%s)",
            (data.tipo, data.monto, data.descripcion)
        )
        conn.commit()
        return {"success": True}
    finally:
        cursor.close()
        conn.close()

# =========================================
# ROOT
# =========================================
# =========================================
# ROOT CON VERIFICACIÓN DE BASE DE DATOS
# =========================================
@app.get("/")
def root():
    db_status = "Desconectada ❌"
    try:
        # Intentamos abrir una conexión rápida
        conn = get_db()
        if conn.is_connected():
            db_status = "Conectada a Aiven ✅"
        conn.close()
    except Exception as e:
        db_status = f"Error de conexión: {str(e)} ❌"

    return {
        "status": "online",
        "database": db_status,
        "message": "Sistema Don Bosco API activa ✔",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port) 
