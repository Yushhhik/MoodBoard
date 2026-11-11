import re
import os
import sys
import uuid
import shutil
from pydantic import BaseModel
from typing import Optional
from fastapi.responses import FileResponse
import traceback
from sqlalchemy import func
from pathlib import Path
from fastapi import FastAPI, HTTPException, Depends, Query, status, Header, UploadFile, File, Form, Request, Body
from sqlalchemy.orm import Session
from sqlalchemy import text, and_, or_, func
from sqlalchemy.exc import OperationalError
from typing import List, Optional
from database import SessionLocal, engine
from models import Base, User, Board, ContentItem, BoardMember
from pydantic import BaseModel, Field, validator
from fastapi.middleware.cors import CORSMiddleware
import secrets
from datetime import datetime, timedelta
import logging
from passlib.context import CryptContext
import string
import jwt
from rq import Queue
from redis import Redis
from fastapi.staticfiles import StaticFiles
import time
from fastapi.responses import JSONResponse
from database_utils import SafeDB, sanitize_input, validate_sql_input
from security_config import SecurityConfig

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent.parent if "api" in str(Path(__file__)) else Path(__file__).parent
UPLOAD_BASE = os.getenv("UPLOADS_DIR", str(BASE_DIR / "uploads"))
UPLOAD_DIR = Path(UPLOAD_BASE)
UPLOAD_DIR.mkdir(exist_ok=True, parents=True)

for folder in ["images", "texts"]:
    (UPLOAD_DIR / folder).mkdir(exist_ok=True, parents=True)

logger.info(f"Upload directory: {UPLOAD_DIR.absolute()}")
logger.info("Created folders: images, texts")

def get_file_url(filepath: str) -> str:
    if not filepath:
        return ""
    if filepath.startswith(("http://", "https://")):
        return filepath
    if filepath.startswith("/static/"):
        import os
        base_url = os.getenv("BASE_URL", "")
        return f"{base_url}{filepath}"
    try:
        rel_path = Path(filepath).relative_to(UPLOAD_DIR)
        return f"/static/{rel_path}"
    except ValueError:
        return filepath

logger.info(f"Database URL: {os.getenv('DATABASE_URL')}")
logger.info(f"Secret Key length: {len(os.getenv('SECRET_KEY', '')) if os.getenv('SECRET_KEY') else 0}")

security_config = SecurityConfig()

UPLOAD_BASE = os.getenv("UPLOADS_DIR", "/app/uploads")
UPLOAD_DIR = Path(UPLOAD_BASE)
UPLOAD_DIR.mkdir(exist_ok=True, parents=True)

for folder in ["images", "texts"]:
    (UPLOAD_DIR / folder).mkdir(exist_ok=True, parents=True)

logger.info(f"Upload directory created at: {UPLOAD_DIR.absolute()}")
logger.info("Created folders: images, texts")

def wait_for_db():
    max_retries = 30
    retry_delay = 1

    for i in range(max_retries):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("✅ База данных доступна")
            return True
        except OperationalError as e:
            logger.warning(f"База данных недоступна, попытка {i + 1}/{max_retries}: {e}")
            time.sleep(retry_delay)

    logger.error("❌ Не удалось подключиться к базе данных после всех попыток")
    return False

if not wait_for_db():
    logger.error("Приложение не может запуститься без базы данных")
    sys.exit(1)

logger.info("Создаю таблицы в базе данных...")
try:
    Base.metadata.create_all(bind=engine)
    logger.info("✅ Таблицы созданы успешно")
except Exception as e:
    logger.error(f"❌ Ошибка при создании таблиц: {e}")
    logger.error(traceback.format_exc())

try:
    from migrations import run_migrations

    logger.info("Запускаю миграции...")
    run_migrations()
    logger.info("✅ Миграции выполнены")
except ImportError as e:
    logger.warning(f"Модуль миграций не найден: {e}")
except Exception as e:
    logger.error(f"Ошибка при выполнении миграций: {e}")

app = FastAPI(
    title="MoodBoard API",
    version="4.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

@app.middleware("http")
async def sql_injection_protection_middleware(request: Request, call_next):
    for param_name, param_value in request.query_params.items():
        if param_value and validate_sql_input(param_value):
            security_config.increment_blocked_attempts()
            logger.warning(f"🔴 Потенциальная SQL-инъекция заблокирована в query параметре {param_name}: {param_value}")
            return JSONResponse(
                status_code=400,
                content={
                    "detail": "Подозрительный запрос заблокирован системой безопасности",
                    "error_code": "SECURITY_BLOCKED"
                }
            )
    for param_name, param_value in request.path_params.items():
        if param_value and validate_sql_input(str(param_value)):
            security_config.increment_blocked_attempts()
            logger.warning(f"🔴 Потенциальная SQL-инъекция заблокирована в path параметре {param_name}: {param_value}")
            return JSONResponse(
                status_code=400,
                content={
                    "detail": "Подозрительный запрос заблокирован системой безопасности",
                    "error_code": "SECURITY_BLOCKED"
                }
            )
    for header_name, header_value in request.headers.items():
        if header_value and validate_sql_input(header_value):
            security_config.increment_blocked_attempts()
            logger.warning(f"🔴 Потенциальная SQL-инъекция заблокирована в header {header_name}: {header_value}")
            return JSONResponse(
                status_code=400,
                content={
                    "detail": "Подозрительный запрос заблокирован системой безопасности",
                    "error_code": "SECURITY_BLOCKED"
                }
            )
    response = await call_next(request)
    return response

app.mount("/static", StaticFiles(directory=UPLOAD_DIR), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "")
if not SECRET_KEY:
    logger.warning("SECRET_KEY не установлен. Генерирую временный ключ...")
    SECRET_KEY = secrets.token_urlsafe(32)
elif len(SECRET_KEY) < 32:
    logger.warning(f"SECRET_KEY слишком короткий ({len(SECRET_KEY)} символов). Рекомендуется минимум 32 символа.")
    if len(SECRET_KEY) < 32:
        padding = secrets.token_urlsafe(32 - len(SECRET_KEY))
        SECRET_KEY = SECRET_KEY + padding[:32 - len(SECRET_KEY)]

ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")

logger.info(f"Использую алгоритм JWT: {ALGORITHM}")
logger.info(f"Длина SECRET_KEY: {len(SECRET_KEY)}")

try:
    redis_conn = Redis.from_url(REDIS_URL, socket_connect_timeout=5, socket_timeout=5)
    task_queue = Queue('default', connection=redis_conn)
    logger.info("Redis подключен успешно")
except Exception as e:
    logger.warning(f"Ошибка подключения к Redis: {e}")
    logger.warning("Приложение будет работать без Redis очередей")
    redis_conn = None
    task_queue = None

pwd_context = CryptContext(
    schemes=["sha256_crypt"],
    default="sha256_crypt",
    deprecated="auto"
)

def generate_board_code():
    letters = string.ascii_uppercase
    digits = string.digits
    return f"{''.join(secrets.choice(letters) for _ in range(3))}-" \
           f"{''.join(secrets.choice(letters + digits) for _ in range(3))}-" \
           f"{''.join(secrets.choice(digits) for _ in range(3))}"

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        logger.error(f"Ошибка при создании JWT токена: {e}")
        raise HTTPException(status_code=500, detail="Ошибка при создании токена")

def save_uploaded_file(file: UploadFile, file_type: str, user_id: int) -> dict:
    try:
        logger.info(f"Сохранение файла: {file.filename}, тип: {file_type}, пользователь: {user_id}")
        if file_type not in ["image", "text"]:
            raise HTTPException(
                status_code=400,
                detail="Неподдерживаемый тип файла. Допустимые типы: image, text"
            )
        if file_type == "image":
            allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
            file_extension = Path(file.filename).suffix.lower() if file.filename else ""
            if file_extension not in allowed_extensions:
                raise HTTPException(
                    status_code=400,
                    detail=f"Неподдерживаемый формат изображения. Допустимые: {', '.join(allowed_extensions)}"
                )
        original_filename = file.filename or "unnamed_file"
        file_extension = Path(original_filename).suffix
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        folder = "images" if file_type == "image" else "texts"
        save_path = UPLOAD_DIR / folder / unique_filename
        logger.info(f"Сохранение файла в: {save_path}")
        save_path.parent.mkdir(parents=True, exist_ok=True)
        with open(save_path, "wb") as buffer:
            content = file.file.read()
            buffer.write(content)
        file_size = os.path.getsize(save_path)
        file_url = f"/static/{folder}/{unique_filename}"
        logger.info(f"Файл успешно сохранен: {save_path}, размер: {file_size} байт, URL: {file_url}")
        return {
            "filename": unique_filename,
            "original_name": original_filename,
            "filepath": str(save_path),
            "url": file_url,
            "size": file_size,
            "type": file_type,
            "folder": folder
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка при сохранении файла: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ошибка при сохранении файла: {str(e)}")

def save_text_content(text: str, user_id: int) -> dict:
    try:
        if not text or text.strip() == "":
            raise ValueError("Текст не может быть пустым")
        unique_filename = f"{uuid.uuid4()}.txt"
        folder = "texts"
        save_path = UPLOAD_DIR / folder / unique_filename
        save_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Сохранение текста в файл: {save_path}")
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(text)
        file_size = os.path.getsize(save_path)
        file_url = f"/static/{folder}/{unique_filename}"
        logger.info(f"Текст сохранен в файл: {save_path}, размер: {file_size} байт")
        return {
            "filename": unique_filename,
            "original_name": "text_content.txt",
            "filepath": str(save_path),
            "url": file_url,
            "size": file_size,
            "type": "text",
            "folder": folder,
            "content_preview": text[:100] + "..." if len(text) > 100 else text
        }
    except Exception as e:
        logger.error(f"Ошибка при сохранении текста: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ошибка при сохранении текста: {str(e)}")

class UserRegister(BaseModel):
    telegram_id: int
    username: str = Field(..., min_length=1, max_length=50)

    @validator('username')
    def validate_username(cls, v):
        v = re.sub(r'[^\w\s\-_@\.]', '', v)
        if len(v) < 1:
            raise ValueError('Имя пользователя не может быть пустым')
        return v.strip()

class UserCredentials(BaseModel):
    login: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=50)

    @validator('login')
    def validate_login(cls, v):
        v = re.sub(r'[^\w\-_\.]', '', v)
        return v

class UserResponse(BaseModel):
    id: int
    telegram_id: Optional[int]
    username: str
    is_registered: bool
    website_login: Optional[str]

    class Config:
        from_attributes = True

class UserCredentialsResponse(BaseModel):
    login: str
    password: str
    message: str

class BoardCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field("", max_length=500)
    is_public: bool = False

    @validator('name', 'description')
    def sanitize_strings(cls, v):
        if v:
            v = re.sub(r'[\'\";]', '', v)
        return v

class BoardSettingsUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    is_public: Optional[bool] = None
    background_color: Optional[str] = None
    border_color: Optional[str] = None
    board_width: Optional[int] = Field(None, ge=400, le=2500)
    board_height: Optional[int] = Field(None, ge=300, le=2000)

    @validator('name', 'description')
    def sanitize_strings(cls, v):
        if v:
            v = re.sub(r'[\'\";]', '', v)
        return v

    @validator('name')
    def validate_name_length(cls, v):
        if v is not None and len(v.strip()) < 2:
            raise ValueError('Название должно содержать минимум 2 символа')
        return v

class BoardResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    board_code: str
    is_public: bool
    owner_id: int
    created_at: str

    class Config:
        from_attributes = True

class BoardCreateResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    board_code: str
    is_public: bool
    owner_id: int
    created_at: str
    message: str

class ContentItemCreate(BaseModel):
    type: str = Field(..., pattern="^(text|image)$")
    content: Optional[str] = Field(None, max_length=10000)
    x_position: int = Field(0, ge=0, le=10000)
    y_position: int = Field(0, ge=0, le=10000)
    width: Optional[int] = Field(None, ge=0, le=1000)
    height: Optional[int] = Field(None, ge=0, le=1000)
    z_index: Optional[int] = Field(1, ge=1, le=100)
    media_metadata: Optional[dict] = None

    @validator('content')
    def sanitize_content(cls, v):
        if v:
            v = re.sub(r'[\'";\\\\]', '', v)
        return v

    @validator('width', 'height')
    def validate_dimensions(cls, v, values, **kwargs):
        if v is None:
            return v
        if v == 0:
            return v
        if v > 0 and v < 50:
            return 50
        return v

class ContentItemResponse(BaseModel):
    id: int
    board_id: int
    type: str
    content: str
    content_url: Optional[str] = None
    x_position: int
    y_position: int
    width: Optional[int]
    height: Optional[int]
    z_index: int
    media_metadata: Optional[dict]
    created_at: str
    file_info: Optional[dict] = None

    class Config:
        from_attributes = True

class ContentItemWithFileCreate(BaseModel):
    type: str = Field(..., pattern="^(text|image)$")
    x_position: int = Field(0, ge=0, le=10000)
    y_position: int = Field(0, ge=0, le=10000)
    width: Optional[int] = Field(None, ge=50, le=1000)
    height: Optional[int] = Field(None, ge=50, le=1000)
    z_index: Optional[int] = Field(1, ge=1, le=100)
    text_content: Optional[str] = Field(None, max_length=10000)

    @validator('text_content')
    def sanitize_text_content(cls, v):
        if v:
            v = re.sub(r'[\'";\\\\]', '', v)
        return v

class CollaboratorAdd(BaseModel):
    telegram_username: str = Field(..., min_length=1, max_length=50)

    @validator('telegram_username')
    def sanitize_username(cls, v):
        v = v.lstrip('@')
        v = re.sub(r'[^\w]', '', v)
        return v

class CollaboratorResponse(BaseModel):
    success: bool
    message: str
    collaborator_id: Optional[int] = None

class BoardAccessCheck(BaseModel):
    board_code: str = Field(..., min_length=11, max_length=11)

    @validator('board_code')
    def validate_board_code(cls, v):
        if not re.match(r'^[A-Z]{3}-[A-Z0-9]{3}-\d{3}$', v):
            raise ValueError('Неверный формат кода доски')
        return v

class BoardAccessResponse(BaseModel):
    has_access: bool
    can_view: bool
    can_edit: bool
    board_id: Optional[int] = None
    board_name: Optional[str] = None
    message: Optional[str] = None

class AuthResponse(BaseModel):
    access_token: str
    token_type: str
    user_id: int
    telegram_id: Optional[int]
    username: str

class WebsiteLogin(BaseModel):
    login: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=50)

    @validator('login')
    def sanitize_login(cls, v):
        v = re.sub(r'[^\w\-_\.]', '', v)
        return v

class WebsiteAuthResponse(BaseModel):
    success: bool
    access_token: Optional[str] = None
    user_id: Optional[int] = None
    telegram_id: Optional[int] = None
    username: Optional[str] = None
    message: Optional[str] = None

class FileUploadResponse(BaseModel):
    success: bool
    url: Optional[str] = None
    filename: Optional[str] = None
    size: Optional[int] = None
    message: Optional[str] = None

class ContentUpdateRequest(BaseModel):
    x_position: Optional[int] = Field(None, ge=0, le=10000)
    y_position: Optional[int] = Field(None, ge=0, le=10000)
    width: Optional[int] = Field(None, ge=0, le=1000)
    height: Optional[int] = Field(None, ge=0, le=1000)
    content: Optional[str] = Field(None, max_length=10000)
    z_index: Optional[int] = Field(None, ge=1, le=100)

    @validator('content')
    def sanitize_content(cls, v):
        if v:
            v = re.sub(r'[\'";\\\\]', '', v)
        return v

    @validator('width', 'height')
    def validate_dimensions(cls, v, values, **kwargs):
        if v is None:
            return v
        if v == 0:
            return v
        if v > 0 and v < 50:
            return 50
        return v

class LayerUpdateRequest(BaseModel):
    operation: str = Field(..., pattern="^(raise|lower|to_top|to_bottom)$")

class MemberAdd(BaseModel):
    telegram_username: str = Field(..., min_length=1, max_length=50)
    role: str = Field("collaborator", pattern="^(owner|collaborator|editor|viewer)$")

    @validator('telegram_username')
    def sanitize_username(cls, v):
        v = v.lstrip('@')
        v = re.sub(r'[^\w]', '', v)
        return v

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Header(...), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Неверный токен")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Токен истек")
    except jwt.InvalidTokenError as e:
        logger.error(f"Неверный токен: {e}")
        raise HTTPException(status_code=401, detail="Неверный токен")
    except Exception as e:
        logger.error(f"Ошибка при декодировании токена: {e}")
        raise HTTPException(status_code=401, detail="Неверный токен")
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Пользователь не найден")
    return user

def get_or_create_user(telegram_id: int, username: str, db: Session,
                       register: bool = False):
    logger.info(f"Получение/создание пользователя: telegram_id={telegram_id}, username={username}")
    telegram_id = int(telegram_id)
    username = re.sub(r'[^\w\s\-_@\.]', '', username.strip())
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        logger.info(f"Создаю нового пользователя: telegram_id={telegram_id}")
        user = User(
            telegram_id=telegram_id,
            username=username,
            is_registered=register
        )
        db.add(user)
        try:
            db.commit()
            db.refresh(user)
            logger.info(f"Пользователь создан с ID: {user.id}")
        except Exception as e:
            db.rollback()
            logger.error(f"Ошибка при создании пользователя: {e}")
            raise
    return user

def generate_password(length=12):
    if length < 8:
        length = 12
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    all_chars = lowercase + uppercase + digits
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits)
    ]
    password.extend(secrets.choice(all_chars) for _ in range(length - 3))
    secrets.SystemRandom().shuffle(password)
    result = ''.join(password)
    return result

def generate_website_login():
    import uuid
    import time
    timestamp = str(int(time.time()))[-6:]
    uuid_part = str(uuid.uuid4())[:8]
    login = f"user_{timestamp}_{uuid_part}"
    return login[:50]

def register_user_internal(telegram_id: int, username: str, db: Session):
    logger.info(f"=== НАЧАЛО РЕГИСТРАЦИИ ===")
    logger.info(f"telegram_id: {telegram_id}, username: {username}")
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if user:
        logger.info(f"Пользователь уже существует: id={user.id}, is_registered={user.is_registered}")
        if user.is_registered and user.website_login and user.hashed_password and user.plain_password:
            logger.info(f"Пользователь уже зарегистрирован: login={user.website_login}, пароль сохранен")
            return user, user.website_login, user.plain_password, "Пользователь уже зарегистрирован. Ваши данные остались прежними."
    import re
    import time
    clean_username = re.sub(r'[^\x00-\x7F]+', '', username) if username else ""
    clean_username = clean_username.strip()
    if not clean_username or len(clean_username) < 2:
        clean_username = f"user_{telegram_id}"
        logger.info(f"Сгенерирован username: {clean_username}")
    clean_username = clean_username[:50]
    if not user or (user and user.username != clean_username):
        existing_user = db.query(User).filter(User.username == clean_username).first()
        if existing_user and existing_user.id != (user.id if user else None):
            suffix = 1
            while True:
                new_username = f"{clean_username[:45]}_{suffix}"
                existing = db.query(User).filter(User.username == new_username).first()
                if not existing:
                    clean_username = new_username
                    logger.info(f"Username изменен на уникальный: {clean_username}")
                    break
                suffix += 1
                if suffix > 100:
                    clean_username = f"user_{telegram_id}_{int(time.time()) % 10000}"
                    logger.info(f"Используем fallback username: {clean_username}")
                    break
    website_login = generate_website_login()
    website_password = generate_password()
    logger.info(f"Сгенерирован login: {website_login}")
    logger.info(f"Сгенерирован пароль (plain): {website_password}")
    attempts = 0
    max_attempts = 5
    while attempts < max_attempts:
        existing_login = db.query(User).filter(User.website_login == website_login).first()
        if not existing_login:
            break
        logger.warning(f"Логин {website_login} уже существует. Генерируем новый...")
        website_login = generate_website_login()
        attempts += 1
    if attempts >= max_attempts:
        website_login = f"user_{telegram_id}_{int(time.time())}"
        logger.warning(f"Используем fallback логин: {website_login}")
    try:
        logger.info(f"Хешируем пароль для безопасного хранения...")
        password_bytes = website_password.encode('utf-8')
        if len(password_bytes) > 72:
            logger.warning(f"Пароль слишком длинный ({len(password_bytes)} байт). Обрезаем до 72 байт.")
            truncated_bytes = password_bytes[:72]
            while True:
                try:
                    truncated_password = truncated_bytes.decode('utf-8')
                    break
                except UnicodeDecodeError:
                    truncated_bytes = truncated_bytes[:-1]
            logger.info(f"Пароль обрезан до {len(truncated_password)} символов")
            password_hash = pwd_context.hash(truncated_password)
            website_password = truncated_password
        else:
            password_hash = pwd_context.hash(website_password)
        logger.info("Пароль успешно захэширован")
    except Exception as e:
        logger.error(f"Ошибка хеширования пароля: {e}", exc_info=True)
        logger.info("Генерируем короткий пароль...")
        short_password = secrets.token_urlsafe(20)[:20]
        password_hash = pwd_context.hash(short_password)
        website_password = short_password
        logger.info(f"Использован короткий пароль: {website_password}")
    if not user:
        user = User(
            telegram_id=telegram_id,
            username=clean_username,
            website_login=website_login,
            hashed_password=password_hash,
            plain_password=website_password,
            is_registered=True
        )
        db.add(user)
        logger.info(f"Создан новый пользователь с сохраненным паролем")
    else:
        user.username = clean_username
        user.website_login = website_login
        user.hashed_password = password_hash
        user.plain_password = website_password
        user.is_registered = True
        logger.info(f"Обновлен существующий пользователь id={user.id}, пароль сохранен")
    try:
        db.commit()
        db.refresh(user)
        logger.info(f"✅ Пользователь сохранен в БД: id={user.id}, login={user.website_login}")
        db_user = db.query(User).filter(User.id == user.id).first()
        if db_user and db_user.plain_password:
            logger.info(f"✅ Пароль успешно сохранен в plain_password: {db_user.plain_password}")
        else:
            logger.error(f"❌ Пароль не сохранен в plain_password!")
            db_user.plain_password = website_password
            db.commit()
            db.refresh(db_user)
            logger.info(f"✅ Пароль сохранен повторно: {db_user.plain_password}")
    except Exception as e:
        db.rollback()
        logger.error(f"❌ Ошибка при сохранении пользователя в БД: {e}", exc_info=True)
        try:
            logger.info("Пробуем альтернативный подход...")
            if not user.id:
                user = User(
                    telegram_id=telegram_id,
                    username=clean_username,
                    website_login=website_login,
                    plain_password=website_password,
                    is_registered=True
                )
                db.add(user)
                db.commit()
                db.refresh(user)
                logger.info(f"✅ Создан пользователь с паролем в plain_password, id={user.id}")
                return user, website_login, website_password, "Регистрация успешна"
        except Exception as e2:
            logger.error(f"❌ Альтернативный подход тоже не сработал: {e2}")
            return None, None, None, f"Ошибка базы данных: {str(e)}"
    logger.info(f"=== РЕГИСТРАЦИЯ УСПЕШНА ===")
    logger.info(f"telegram_id: {telegram_id}")
    logger.info(f"username: {clean_username}")
    logger.info(f"website_login: {website_login}")
    logger.info(f"plain_password: {website_password}")
    return user, website_login, website_password, "Регистрация успешна"

@app.get("/")
def read_root():
    return {"message": "MoodBoard API работает! 🎨", "version": "4.0.0", "has_redis": redis_conn is not None}

@app.get("/health")
def health_check():
    redis_status = "disconnected"
    if redis_conn:
        try:
            if redis_conn.ping():
                redis_status = "connected"
        except Exception as e:
            logger.warning(f"Redis ping failed: {e}")
            redis_status = "error"
    upload_dirs = {}
    for folder in ["images", "texts"]:
        folder_path = UPLOAD_DIR / folder
        upload_dirs[folder] = {
            "exists": folder_path.exists(),
            "writable": os.access(folder_path, os.W_OK) if folder_path.exists() else False
        }
    db_status = "unknown"
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            db_status = "connected"
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        db_status = "disconnected"
    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "timestamp": datetime.now().isoformat(),
        "service": "MoodBoard API v4",
        "database": db_status,
        "redis": redis_status,
        "upload_dirs": upload_dirs,
        "upload_path": str(UPLOAD_DIR.absolute()),
        "security": {
            "sql_injection_protection": "enabled",
            "input_validation": "enabled",
            "middleware_active": True,
            "blocked_attempts": security_config.get_blocked_attempts()["total"]
        }
    }

@app.delete("/api/boards/{board_id}")
@sanitize_input
def delete_board(
        board_id: int,
        telegram_id: int = Query(..., description="Telegram ID пользователя"),
        db: Session = Depends(get_db)
):
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        raise HTTPException(status_code=404, detail="Доска не найдена")
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if board.owner_id != user.id:
        raise HTTPException(
            status_code=403,
            detail="Только владелец может удалить доску"
        )
    board_name = board.name
    content_count = 0
    try:
        content_items = db.query(ContentItem).filter(ContentItem.board_id == board_id).all()
        content_count = len(content_items)
        for item in content_items:
            if item.type in ["image", "text"] and item.content.startswith("/static/"):
                try:
                    file_path = item.content.replace("/static/", str(UPLOAD_DIR) + "/")
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        logger.info(f"Удален файл: {file_path}")
                except Exception as e:
                    logger.error(f"Ошибка при удалении файла {item.content}: {e}")
        db.query(ContentItem).filter(ContentItem.board_id == board_id).delete()
        db.query(BoardMember).filter(BoardMember.board_id == board_id).delete()
        db.delete(board)
        db.commit()
        logger.info(f"Доска {board_id} ('{board_name}') удалена пользователем {user.id}. "
                    f"Удалено контента: {content_count}")
        return {
            "success": True,
            "message": f"Доска '{board_name}' успешно удалена",
            "deleted_content_count": content_count
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Ошибка при удалении доски {board_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при удалении доски: {str(e)}"
        )

@app.get("/api/users/{telegram_id}/password")
@sanitize_input
def get_user_password(telegram_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if not user.is_registered:
        raise HTTPException(status_code=400, detail="Пользователь не зарегистрирован")
    if not user.plain_password:
        return {
            "login": user.website_login,
            "password": "Пароль не сохранен. Зарегистрируйтесь заново через /start в боте",
            "message": "Пароль доступен только после новой регистрации"
        }
    return {
        "login": user.website_login,
        "password": user.plain_password,
        "message": "Ваши данные для входа на сайт"
    }

@app.post("/api/upload", response_model=FileUploadResponse)
async def upload_file(
        file: UploadFile = File(...),
        file_type: str = Form("image"),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    logger.info(f"Загрузка файла: {file.filename}, тип: {file_type}, пользователь: {current_user.id}")
    allowed_types = ["image", "text"]
    if file_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"Неподдерживаемый тип файла. Допустимые типы: {', '.join(allowed_types)}"
        )
    MAX_FILE_SIZE = 10 * 1024 * 1024 if file_type == "image" else 1 * 1024 * 1024
    try:
        file.file.seek(0, 2)
        file_size = file.file.tell()
        file.file.seek(0)
        logger.info(f"Размер файла: {file_size} байт, максимум: {MAX_FILE_SIZE} байт")
        if file_size > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"Файл слишком большой. Максимальный размер: {MAX_FILE_SIZE // (1024 * 1024)}MB"
            )
        file_info = save_uploaded_file(file, file_type, current_user.id)
        return FileUploadResponse(
            success=True,
            url=file_info["url"],
            filename=file_info["original_name"],
            size=file_info["size"],
            message="Файл успешно загружен"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка при загрузке файла: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ошибка при загрузке файла: {str(e)}")

@app.get("/api/users/{telegram_id}/status")
@sanitize_input
def check_user_status(telegram_id: int, db: Session = Depends(get_db)):
    logger.info(f"Проверка статуса пользователя: telegram_id={telegram_id}")
    safe_db = SafeDB()
    query = db.query(User)
    query = safe_db.safe_filter(query, User, telegram_id=telegram_id)
    user = query.first()
    if not user:
        logger.info(f"Пользователь не найден: {telegram_id}")
        return {
            "is_registered": False,
            "message": "Пользователь не найден"
        }
    return {
        "is_registered": user.is_registered,
        "username": user.username,
        "has_credentials": user.website_login is not None and user.hashed_password is not None
    }

@app.post("/api/users/register", response_model=UserCredentialsResponse)
@sanitize_input
def register_user(user_data: UserRegister, db: Session = Depends(get_db)):
    logger.info(f"Регистрация пользователя: telegram_id={user_data.telegram_id}, username={user_data.username}")
    try:
        user, login, password, message = register_user_internal(
            user_data.telegram_id,
            user_data.username,
            db
        )
        if login is None or password is None:
            logger.error(f"Регистрация не удалась: {message}")
            raise HTTPException(
                status_code=400,
                detail=message
            )
        logger.info(f"Пользователь успешно зарегистрирован: login={login}, telegram_id={user_data.telegram_id}")
        return UserCredentialsResponse(
            login=login,
            password=password,
            message=message
        )
    except ValueError as e:
        if "password cannot be longer than 72 bytes" in str(e):
            raise HTTPException(
                status_code=400,
                detail="Ошибка генерации пароля. Попробуйте еще раз."
            )
        logger.error(f"Ошибка при регистрации: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Внутренняя ошибка сервера: {str(e)}"
        )

@app.get("/api/users/{telegram_id}/credentials")
@sanitize_input
def get_user_credentials(telegram_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if not user.is_registered or not user.website_login:
        raise HTTPException(status_code=400, detail="Пользователь не зарегистрирован")
    return {
        "login": user.website_login,
        "is_registered": user.is_registered,
        "message": "Для смены пароля обратитесь к администратору"
    }

@app.get("/api/users/{telegram_id}/boards", response_model=List[BoardResponse])
@sanitize_input
def get_user_boards(telegram_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    safe_db = SafeDB()
    owned_boards_query = db.query(Board)
    owned_boards_query = safe_db.safe_filter(owned_boards_query, Board, owner_id=user.id)
    owned_boards = owned_boards_query.all()
    member_boards_query = db.query(Board).join(BoardMember)
    member_boards_query = member_boards_query.filter(
        BoardMember.user_id == user.id,
        BoardMember.board_id == Board.id
    )
    member_boards = member_boards_query.all()
    all_boards = list({board.id: board for board in owned_boards + member_boards}.values())
    return [
        {
            "id": board.id,
            "name": board.name,
            "description": board.description,
            "board_code": board.board_code,
            "is_public": board.is_public,
            "owner_id": board.owner_id,
            "created_at": board.created_at.isoformat()
        }
        for board in all_boards
    ]

@app.post("/api/boards", response_model=BoardCreateResponse)
@sanitize_input
def create_board(
        board_data: BoardCreate,
        telegram_id: int = Query(..., description="Telegram ID создателя"),
        db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    board_code = generate_board_code()
    board = Board(
        name=board_data.name,
        description=board_data.description,
        board_code=board_code,
        is_public=board_data.is_public,
        owner_id=user.id,
        view_token=secrets.token_urlsafe(16)
    )
    db.add(board)
    db.commit()
    db.refresh(board)
    board_member = BoardMember(
        board_id=board.id,
        user_id=user.id,
        role="owner"
    )
    db.add(board_member)
    db.commit()
    return BoardCreateResponse(
        id=board.id,
        name=board.name,
        description=board.description,
        board_code=board.board_code,
        is_public=board.is_public,
        owner_id=board.owner_id,
        created_at=board.created_at.isoformat(),
        message="Досксоздана успешно"
    )

@app.get("/api/boards/{board_id}/content", response_model=List[ContentItemResponse])
@sanitize_input
def get_board_content(board_id: int, db: Session = Depends(get_db)):
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        raise HTTPException(status_code=404, detail="Доска не найдена")
    safe_db = SafeDB()
    query = db.query(ContentItem)
    query = safe_db.safe_filter(query, ContentItem, board_id=board_id)
    content_items = query.order_by(ContentItem.z_index.asc(), ContentItem.created_at).all()
    response_items = []
    for item in content_items:
        item_data = {
            "id": item.id,
            "board_id": item.board_id,
            "type": item.type,
            "content": item.content,
            "x_position": item.x_position,
            "y_position": item.y_position,
            "width": item.width,
            "height": item.height,
            "z_index": item.z_index if item.z_index else 1,
            "media_metadata": item.media_metadata,
            "created_at": item.created_at.isoformat(),
            "content_url": None
        }
        if item.type in ["image", "text"]:
            if item.content.startswith("/static/"):
                item_data["content_url"] = get_file_url(item.content)
            elif item.content:
                item_data["content_url"] = item.content
        if item.type == "text" and item.media_metadata:
            item_data["file_info"] = {
                "preview": item.media_metadata.get("content_preview", item.content[:100] + "..." if len(
                    item.content) > 100 else item.content)
            }
        response_items.append(item_data)
    return response_items

@app.post("/api/boards/{board_id}/content/upload", response_model=ContentItemResponse)
async def add_content_to_board_upload(
        board_id: int,
        file: UploadFile = File(None),
        text_content: str = Form(None),
        type: str = Form("image"),
        x_position: int = Form(0),
        y_position: int = Form(0),
        width: Optional[int] = Form(None),
        height: Optional[int] = Form(None),
        z_index: Optional[int] = Form(1),
        telegram_id: int = Query(..., description="Telegram ID пользователя"),
        db: Session = Depends(get_db)
):
    logger.info(f"Добавление контента на доску {board_id}, тип: {type}")
    if not (file or text_content):
        raise HTTPException(status_code=400, detail="Необходимо предоставить либо файл, либо текстовый контент")
    if type not in ["image", "text"]:
        raise HTTPException(status_code=400, detail="Неподдерживаемый тип контента. Допустимые типы: image, text")
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        raise HTTPException(status_code=404, detail="Доска не найдена")
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    is_owner = board.owner_id == user.id
    member = db.query(BoardMember).filter(
        BoardMember.board_id == board_id,
        BoardMember.user_id == user.id
    ).first()
    can_edit = is_owner or (member and member.role in ["owner", "collaborator"])
    if not can_edit:
        raise HTTPException(
            status_code=403,
            detail="Недостаточно прав для добавления контента"
        )
    content_data = {
        "board_id": board_id,
        "type": type,
        "x_position": x_position,
        "y_position": y_position,
        "width": width,
        "height": height,
        "z_index": z_index or 1,
        "created_by": user.id,
        "media_metadata": {}
    }
    if type == "text" and text_content:
        text_content = re.sub(r'[\'\";\\-\-]', '', text_content)
        file_info = save_text_content(text_content, user.id)
        content_data["content"] = text_content
        content_data["media_metadata"] = {
            "file_url": file_info["url"],
            "file_size": file_info["size"],
            "content_preview": file_info.get("content_preview", ""),
            "original_name": file_info["original_name"]
        }
    elif file and type == "image":
        if file.filename and validate_sql_input(file.filename):
            raise HTTPException(status_code=400, detail="Подозрительное имя файла")
        file_info = save_uploaded_file(file, type, user.id)
        content_data["content"] = file_info["url"]
        content_data["media_metadata"] = {
            "filename": file_info["original_name"],
            "file_size": file_info["size"],
            "file_url": file_info["url"],
            "original_name": file_info["original_name"]
        }
        try:
            from PIL import Image
            with Image.open(file_info["filepath"]) as img:
                content_data["media_metadata"]["dimensions"] = {
                    "width": img.width,
                    "height": img.height
                }
                if not width and img.width > 0:
                    content_data["width"] = min(img.width, 500)
                if not height and img.height > 0:
                    content_data["height"] = min(img.height, 500)
        except ImportError:
            logger.warning("PIL не установлен, не могу получить размеры изображения")
        except Exception as e:
            logger.warning(f"Не удалось получить размеры изображения: {e}")
            if not width:
                content_data["width"] = 300
            if not height:
                content_data["height"] = 200
    else:
        raise HTTPException(
            status_code=400,
            detail="Для типа 'image' необходимо загрузить файл, для типа 'text' - текстовый контент"
        )
    content_item = ContentItem(**content_data)
    db.add(content_item)
    db.commit()
    db.refresh(content_item)
    response_data = {
        "id": content_item.id,
        "board_id": content_item.board_id,
        "type": content_item.type,
        "content": content_item.content,
        "x_position": content_item.x_position,
        "y_position": content_item.y_position,
        "width": content_item.width,
        "height": content_item.height,
        "z_index": content_item.z_index,
        "media_metadata": content_item.media_metadata,
        "created_at": content_item.created_at.isoformat(),
        "content_url": content_item.content if content_item.type == "image" else None
    }
    return ContentItemResponse(**response_data)

@app.post("/api/boards/{board_id}/content", response_model=ContentItemResponse)
@sanitize_input
def add_content_to_board(
        board_id: int,
        content: ContentItemCreate,
        telegram_id: int = Query(..., description="Telegram ID пользователя"),
        db: Session = Depends(get_db)
):
    logger.info(
        f"Добавление контента на доску {board_id}, тип: {content.type}")
    if content.type not in ["image", "text"]:
        logger.error(f"Неподдерживаемый тип контента: {content.type}")
        raise HTTPException(status_code=400, detail="Неподдерживаемый тип контента")
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        logger.error(f"Доска {board_id} не найдена")
        raise HTTPException(status_code=404, detail="Доска не найдена")
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        logger.error(f"Пользователь с telegram_id={telegram_id} не найден")
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    is_owner = board.owner_id == user.id
    member = db.query(BoardMember).filter(
        BoardMember.board_id == board_id,
        BoardMember.user_id == user.id
    ).first()
    can_edit = is_owner or (member and member.role in ["owner", "collaborator"])
    if not can_edit:
        logger.error(f"Пользователь {user.id} не имеет прав для добавления контента на доску {board_id}")
        raise HTTPException(
            status_code=403,
            detail="Недостаточно прав для добавления контента"
        )
    content_data = {
        "board_id": board_id,
        "type": content.type,
        "x_position": content.x_position,
        "y_position": content.y_position,
        "width": content.width,
        "height": content.height,
        "z_index": content.z_index if content.z_index else 1,
        "media_metadata": content.media_metadata,
        "created_by": user.id
    }
    if content.type == "text":
        if not content.content or content.content.strip() == "":
            logger.error("Пустой текстовый контент")
            raise HTTPException(status_code=400, detail="Текст не может быть пустым")
        logger.info(f"Сохранение текстового контента длиной {len(content.content)} символов")
        try:
            clean_content = re.sub(r'[\'"\;\\\-]', '', content.content)
            file_info = save_text_content(clean_content, user.id)
            logger.info(f"Текст сохранен в файл: {file_info['url']}")
            content_data["content"] = clean_content
            content_data["media_metadata"] = content.media_metadata or {}
            content_data["media_metadata"].update({
                "file_url": file_info["url"],
                "file_size": file_info["size"],
                "content_preview": file_info.get("content_preview", clean_content[:100])
            })
        except Exception as e:
            logger.error(f"Ошибка при сохранении текста: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Ошибка при сохранении текста: {str(e)}")
    else:
        content_data["content"] = content.content
    try:
        logger.info(f"Создание ContentItem с данными: {content_data}")
        content_item = ContentItem(**content_data)
        db.add(content_item)
        db.commit()
        db.refresh(content_item)
        logger.info(f"ContentItem создан с ID: {content_item.id}")
    except Exception as e:
        db.rollback()
        logger.error(f"Ошибка при создании ContentItem: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ошибка базы данных: {str(e)}")
    response_data = {
        "id": content_item.id,
        "board_id": content_item.board_id,
        "type": content_item.type,
        "content": content_item.content,
        "x_position": content_item.x_position,
        "y_position": content_item.y_position,
        "width": content_item.width,
        "height": content_item.height,
        "z_index": content_item.z_index,
        "media_metadata": content_item.media_metadata,
        "created_at": content_item.created_at.isoformat()
    }
    if content_item.type == "text" and content_item.media_metadata and "file_url" in content_item.media_metadata:
        response_data["content_url"] = content_item.media_metadata["file_url"]
    return ContentItemResponse(**response_data)

@app.delete("/api/boards/{board_id}/content/{content_id}")
@sanitize_input
def delete_content(
        board_id: int,
        content_id: int,
        telegram_id: int = Query(..., description="Telegram ID пользователя"),
        db: Session = Depends(get_db)
):
    content = db.query(ContentItem).filter(
        ContentItem.id == content_id,
        ContentItem.board_id == board_id
    ).first()
    if not content:
        raise HTTPException(status_code=404, detail="Контент не найден")
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    board = db.query(Board).filter(Board.id == board_id).first()
    is_owner = board.owner_id == user.id
    is_content_creator = content.created_by == user.id
    member = db.query(BoardMember).filter(
        BoardMember.board_id == board_id,
        BoardMember.user_id == user.id
    ).first()
    can_delete = is_owner or is_content_creator or (member and member.role in ["owner", "collaborator"])
    if not can_delete:
        raise HTTPException(
            status_code=403,
            detail="Недостаточно прав для удаления контента"
        )
    if content.type in ["image", "text"] and content.content.startswith("/static/"):
        try:
            file_path = content.content.replace("/static/", str(UPLOAD_DIR) + "/")
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"Файл удален с диска: {file_path}")
        except Exception as e:
            logger.error(f"Ошибка при удалении файла с диска: {e}")
    db.delete(content)
    db.commit()
    return {"success": True, "message": "Контент удален успешно"}

@app.put("/api/boards/{board_id}/content/{content_id}/position")
@sanitize_input
def update_content_position(
        board_id: int,
        content_id: int,
        update_data: ContentUpdateRequest,
        telegram_id: int = Query(..., description="Telegram ID пользователя"),
        db: Session = Depends(get_db)
):
    content = db.query(ContentItem).filter(
        ContentItem.id == content_id,
        ContentItem.board_id == board_id
    ).first()
    if not content:
        raise HTTPException(status_code=404, detail="Контент не найден")
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    board = db.query(Board).filter(Board.id == board_id).first()
    is_owner = board.owner_id == user.id
    is_content_creator = content.created_by == user.id
    member = db.query(BoardMember).filter(
        BoardMember.board_id == board_id,
        BoardMember.user_id == user.id
    ).first()
    can_edit = is_owner or is_content_creator or (member and member.role in ["owner", "collaborator"])
    if not can_edit:
        raise HTTPException(
            status_code=403,
            detail="Недостаточно прав для редактирования контента"
        )
    if (update_data.width is not None and update_data.width == 0) or \
            (update_data.height is not None and update_data.height == 0):
        content.x_position = 0
        content.y_position = 0
        content.width = 0
        content.height = 0
    else:
        if update_data.x_position is not None:
            content.x_position = update_data.x_position
        if update_data.y_position is not None:
            content.y_position = update_data.y_position
        if update_data.width is not None:
            content.width = max(update_data.width, 50) if update_data.width > 0 else update_data.width
        if update_data.height is not None:
            content.height = max(update_data.height, 50) if update_data.height > 0 else update_data.height
    if update_data.z_index is not None:
        content.z_index = update_data.z_index
    if update_data.content is not None and content.type == "text":
        update_data.content = re.sub(r'[\'";\\\\]', '', update_data.content)
        content.content = update_data.content
    db.commit()
    db.refresh(content)
    return {
        "success": True,
        "message": "Контент обновлен",
        "content": {
            "id": content.id,
            "x_position": content.x_position,
            "y_position": content.y_position,
            "width": content.width,
            "height": content.height,
            "z_index": content.z_index,
            "content": content.content if content.type == "text" else None
        }
    }

@app.post("/api/boards/{board_id}/members", response_model=CollaboratorResponse)
@sanitize_input
def add_board_member(
        board_id: int,
        member_data: MemberAdd,
        telegram_id: int = Query(..., description="Telegram ID приглашающего"),
        db: Session = Depends(get_db)
):
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        raise HTTPException(status_code=404, detail="Доска не найдена")
    inviter = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not inviter:
        raise HTTPException(status_code=404, detail="Приглашающий не найден")
    if board.owner_id != inviter.id:
        raise HTTPException(
            status_code=403,
            detail="Только владелец может добавлять участников на доску"
        )
    telegram_username = member_data.telegram_username.lstrip('@')
    new_member_user = db.query(User).filter(User.username == telegram_username).first()
    if not new_member_user:
        return CollaboratorResponse(
            success=False,
            message="Пользователь не найден. Попросите его зарегистрироваться через бота."
        )
    if not new_member_user.is_registered:
        return CollaboratorResponse(
            success=False,
            message="Пользователь не зарегистрирован. Попросите его зарегистрироваться через бота."
        )
    existing_member = db.query(BoardMember).filter(
        BoardMember.board_id == board_id,
        BoardMember.user_id == new_member_user.id
    ).first()
    if existing_member:
        return CollaboratorResponse(
            success=False,
            message=f"Пользователь уже является участником этой доски с ролью {existing_member.role}"
        )
    if member_data.role == "owner":
        return CollaboratorResponse(
            success=False,
            message="На доске может быть только один владелец"
        )
    board_member = BoardMember(
        board_id=board_id,
        user_id=new_member_user.id,
        role=member_data.role
    )
    db.add(board_member)
    db.commit()
    role_names = {
        "owner": "владелец",
        "collaborator": "соавтор",
        "editor": "редактор",
        "viewer": "зритель"
    }
    return CollaboratorResponse(
        success=True,
        message=f"Пользователь @{telegram_username} добавлен как {role_names.get(member_data.role, 'участник')}",
        collaborator_id=new_member_user.id
    )

@app.post("/api/boards/{board_id}/collaborators", response_model=CollaboratorResponse)
@sanitize_input
def add_collaborator(
        board_id: int,
        collaborator_data: CollaboratorAdd,
        telegram_id: int = Query(..., description="Telegram ID приглашающего"),
        db: Session = Depends(get_db)
):
    logger.info(f"=== НАЧАЛО: Добавление соавтора ===")
    logger.info(f"Доска: {board_id}, telegram_id: {telegram_id}")
    logger.info(f"Данные соавтора: {collaborator_data.dict()}")
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        logger.error(f"Доска {board_id} не найдена")
        raise HTTPException(status_code=404, detail="Доска не найдена")
    inviter = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not inviter:
        logger.error(f"Пользователь с telegram_id={telegram_id} не найден")
        raise HTTPException(status_code=404, detail="Приглашающий не найден")
    logger.info(f"Приглашающий найден: id={inviter.id}, telegram_id={inviter.telegram_id}, username={inviter.username}")
    logger.info(f"Владелец доски: board.owner_id={board.owner_id}, inviter.id={inviter.id}")
    if board.owner_id != inviter.id:
        logger.error(f"Пользователь {inviter.id} не является владельцем доски {board_id}")
        raise HTTPException(
            status_code=403,
            detail="Только владелец может добавлять соавторов на доску"
        )
    telegram_username = collaborator_data.telegram_username.lstrip('@')
    logger.info(f"Ищем пользователя с username: {telegram_username}")
    new_collaborator = db.query(User).filter(User.username == telegram_username).first()
    if not new_collaborator:
        logger.warning(f"Пользователь с username={telegram_username} не найден")
        return CollaboratorResponse(
            success=False,
            message="Пользователь не найден. Попросите его зарегистрироваться через бота."
        )
    logger.info(
        f"Найден пользователь: id={new_collaborator.id}, username={new_collaborator.username}, is_registered={new_collaborator.is_registered}")
    if not new_collaborator.is_registered:
        logger.warning(f"Пользователь {new_collaborator.id} не зарегистрирован")
        return CollaboratorResponse(
            success=False,
            message="Пользователь не зарегистрирован. Попросите его зарегистрироваться через бота."
        )
    existing_member = db.query(BoardMember).filter(
        BoardMember.board_id == board_id,
        BoardMember.user_id == new_collaborator.id
    ).first()
    if existing_member:
        logger.warning(f"Пользователь {new_collaborator.id} уже участник доски с ролью {existing_member.role}")
        return CollaboratorResponse(
            success=False,
            message=f"Пользователь уже является участником этой доски с ролью {existing_member.role}"
        )
    board_member = BoardMember(
        board_id=board_id,
        user_id=new_collaborator.id,
        role="collaborator"
    )
    db.add(board_member)
    db.commit()
    logger.info(f"=== УСПЕХ: Соавтор @{telegram_username} добавлен на доску {board_id} ===")
    return CollaboratorResponse(
        success=True,
        message=f"Пользователь @{telegram_username} добавлен как соавтор",
        collaborator_id=new_collaborator.id
    )

@app.get("/api/boards/{board_id}/members")
@sanitize_input
def get_board_members(
        board_id: int,
        db: Session = Depends(get_db)
):
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        raise HTTPException(status_code=404, detail="Доска не найдена")
    owner = db.query(User).filter(User.id == board.owner_id).first()
    members = db.query(BoardMember, User).join(
        User, BoardMember.user_id == User.id
    ).filter(
        BoardMember.board_id == board_id
    ).all()
    result = []
    if owner:
        result.append({
            "user_id": owner.id,
            "username": owner.username,
            "telegram_username": owner.username,
            "role": "owner",
            "is_owner": True
        })
    for member, user in members:
        if user.id == owner.id:
            continue
        result.append({
            "user_id": user.id,
            "username": user.username,
            "telegram_username": user.username,
            "role": member.role,
            "is_owner": False
        })
    return {
        "board_id": board_id,
        "board_name": board.name,
        "members_count": len(result),
        "members": result
    }

@app.post("/api/boards/access/check", response_model=BoardAccessResponse)
@sanitize_input
def check_board_access(
        access: BoardAccessCheck,
        user_id: Optional[int] = Query(None, description="ID пользователя (если авторизован)"),
        db: Session = Depends(get_db)
):
    board = db.query(Board).filter(Board.board_code == access.board_code).first()
    if not board:
        return BoardAccessResponse(
            has_access=False,
            can_view=False,
            can_edit=False,
            message="Доска не найдена"
        )
    can_view = False
    can_edit = False
    message = ""
    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            if user.id == board.owner_id:
                can_view = True
                can_edit = True
                message = "Вы владелец этой доски"
            else:
                member = db.query(BoardMember).filter(
                    BoardMember.board_id == board.id,
                    BoardMember.user_id == user.id
                ).first()
                if member:
                    can_view = True
                    can_edit = member.role in ["owner", "collaborator"]
                    message = f"Вы участник с ролью {member.role}"
    if not can_view and board.is_public:
        can_view = True
        can_edit = False
        message = "Доска публичная"
    if not can_view:
        message = "Доска приватная и вы не имеете к ней доступа"
    return BoardAccessResponse(
        has_access=can_view or can_edit,
        can_view=can_view,
        can_edit=can_edit,
        board_id=board.id,
        board_name=board.name,
        message=message
    )

@app.get("/api/boards/code/{board_code}")
@sanitize_input
def get_board_by_code(
        board_code: str,
        with_content: bool = Query(False, description="Включить контент доски"),
        db: Session = Depends(get_db)
):
    logger.info(f"=== ЗАПРОС ДОСКИ ПО КОДУ ===")
    logger.info(f"board_code: {board_code}, with_content: {with_content}")
    board = db.query(Board).filter(Board.board_code == board_code).first()
    if not board:
        logger.error(f"Доска с кодом {board_code} не найдена")
        raise HTTPException(status_code=404, detail="Доска не найдена")
    logger.info(f"Найдена доска: id={board.id}, name='{board.name}', is_public={board.is_public}")
    owner = db.query(User).filter(User.id == board.owner_id).first()
    owner_username = owner.username if owner else "Неизвестно"
    logger.info(f"Владелец доски: id={board.owner_id}, username='{owner_username}'")
    content_count = db.query(ContentItem).filter(ContentItem.board_id == board.id).count()
    logger.info(f"Количество контента на доске: {content_count}")
    members_by_role = db.query(
        BoardMember.role,
        func.count(BoardMember.role).label('count')
    ).filter(
        BoardMember.board_id == board.id
    ).group_by(BoardMember.role).all()
    logger.info(f"Участники из board_members: {members_by_role}")
    members_count = {
        "total": 0,
        "owner": 0,
        "collaborator": 0,
        "editor": 0,
        "viewer": 0
    }
    for role, count in members_by_role:
        if role in members_count:
            members_count[role] = count
            members_count["total"] += count
    members_count["owner"] += 1
    members_count["total"] += 1
    logger.info(f"Итоговые счетчики участников: {members_count}")
    result = {
        "id": board.id,
        "name": board.name,
        "description": board.description,
        "owner_username": owner_username,
        "board_code": board.board_code,
        "is_public": board.is_public,
        "view_token": board.view_token,
        "created_at": board.created_at.isoformat(),
        "content_count": content_count,
        "members_count": members_count,
        "board_settings": {
            "background_color": board.background_color if board.background_color else "#FFFBF0",
            "border_color": board.border_color if board.border_color else "#5D4037",
            "board_width": board.board_width if board.board_width else 1200,
            "board_height": board.board_height if board.board_height else 900
        },
        "background_color": board.background_color if board.background_color else "#FFFBF0",
        "border_color": board.border_color if board.border_color else "#5D4037",
        "board_width": board.board_width if board.board_width else 1200,
        "board_height": board.board_height if board.board_height else 900
    }
    logger.info(f"Настройки доски: bg={result['background_color']}, border={result['border_color']}, "
                f"size={result['board_width']}x{result['board_height']}")
    if with_content:
        logger.info("Запрошен контент доски, загружаем...")
        content_items = db.query(ContentItem).filter(
            ContentItem.board_id == board.id
        ).order_by(ContentItem.z_index.asc()).all()
        logger.info(f"Найдено элементов контента: {len(content_items)}")
        content_response = []
        for item in content_items:
            item_data = {
                "id": item.id,
                "type": item.type,
                "content": item.content,
                "x_position": item.x_position,
                "y_position": item.y_position,
                "width": item.width,
                "height": item.height,
                "z_index": item.z_index if item.z_index else 1,
                "media_metadata": item.media_metadata,
                "created_at": item.created_at.isoformat(),
                "content_url": None
            }
            if item.type in ["image", "text"]:
                if item.content.startswith("/static/"):
                    item_data["content_url"] = get_file_url(item.content)
                elif item.content:
                    item_data["content_url"] = item.content
            if item.type == "text" and item.media_metadata:
                item_data["file_info"] = {
                    "preview": item.media_metadata.get(
                        "content_preview",
                        item.content[:100] + "..." if len(item.content) > 100 else item.content
                    )
                }
            content_response.append(item_data)
        result["content"] = content_response
        logger.info(f"Контент успешно добавлен в ответ ({len(content_response)} элементов)")
    logger.info(f"=== УСПЕШНО ВОЗВРАЩЕН ОТВЕТ ДЛЯ ДОСКИ {board_code} ===")
    return result

@app.get("/api/boards/code/{board_code}/view")
@sanitize_input
def get_board_by_code_for_view(board_code: str, db: Session = Depends(get_db)):
    logger.info(f"Запрос доски для просмотра по коду: {board_code}")
    board = db.query(Board).filter(Board.board_code == board_code).first()
    if not board:
        logger.warning(f"Доска с кодом {board_code} не найдена")
        raise HTTPException(status_code=404, detail="Доска не найдена")
    logger.info(f"Найдена доска: id={board.id}, name={board.name}, is_public={board.is_public}")
    if not board.is_public:
        logger.warning(f"Доска {board.id} приватная, доступ запрещен")
        raise HTTPException(
            status_code=403,
            detail="Доска приватная. Только владелец и участники могут её просматривать"
        )
    logger.info(f"Найдена доска: id={board.id}, name={board.name}, is_public={board.is_public}")
    if not board.is_public:
        logger.warning(f"Доска {board.id} приватная, доступ запрещен")
        raise HTTPException(
            status_code=403,
            detail="Доска приватная. Только владелец и участники могут её просматривать"
        )
    owner = db.query(User).filter(User.id == board.owner_id).first()
    content_items = db.query(ContentItem).filter(
        ContentItem.board_id == board.id
    ).order_by(ContentItem.z_index.asc()).all()
    logger.info(f"Найдено элементов контента: {len(content_items)}")
    content_response = []
    for item in content_items:
        item_data = {
            "id": item.id,
            "type": item.type,
            "content": item.content,
            "x_position": item.x_position,
            "y_position": item.y_position,
            "width": item.width,
            "height": item.height,
            "z_index": item.z_index if item.z_index else 1,
            "media_metadata": item.media_metadata,
            "created_at": item.created_at.isoformat(),
            "content_url": None
        }
        if item.type in ["image", "text"]:
            if item.content.startswith("/static/"):
                item_data["content_url"] = get_file_url(item.content)
            elif item.content:
                item_data["content_url"] = item.content
        if item.type == "text" and item.media_metadata:
            item_data["file_info"] = {
                "preview": item.media_metadata.get(
                    "content_preview",
                    item.content[:100] + "..." if len(item.content) > 100 else item.content
                )
            }
        content_response.append(item_data)
    result = {
        "board": {
            "id": board.id,
            "name": board.name,
            "description": board.description,
            "owner_username": owner.username if owner else "Неизвестно",
            "is_public": board.is_public,
            "board_code": board.board_code,
            "created_at": board.created_at.isoformat()
        },
        "content": content_response
    }
    logger.info(f"Успешно подготовлены данные для доски {board.id}")
    return result

@app.get("/api/boards/{board_id}/public-settings")
@sanitize_input
def get_public_board_settings(
        board_id: int,
        db: Session = Depends(get_db)
):
    try:
        print(f"📥 GET /api/boards/{board_id}/public-settings - запрос настроек публичной доски")
        board = db.query(Board).filter(Board.id == board_id).first()
        if not board:
            print(f"❌ Доска {board_id} не найдена")
            raise HTTPException(status_code=404, detail="Доска не найдена")
        print(f"🔍 Найдена доскс: id={board.id}, name={board.name}, is_public={board.is_public}")
        if not board.is_public:
            print(f"❌ Доска {board_id} приватная, доступ запрещен")
            raise HTTPException(
                status_code=403,
                detail="Доска приватная. Только владелец и участники могут просматривать настройки"
            )
        print(f"✅ Настройки публичной доски {board_id} получены: "
              f"bg={board.background_color}, border={board.border_color}, "
              f"size={board.board_width}x{board.board_height}")
        return {
            "background_color": board.background_color,
            "border_color": board.border_color,
            "board_width": board.board_width,
            "board_height": board.board_height
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Ошибка в get_public_board_settings: {e}")
        raise HTTPException(status_code=500, detail=f"Внутренняя ошибка сервера: {str(e)}")

@app.post("/api/auth/login", response_model=WebsiteAuthResponse)
@sanitize_input
def website_login(auth: WebsiteLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.website_login == auth.login).first()
    if not user:
        return WebsiteAuthResponse(
            success=False,
            message="Неверный логин или пароль"
        )
    if not user.hashed_password or not pwd_context.verify(auth.password, user.hashed_password):
        return WebsiteAuthResponse(
            success=False,
            message="Неверный логин или пароль"
        )
    access_token = create_access_token(
        data={"user_id": user.id, "username": user.username}
    )
    return WebsiteAuthResponse(
        success=True,
        access_token=access_token,
        user_id=user.id,
        telegram_id=user.telegram_id,
        username=user.username,
        message="Вход выполнен успешно"
    )

@app.get("/api/auth/validate")
@sanitize_input
def validate_token(current_user: User = Depends(get_current_user)):
    return {
        "valid": True,
        "user_id": current_user.id,
        "username": current_user.username,
        "telegram_id": current_user.telegram_id
    }

@app.put("/api/boards/{board_id}/settings")
@sanitize_input
def update_board_settings(
        board_id: int,
        settings: BoardSettingsUpdate,
        telegram_id: int = Query(..., description="Telegram ID пользователя"),
        db: Session = Depends(get_db)
):
    logger.info(f"Обновление ВСЕХ настроек доски {board_id}, telegram_id: {telegram_id}")
    logger.info(f"Данные настроек: {settings.dict(exclude_unset=True)}")
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        logger.error(f"Пользователь с telegram_id={telegram_id} не найден")
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    logger.info(f"Найден пользователь: id={user.id}, telegram_id={user.telegram_id}")
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        logger.error(f"Доска {board_id} не найдена")
        raise HTTPException(status_code=404, detail="Доска не найдена")
    logger.info(f"Проверка прав: board.owner_id={board.owner_id}, user.id={user.id}")
    if board.owner_id != user.id:
        logger.error(f"Пользователь {user.id} не является владельцем доски {board_id}")
        raise HTTPException(
            status_code=403,
            detail="Только владелец может изменять настройки доски"
        )
    logger.info(f"Пользователь {user.id} является владельцем доски {board_id}")
    updated_fields = []
    if settings.name is not None:
        if len(settings.name.strip()) < 2:
            raise HTTPException(status_code=400, detail="Название должно содержать минимум 2 символа")
        if len(settings.name.strip()) > 100:
            raise HTTPException(status_code=400, detail="Название слишком длинное (максимум 100 символов)")
        board.name = settings.name.strip()
        updated_fields.append("name")
    if settings.description is not None:
        if len(settings.description) > 500:
            raise HTTPException(status_code=400, detail="Описание слишком длинное (максимум 500 символов)")
        board.description = settings.description
        updated_fields.append("description")
    if settings.is_public is not None:
        board.is_public = settings.is_public
        updated_fields.append("is_public")
    if settings.background_color is not None:
        board.background_color = settings.background_color
        updated_fields.append("background_color")
    if settings.border_color is not None:
        board.border_color = settings.border_color
        updated_fields.append("border_color")
    if settings.board_width is not None:
        board.board_width = settings.board_width
        updated_fields.append("board_width")
    if settings.board_height is not None:
        board.board_height = settings.board_height
        updated_fields.append("board_height")
    if updated_fields:
        try:
            db.commit()
            logger.info(f"Все настройки доски {board_id} обновлены: {', '.join(updated_fields)}")
            return {
                "success": True,
                "message": "Настройки доски обновлены",
                "updated_fields": updated_fields,
                "board": {
                    "id": board.id,
                    "name": board.name,
                    "description": board.description,
                    "is_public": board.is_public,
                    "board_code": board.board_code,
                    "background_color": board.background_color,
                    "border_color": board.border_color,
                    "board_width": board.board_width,
                    "board_height": board.board_height
                }
            }
        except Exception as e:
            db.rollback()
            logger.error(f"Ошибка при сохранении в БД: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Ошибка базы данных: {str(e)}")
    else:
        logger.warning("Нет данных для обновления в запросе")
        return {"success": False, "message": "Нет данных для обновления"}

@app.get("/api/boards/{board_id}")
@sanitize_input
def get_board_info(
        board_id: int,
        telegram_id: int = Query(None, description="Telegram ID пользователя (опционально)"),
        db: Session = Depends(get_db)
):
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        raise HTTPException(status_code=404, detail="Доска не найдена")
    owner = db.query(User).filter(User.id == board.owner_id).first()
    content_count = db.query(ContentItem).filter(ContentItem.board_id == board_id).count()
    members_by_role = db.query(
        BoardMember.role,
        func.count(BoardMember.role).label('count')
    ).filter(
        BoardMember.board_id == board_id
    ).group_by(BoardMember.role).all()
    members_count = {
        "total": 0,
        "owner": 0,
        "collaborator": 0,
        "editor": 0,
        "viewer": 0
    }
    for role, count in members_by_role:
        members_count[role] = count
        members_count["total"] += count
    members_count["owner"] += 1
    members_count["total"] += 1
    user_role = None
    if telegram_id:
        user = db.query(User).filter(User.telegram_id == telegram_id).first()
        if user:
            if user.id == board.owner_id:
                user_role = "owner"
            else:
                member = db.query(BoardMember).filter(
                    BoardMember.board_id == board_id,
                    BoardMember.user_id == user.id
                ).first()
                if member:
                    user_role = member.role
    result = {
        "id": board.id,
        "name": board.name,
        "description": board.description,
        "board_code": board.board_code,
        "is_public": board.is_public,
        "owner_id": board.owner_id,
        "owner_username": owner.username if owner else "Неизвестно",
        "content_count": content_count,
        "members_count": members_count,
        "created_at": board.created_at.isoformat()
    }
    if telegram_id:
        result["user_role"] = user_role
    return result

@app.get("/api/users/{user_id}")
@sanitize_input
def get_user_by_id(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return {
        "id": user.id,
        "telegram_id": user.telegram_id,
        "username": user.username,
        "website_login": user.website_login,
        "is_registered": user.is_registered,
        "created_at": user.created_at.isoformat() if user.created_at else None
    }

@app.get("/api/users/telegram/{telegram_id}")
@sanitize_input
def get_user_by_telegram_id(telegram_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return {
        "id": user.id,
        "telegram_id": user.telegram_id,
        "username": user.username,
        "website_login": user.website_login,
        "is_registered": user.is_registered,
        "created_at": user.created_at.isoformat() if user.created_at else None
    }

@app.get("/api/boards/token/{view_token}")
@sanitize_input
def get_board_by_token(view_token: str, db: Session = Depends(get_db)):
    board = db.query(Board).filter(Board.view_token == view_token).first()
    if not board:
        raise HTTPException(status_code=404, detail="Доска не найдена")
    owner = db.query(User).filter(User.id == board.owner_id).first()
    return {
        "id": board.id,
        "name": board.name,
        "description": board.description,
        "owner_username": owner.username if owner else "Неизвестно",
        "board_code": board.board_code,
        "is_public": board.is_public,
        "view_token": board.view_token,
        "created_at": board.created_at.isoformat()
    }

@app.get("/api/boards/{board_id}/user-role/{telegram_id}")
@sanitize_input
def get_user_role_on_board(
        board_id: int,
        telegram_id: int,
        db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        return {"role": None, "is_owner": False, "has_access": False}
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        return {"role": None, "is_owner": False, "has_access": False}
    if board.owner_id == user.id:
        return {
            "role": "owner",
            "is_owner": True,
            "has_access": True,
            "can_edit": True,
            "can_manage": True
        }
    member = db.query(BoardMember).filter(
        BoardMember.board_id == board_id,
        BoardMember.user_id == user.id
    ).first()
    if member:
        can_edit = member.role in ["owner", "collaborator"]
        return {
            "role": member.role,
            "is_owner": False,
            "has_access": True,
            "can_edit": can_edit,
            "can_manage": False
        }
    return {"role": None, "is_owner": False, "has_access": False}

@app.delete("/api/boards/{board_id}/collaborators/{user_id}")
@sanitize_input
def remove_collaborator(
        board_id: int,
        user_id: int,
        telegram_id: int = Query(..., description="Telegram ID удаляющего"),
        db: Session = Depends(get_db)
):
    logger.info(f"=== НАЧАЛО: Удаление соавтора ===")
    logger.info(f"Доска: {board_id}, user_id: {user_id}, telegram_id: {telegram_id}")
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        logger.error(f"Доска {board_id} не найдена")
        raise HTTPException(status_code=404, detail="Доска не найдена")
    remover = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not remover:
        logger.error(f"Пользователь с telegram_id={telegram_id} не найден")
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    logger.info(f"Пользователь найден: id={remover.id}, telegram_id={remover.telegram_id}")
    logger.info(f"Проверка прав: board.owner_id={board.owner_id}, remover.id={remover.id}")
    if board.owner_id != remover.id:
        logger.error(f"Пользователь {remover.id} не является владельцем доски {board_id}")
        raise HTTPException(
            status_code=403,
            detail="Только владелец может удалять соавторов"
        )
    member_to_remove = db.query(BoardMember).filter(
        BoardMember.board_id == board_id,
        BoardMember.user_id == user_id,
        BoardMember.role == "collaborator"
    ).first()
    if not member_to_remove:
        logger.error(f"Соавтор с user_id={user_id} не найден на доске {board_id}")
        raise HTTPException(
            status_code=404,
            detail="Соавтор не найден на этой доске"
        )
    user_to_remove = db.query(User).filter(User.id == user_id).first()
    if not user_to_remove:
        logger.warning(f"Пользователь с id={user_id} не найден, но запись в BoardMember существует")
    db.delete(member_to_remove)
    db.commit()
    username = user_to_remove.username if user_to_remove else "unknown"
    logger.info(f"=== УСПЕХ: Соавтор @{username} удален с доски {board_id} ===")
    return {
        "success": True,
        "message": f"Соавтор @{username} удален"
    }

@app.get("/api/boards/{board_id}/collaborators")
@sanitize_input
def get_board_collaborators(
        board_id: int,
        telegram_id: int = Query(..., description="Telegram ID запрашивающего"),
        db: Session = Depends(get_db)
):
    logger.info(f"=== НАЧАЛО: Получение списка соавторов ===")
    logger.info(f"Доска: {board_id}, telegram_id: {telegram_id}")
    try:
        board = db.query(Board).filter(Board.id == board_id).first()
        if not board:
            logger.error(f"Доска {board_id} не найдена")
            raise HTTPException(status_code=404, detail="Доска не найдена")
        requester = db.query(User).filter(User.telegram_id == telegram_id).first()
        if not requester:
            logger.error(f"Пользователь с telegram_id={telegram_id} не найден")
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        logger.info(f"Пользователь найден: id={requester.id}, telegram_id={requester.telegram_id}")
        logger.info(f"Проверка прав: board.owner_id={board.owner_id}, requester.id={requester.id}")
        if board.owner_id != requester.id:
            logger.info(f"Пользователь {requester.id} не является владельцем, возвращаем пустой список")
            return {
                "board_id": board_id,
                "board_name": board.name,
                "collaborators_count": 0,
                "collaborators": []
            }
        logger.info(f"Пользователь {requester.id} является владельцем доски {board_id}")
        try:
            collaborators = db.query(BoardMember, User).join(
                User, BoardMember.user_id == User.id
            ).filter(
                BoardMember.board_id == board_id,
                BoardMember.role == "collaborator"
            ).all()
            logger.info(f"Найдено записей в БД: {len(collaborators)}")
        except Exception as db_error:
            logger.error(f"Ошибка БД при получении соавторов: {db_error}", exc_info=True)
            collaborators = []
        result = []
        for member, user in collaborators:
            try:
                if not user:
                    logger.warning(f"Пользователь не найден для member {member.id}")
                    continue
                result.append({
                    "user_id": user.id,
                    "username": user.username if user.username else "Неизвестно",
                    "telegram_username": user.username if user.username else "",
                    "role": member.role if member.role else "collaborator",
                })
            except Exception as e:
                logger.error(f"Ошибка при обработке записи соавтора: {e}")
                continue
        logger.info(f"=== УСПЕХ: Найдено {len(result)} соавторов для доски {board_id} ===")
        return {
            "board_id": board_id,
            "board_name": board.name,
            "collaborators_count": len(result),
            "collaborators": result
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"=== ОШИБКА в get_board_collaborators: {e} ===", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Внутренняя ошибка сервера: {str(e)}"
        )

@app.get("/api/boards/{board_id}/extended")
@sanitize_input
def get_board_extended_info(
        board_id: int,
        telegram_id: int = Query(..., description="Telegram ID пользователя"),
        db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        raise HTTPException(status_code=404, detail="Доска не найдена")
    owner = db.query(User).filter(User.id == board.owner_id).first()
    content_count = db.query(ContentItem).filter(ContentItem.board_id == board_id).count()
    members_by_role = db.query(
        BoardMember.role,
        func.count(BoardMember.role).label('count')
    ).filter(
        BoardMember.board_id == board_id
    ).group_by(BoardMember.role).all()
    members_count = {
        "total": 0,
        "owner": 0,
        "collaborator": 0,
        "editor": 0,
        "viewer": 0
    }
    for role, count in members_by_role:
        if role in members_count:
            members_count[role] = count
            members_count["total"] += count
    members_count["owner"] += 1
    members_count["total"] += 1
    user_role = None
    if board.owner_id == user.id:
        user_role = "owner"
    else:
        member = db.query(BoardMember).filter(
            BoardMember.board_id == board_id,
            BoardMember.user_id == user.id
        ).first()
        if member:
            user_role = member.role
    return {
        "id": board.id,
        "name": board.name,
        "description": board.description,
        "board_code": board.board_code,
        "is_public": board.is_public,
        "owner_id": board.owner_id,
        "owner_username": owner.username if owner else "Неизвестно",
        "content_count": content_count,
        "collaborators_count": members_count["collaborator"],
        "members_count": members_count,
        "user_role": user_role,
        "can_edit": user_role in ["owner", "collaborator"],
        "can_manage": user_role == "owner",
        "created_at": board.created_at.isoformat()
    }

@app.get("/api/users/{telegram_id}/boards-with-roles")
@sanitize_input
def get_user_boards_with_roles(
        telegram_id: int,
        db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    owned_boards = db.query(Board).filter(Board.owner_id == user.id).all()
    member_boards = db.query(Board).join(BoardMember).filter(
        BoardMember.user_id == user.id,
        BoardMember.board_id == Board.id
    ).all()
    all_boards = []
    for board in owned_boards:
        all_boards.append({
            "id": board.id,
            "name": board.name,
            "description": board.description,
            "board_code": board.board_code,
            "is_public": board.is_public,
            "owner_id": board.owner_id,
            "user_role": "owner",
            "is_owner": True
        })
    for board in member_boards:
        member = db.query(BoardMember).filter(
            BoardMember.board_id == board.id,
            BoardMember.user_id == user.id
        ).first()
        if board.owner_id != user.id:
            all_boards.append({
                "id": board.id,
                "name": board.name,
                "description": board.description,
                "board_code": board.board_code,
                "is_public": board.is_public,
                "owner_id": board.owner_id,
                "user_role": member.role if member else "unknown",
                "is_owner": False
            })
    return all_boards

@app.get("/api/stats")
@sanitize_input
def get_stats(db: Session = Depends(get_db)):
    users_count = db.query(User).count()
    boards_count = db.query(Board).count()
    content_count = db.query(ContentItem).count()
    content_by_type = db.query(
        ContentItem.type,
        func.count(ContentItem.id).label('count')
    ).group_by(ContentItem.type).all()
    content_stats = {item.type: item.count for item in content_by_type}
    public_boards = db.query(Board).filter(Board.is_public == True).count()
    private_boards = boards_count - public_boards
    members_by_role = db.query(
        BoardMember.role,
        func.count(BoardMember.role).label('count')
    ).group_by(BoardMember.role).all()
    role_stats = {role: count for role, count in members_by_role}
    redis_connected = False
    if redis_conn:
        try:
            redis_connected = redis_conn.ping()
        except Exception:
            redis_connected = False
    return {
        "users": users_count,
        "boards": boards_count,
        "content": content_count,
        "content_by_type": content_stats,
        "members_by_role": role_stats,
        "public_boards": public_boards,
        "private_boards": private_boards,
        "upload_directory": str(UPLOAD_DIR.absolute()),
        "redis_connected": redis_connected,
        "security": {
            "sql_injection_protection": "enabled",
            "blocked_attempts": security_config.get_blocked_attempts()
        }
    }

@app.put("/api/boards/{board_id}/content/{content_id}/layer")
@sanitize_input
def update_content_layer(
        board_id: int,
        content_id: int,
        layer_data: LayerUpdateRequest,
        telegram_id: int = Query(..., description="Telegram ID пользователя"),
        db: Session = Depends(get_db)
):
    content = db.query(ContentItem).filter(
        ContentItem.id == content_id,
        ContentItem.board_id == board_id
    ).first()
    if not content:
        raise HTTPException(status_code=404, detail="Контент не найден")
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    board = db.query(Board).filter(Board.id == board_id).first()
    is_owner = board.owner_id == user.id
    is_content_creator = content.created_by == user.id
    member = db.query(BoardMember).filter(
        BoardMember.board_id == board_id,
        BoardMember.user_id == user.id
    ).first()
    can_edit = is_owner or is_content_creator or (member and member.role in ["owner", "collaborator"])
    if not can_edit:
        raise HTTPException(
            status_code=403,
            detail="Недостаточно прав для изменения слоя"
        )
    all_items = db.query(ContentItem).filter(
        ContentItem.board_id == board_id
    ).order_by(ContentItem.z_index.asc()).all()
    if len(all_items) <= 1:
        return {
            "success": True,
            "message": "Только один элемент на доске",
            "content": {
                "id": content.id,
                "z_index": content.z_index
            }
        }
    current_index = next((i for i, item in enumerate(all_items) if item.id == content_id), -1)
    if current_index == -1:
        raise HTTPException(status_code=500, detail="Элемент не найден в списке")
    operation = layer_data.operation
    try:
        if operation == "raise":
            if current_index < len(all_items) - 1:
                item_above = all_items[current_index + 1]
                content.z_index, item_above.z_index = item_above.z_index, content.z_index
                db.add(item_above)
                db.add(content)
        elif operation == "lower":
            if current_index > 0:
                item_below = all_items[current_index - 1]
                content.z_index, item_below.z_index = item_below.z_index, content.z_index
                db.add(item_below)
                db.add(content)
        elif operation == "to_top":
            max_z_index = max([item.z_index for item in all_items])
            content.z_index = max_z_index + 1
            db.add(content)
        elif operation == "to_bottom":
            min_z_index = min([item.z_index for item in all_items])
            content.z_index = max(1, min_z_index - 1)
            db.add(content)
        else:
            raise HTTPException(status_code=400, detail="Неизвестная операция")
        db.commit()
        db.refresh(content)
        all_items_updated = db.query(ContentItem).filter(
            ContentItem.board_id == board_id
        ).order_by(ContentItem.z_index.asc()).all()
        for i, item in enumerate(all_items_updated):
            if item.z_index != i + 1:
                item.z_index = i + 1
                db.add(item)
        db.commit()
        return {
            "success": True,
            "message": f"Слой элемента изменен: {operation}",
            "content": {
                "id": content.id,
                "z_index": content.z_index,
                "new_position": f"{current_index + 1} из {len(all_items)}"
            }
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Ошибка при изменении слоя: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при изменении слоя: {str(e)}"
        )

@app.get("/api/boards/{board_id}/content/ordered")
@sanitize_input
def get_board_content_ordered(
        board_id: int,
        db: Session = Depends(get_db)
):
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        raise HTTPException(status_code=404, detail="Доска не найдена")
    content_items = db.query(ContentItem) \
        .filter(ContentItem.board_id == board_id) \
        .order_by(ContentItem.z_index.asc()) \
        .all()
    response_items = []
    for item in content_items:
        item_data = {
            "id": item.id,
            "board_id": item.board_id,
            "type": item.type,
            "content": item.content,
            "x_position": item.x_position,
            "y_position": item.y_position,
            "width": item.width,
            "height": item.height,
            "z_index": item.z_index if item.z_index else 1,
            "media_metadata": item.media_metadata,
            "created_at": item.created_at.isoformat(),
            "content_url": None
        }
        if item.type in ["image", "text"]:
            if item.content.startswith("/static/"):
                item_data["content_url"] = get_file_url(item.content)
            elif item.content:
                item_data["content_url"] = item.content
        if item.type == "text" and item.media_metadata:
            item_data["file_info"] = {
                "preview": item.media_metadata.get("content_preview", item.content[:100] + "..." if len(
                    item.content) > 100 else item.content)
            }
        response_items.append(item_data)
    return response_items

@app.get("/api/users/{telegram_id}/files")
@sanitize_input
def get_user_files(
        telegram_id: int,
        file_type: Optional[str] = None,
        db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    safe_db = SafeDB()
    query = db.query(ContentItem).filter(
        ContentItem.created_by == user.id,
        ContentItem.content.like('/static/%')
    )
    if file_type and file_type != "all":
        query = query.filter(ContentItem.type == file_type)
    files = query.order_by(ContentItem.created_at.desc()).all()
    result = []
    for item in files:
        file_info = {
            "id": item.id,
            "filename": item.content.split('/')[-1] if item.content.startswith('/static/') else item.content[:50],
            "url": item.content if item.content.startswith('/static/') else None,
            "type": item.type,
            "size": item.media_metadata.get('file_size') if item.media_metadata else None,
            "board_id": item.board_id,
            "created_at": item.created_at.isoformat(),
            "preview": item.media_metadata.get(
                'content_preview') if item.type == "text" and item.media_metadata else None
        }
        result.append(file_info)
    return {
        "user_id": user.id,
        "username": user.username,
        "files_count": len(files),
        "files": result
    }

@app.get("/api/security/status")
def get_security_status():
    return {
        "sql_injection_protection": {
            "enabled": True,
            "middleware": "active",
            "input_validation": "active",
            "query_sanitization": "active",
            "blocked_attempts": security_config.get_blocked_attempts()
        },
        "password_security": {
            "hashing_algorithm": "sha256_crypt",
            "min_password_length": 8,
            "max_password_length": 50
        },
        "jwt_security": {
            "algorithm": ALGORITHM,
            "token_expiry_minutes": ACCESS_TOKEN_EXPIRE_MINUTES
        },
        "file_upload": {
            "max_file_size_mb": 10,
            "allowed_types": ["image", "text"],
            "upload_directory": str(UPLOAD_DIR.absolute())
        },
        "recommendations": [
            "Используйте HTTPS в production",
            "Настройте firewall правила",
            "Регулярно обновляйте зависимости",
            "Настройте rate limiting для API"
        ]
    }

@app.delete("/api/boards/{board_id}/members/{user_id}")
@sanitize_input
def remove_board_member(
        board_id: int,
        user_id: int,
        telegram_id: int = Query(..., description="Telegram ID удаляющего"),
        db: Session = Depends(get_db)
):
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        raise HTTPException(status_code=404, detail="Доска не найдена")
    remover = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not remover:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if board.owner_id != remover.id:
        raise HTTPException(
            status_code=403,
            detail="Только владелец может удалять участников с доски"
        )
    if user_id == remover.id:
        raise HTTPException(
            status_code=400,
            detail="Владелец не может удалить себя с доски"
        )
    member = db.query(BoardMember).filter(
        BoardMember.board_id == board_id,
        BoardMember.user_id == user_id
    ).first()
    if not member:
        raise HTTPException(
            status_code=404,
            detail="Участник не найден на этой доске"
        )
    db.delete(member)
    db.commit()
    return {
        "success": True,
        "message": "Участник успешно удален с доски"
    }

@app.get("/api/boards/{board_id}/settings")
async def get_board_settings(
        board_id: int,
        telegram_id: str = Query(..., description="Telegram ID пользователя"),
        db: Session = Depends(get_db)
):
    try:
        print(f"📥 GET /api/boards/{board_id}/settings - telegram_id: {telegram_id}")
        user = db.query(User).filter(User.telegram_id == telegram_id).first()
        if not user:
            print(f"❌ Пользователь с telegram_id={telegram_id} не найден")
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        print(f"🔍 Найден пользователь: id={user.id}, telegram_id={user.telegram_id}")
        board = db.query(Board).filter(Board.id == board_id).first()
        if not board:
            print(f"❌ Доска {board_id} не найдена")
            raise HTTPException(status_code=404, detail="Доска не найдена")
        print(f"🔍 Проверка доступа: board.owner_id={board.owner_id}, user.id={user.id}")
        if board.owner_id == user.id:
            print(f"✅ Пользователь {user.id} является владельцем доски {board_id}")
        else:
            board_member = db.query(BoardMember).filter(
                BoardMember.board_id == board_id,
                BoardMember.user_id == user.id
            ).first()
            if not board_member:
                print(f"❌ Пользователь {user.id} не имеет доступа к доске {board_id}")
                raise HTTPException(status_code=403, detail="Нет доступа к этой доске")
            print(f"✅ Пользователь {user.id} найден в board_members с ролью {board_member.role}")
        print(f"✅ Настройки доски {board_id} получены: "
              f"bg={board.background_color}, border={board.border_color}, "
              f"size={board.board_width}x{board.board_height}")
        return {
            "background_color": board.background_color,
            "border_color": board.border_color,
            "board_width": board.board_width,
            "board_height": board.board_height
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Ошибка в get_board_settings: {e}")
        raise HTTPException(status_code=500, detail=f"Внутренняя ошибка сервера: {str(e)}")

@app.get("/api/debug/board/{board_id}/members")
async def debug_board_members(
        board_id: int,
        db: Session = Depends(get_db)
):
    try:
        print(f"🔍 Отладка участников доски {board_id}")
        board = db.query(Board).filter(Board.id == board_id).first()
        if not board:
            return {"error": "Доска не найдена"}
        members = db.query(BoardMember).filter(BoardMember.board_id == board_id).all()
        result = {
            "board_id": board_id,
            "board_name": board.name,
            "owner_id": board.owner_id,
            "members_count": len(members),
            "members": [
                {
                    "user_id": member.user_id,
                    "role": member.role
                }
                for member in members
            ]
        }
        print(f"🔍 Результат отладки: {result}")
        return result
    except Exception as e:
        print(f"❌ Ошибка в debug_board_members: {e}")
        return {"error": str(e)}

@app.get("/api/debug/check-owner/{board_id}/{telegram_id}")
@sanitize_input
def debug_check_owner(
        board_id: int,
        telegram_id: int,
        db: Session = Depends(get_db)
):
    logger.info(f"=== ДЕБАГ: Проверка владельца доски ===")
    logger.info(f"Доска: {board_id}, telegram_id: {telegram_id}")
    user = db.query(User).filter(User.telegram_id == telegram_id).first()
    if not user:
        logger.error(f"Пользователь с telegram_id={telegram_id} не найден")
        return {
            "error": "Пользователь не найден",
            "telegram_id": telegram_id,
            "found": False
        }
    logger.info(f"Найден пользователь: id={user.id}, telegram_id={user.telegram_id}, username={user.username}")
    board = db.query(Board).filter(Board.id == board_id).first()
    if not board:
        logger.error(f"Доска {board_id} не найдена")
        return {
            "error": "Доска не найдена",
            "board_id": board_id,
            "found": False
        }
    logger.info(f"Найдена доска: id={board.id}, name={board.name}, owner_id={board.owner_id}")
    is_owner = board.owner_id == user.id
    logger.info(f"Сравнение: board.owner_id={board.owner_id}, user.id={user.id}, is_owner={is_owner}")
    members = db.query(BoardMember).filter(BoardMember.board_id == board_id).all()
    logger.info(f"Участников доски: {len(members)}")
    for member in members:
        member_user = db.query(User).filter(User.id == member.user_id).first()
        logger.info(
            f"  - user_id={member.user_id}, role={member.role}, username={member_user.username if member_user else 'unknown'}")
    return {
        "success": True,
        "user": {
            "id": user.id,
            "telegram_id": user.telegram_id,
            "username": user.username
        },
        "board": {
            "id": board.id,
            "name": board.name,
            "owner_id": board.owner_id
        },
        "is_owner": is_owner,
        "members_count": len(members),
        "members": [
            {
                "user_id": member.user_id,
                "role": member.role
            }
            for member in members
        ]
    }

if __name__ == "__main__":
    import uvicorn

    try:
        logger.info("Запуск MoodBoard API с улучшенной безопасностью...")
        logger.info("✅ Защита от SQL-инъекций активна")
        logger.info("✅ Middleware безопасности активен")
        logger.info("✅ Валидация входных данных активна")
        logger.info("✅ Поддерживаемые типы файлов: image, text")
        logger.info("✅ Добавлена поддержка слоев (z-index)")
        logger.info("✅ Добавлена поддержка изменения размеров")
        logger.info("✅ Новая система ролей: owner, collaborator, editor, viewer")
        logger.info("✅ Добавлен endpoint для просмотра доски по коду: /api/boards/code/{board_code}/view")
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
    except Exception as e:
        logger.error(f"Ошибка запуска приложения: {e}")
        logger.error(traceback.format_exc())