from fastapi import FastAPI, Request, Form, status
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from pymongo import MongoClient
from passlib.context import CryptContext
from datetime import datetime
import requests
import os
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from dotenv import load_dotenv  # ✅ Added missing import

# --- Load environment variables ---
loaded = load_dotenv(override=True)
print(f".env file loaded: {loaded}")

# --- Configuration ---
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM")
raw_expire_minutes = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "10")
print(f"DEBUG: Raw value from os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES'): '{raw_expire_minutes}'")
ACCESS_TOKEN_EXPIRE_MINUTES = int(raw_expire_minutes)

RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")
MONGO_URI = os.getenv("MONGO_URI")

if not all([SECRET_KEY, ALGORITHM, RECAPTCHA_SITE_KEY, RECAPTCHA_SECRET_KEY, MONGO_URI]):
    raise ValueError("Missing critical environment variables. Check your .env file.")

# Initialize app
app = FastAPI()

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

# Session middleware
app.add_middleware(SessionMiddleware, secret_key=os.urandom(24))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# MongoDB connection
client = MongoClient(MONGO_URI)
db = client["projectfast"]
users_collection = db["user"]
logins_collection = db["logins"]
shipment_collection = db["shipments"]

# ---------------------------
# GLOBAL ERROR HANDLERS
# ---------------------------
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse({"detail": str(exc.detail)}, status_code=exc.status_code)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse({"detail": exc.errors()}, status_code=400)

@app.get("/", response_class=HTMLResponse)
def root():
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse, name="login")
def get_login(request: Request):
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("login.html", {"request": request, "site_key": RECAPTCHA_SITE_KEY, "flash": flash})

@app.get("/signup", response_class=HTMLResponse, name="signup")
def get_signup(request: Request):
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("signup.html", {"request": request, "flash": flash})

@app.post("/signup")
def post_signup(
    request: Request,
    fullname: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    role: str = Form(...)
):
    if password != confirm_password:
        request.session["flash"] = "Passwords do not match."
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    if users_collection.find_one({"email": email}):
        request.session["flash"] = "Email already registered."
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    if role not in ["user", "admin"]:
        role = "user"

    password_hash = pwd_context.hash(password)
    users_collection.insert_one({
        "name": fullname,
        "email": email,
        "password_hash": password_hash,
        "role": role,
        "created_at": datetime.utcnow()
    })

    request.session["flash"] = "Account created successfully! Please log in."
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@app.post("/login")
async def post_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    g_recaptcha_response: str = Form(alias="g-recaptcha-response")
):
    recaptcha_verify = requests.post(
        "https://www.google.com/recaptcha/api/siteverify",
        data={"secret": RECAPTCHA_SECRET_KEY, "response": g_recaptcha_response}
    )
    result = recaptcha_verify.json()

    if not result.get("success"):
        request.session["flash"] = "reCAPTCHA failed. Try again."
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    user = users_collection.find_one({"email": username})
    if user and pwd_context.verify(password, user["password_hash"]):
        request.session["username"] = username
        request.session["role"] = user.get("role", "user")

        logins_collection.insert_one({
            "email": username,
            "login_time": datetime.utcnow(),
            "status": "success"
        })

        if user.get("role") == "admin":
            return RedirectResponse(url="/admin-dashboard", status_code=status.HTTP_302_FOUND)
        else:
            return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

    logins_collection.insert_one({
        "email": username,
        "login_time": datetime.utcnow(),
        "status": "failed"
    })
    request.session["flash"] = "Invalid credentials."
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(request: Request):
    username = request.session.get("username")
    role = request.session.get("role")
    if not username or role == "admin":
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("dashboard.html", {"request": request, "name": username})

@app.get("/admin-dashboard", response_class=HTMLResponse)
def get_admin_dashboard(request: Request):
    username = request.session.get("username")
    role = request.session.get("role")
    if not username or role != "admin":
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("admin_dashboard.html", {"request": request, "name": username})

@app.get("/create-shipment", response_class=HTMLResponse)
def get_create_shipment(request: Request):
    username = request.session.get("username")
    if not username:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("create_shipment.html", {
        "request": request,
        "user_name": username,
        "flash": flash
    })

@app.post("/create-shipment", response_class=HTMLResponse)
async def create_shipment(
    request: Request,
    shipment_id: str = Form(...),
    po_number: str = Form(...),
    route_details: str = Form(...),
    device: str = Form(...),
    ndc_number: str = Form(...),
    serial_number: str = Form(...),
    container_number: str = Form(...),
    goods_type: str = Form(...),
    expected_delivery_date: str = Form(...),
    delivery_number: str = Form(...),
    batch_id: str = Form(...),
    origin: str = Form(...),
    destination: str = Form(...),
    status: str = Form(...),
    shipment_description: str = Form(...)
):
    shipment = {
        "shipment_id": shipment_id,
        "po_number": po_number,
        "route_details": route_details,
        "device": device,
        "ndc_number": ndc_number,
        "serial_number": serial_number,
        "container_number": container_number,
        "goods_type": goods_type,
        "expected_delivery_date": expected_delivery_date,
        "delivery_number": delivery_number,
        "batch_id": batch_id,
        "origin": origin,
        "destination": destination,
        "status": status,
        "shipment_description": shipment_description,
        "created_at": datetime.utcnow()
    }

    try:
        shipment_collection.insert_one(shipment)
        flash_message = f"Shipment {shipment_id} created successfully!"
    except Exception as e:
        print(f"Database error: {e}")
        flash_message = f"Error creating shipment: {str(e)}"

    return templates.TemplateResponse("create_shipment.html", {"request": request, "flash": flash_message})

@app.get("/user_management", response_class=HTMLResponse)
def get_user_management(request: Request):
    username = request.session.get("username")
    role = request.session.get("role")
    if not username or role != "admin":
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    users = list(users_collection.find({}, {"_id": 0, "name": 1, "email": 1, "role": 1}))
    return templates.TemplateResponse("user_management.html", {"request": request, "users": users})

@app.get("/edit-shipment", response_class=HTMLResponse)
def get_edit_shipment(request: Request):
    username = request.session.get("username")
    role = request.session.get("role")
    if not username or role != "admin":
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    flash = request.session.pop("flash", None)
    shipments = list(shipment_collection.find({}, {"_id": 0}))
    return templates.TemplateResponse("edit_shipment.html", {
        "request": request,
        "shipments": shipments,
        "flash": flash
    })

@app.post("/edit-shipment")
def post_edit_shipment(
    request: Request,
    shipment_id: str = Form(...),
    status: str = Form(...),
    destination: str = Form(...),
    expected_delivery_date: str = Form(...)
):
    username = request.session.get("username")
    role = request.session.get("role")
    if not username or role != "admin":
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    result = shipment_collection.update_one(
        {"shipment_id": shipment_id},
        {"$set": {
            "status": status,
            "destination": destination,
            "expected_delivery_date": expected_delivery_date,
            "last_updated": datetime.utcnow()
        }}
    )
    if result.modified_count > 0:
        request.session["flash"] = "Shipment updated successfully."
    else:
        request.session["flash"] = "No changes made or shipment not found."
    return RedirectResponse(url="/edit-shipment", status_code=status.HTTP_302_FOUND)

@app.get("/all-shipments", response_class=HTMLResponse)
def get_all_shipments(request: Request):
    username = request.session.get("username")
    role = request.session.get("role")
    if not username:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    shipments = list(shipment_collection.find({}, {"_id": 0}))
    return templates.TemplateResponse("all_shipments.html", {"request": request, "shipments": shipments, "role": role})

@app.get("/account", response_class=HTMLResponse)
def account_page(request: Request):
    username = request.session.get("username")
    if not username:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    user = users_collection.find_one({"email": username}, {"_id": 0, "name": 1, "email": 1, "role": 1, "created_at": 1})
    if not user:
        request.session["flash"] = "User not found."
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("account.html", {"request": request, "user": user})

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    request.session["flash"] = "Logged out successfully."
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
