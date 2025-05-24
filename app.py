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

# --- Load environment variables ---


# --- Configuration ---

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM")
raw_expire_minutes = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "10")
print(f"DEBUG: Raw value from os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES'): '{raw_expire_minutes}'")


ACCESS_TOKEN_EXPIRE_MINUTES = int(raw_expire_minutes)

RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

 
SECRET_KEY="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ALGORITHM="HS256" 
 
ACCESS_TOKEN_EXPIRE_MINUTES=10
MONGO_URI= os.getenv("MONGO_URI")
RECAPTCHA_SITE_KEY="6Lca5TArAAAAADRedne525SsKt5jf-252ADg2uBS"
RECAPTCHA_SECRET_KEY="6Lca5TArAAAAAK2-XxkeJ1sOcIbu__yFhgBU4JWM"
 
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
MONGO_URI = "mongodb+srv://bhargavmadhiraju123:Bharghav123@cluster0.p6h7hjw.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGO_URI)
db = client["projectfast"]
users_collection = db["user"]
logins_collection = db["logins"]
shipment_collection = db["shipments"]
collection = db['sensor_data_collection']

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
    confirm_password: str = Form(...)
):
    if password != confirm_password:
        request.session["flash"] = "Passwords do not match."
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    if users_collection.find_one({"email": email}):
        request.session["flash"] = "Email already registered."
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    password_hash = pwd_context.hash(password)
    users_collection.insert_one({
        "name": fullname,
        "email": email,
        "password_hash": password_hash,
        "role": "user",
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

        return RedirectResponse(
            url="/admin-dashboard" if user.get("role") == "admin" else "/dashboard",
            status_code=status.HTTP_302_FOUND
        )

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

def user_management(request: Request):

    if request.session.get("role") != "admin":

        return RedirectResponse("/login", status_code=status.HTTP_302_FOUND)

    users = list(users_collection.find({}, {"_id": 0, "name": 1, "email": 1, "role": 1}))

    return templates.TemplateResponse("user_management.html", {"request": request, "users": users})



@app.get("/edit-users/{email}", response_class=HTMLResponse)

async def get_edit_user(request: Request, email: str):

    user = users_collection.find_one({"email": email}, {"_id": 0, "name": 1, "role": 1, "email": 1})

    flash = request.session.pop("flash", None)

    if not user:

        request.session["flash"] = "User not found."

        return RedirectResponse("/user_management", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse("edit_users.html", {"request": request, "user": user, "flash": flash})



@app.post("/update-user/{email}")

async def update_user(request: Request, email: str, name: str = Form(...), new_email: str = Form(...), role: str = Form(...)):

    result = users_collection.update_one(

        {"email": email},

        {"$set": {"name": name, "email": new_email, "role": role}}

    )

    if result.modified_count == 1:

        request.session["flash"] = "User updated successfully."

    else:

        request.session["flash"] = "No changes made or user not found."

    return RedirectResponse("/user_management", status_code=status.HTTP_302_FOUND)



@app.get("/delete-user/{email}")

def delete_user(email: str, request: Request):

    users_collection.delete_one({"email": email})

    request.session["flash"] = "User deleted."

    return RedirectResponse("/user_management", status_code=status.HTTP_302_FOUND)

@app.get("/assign-admin/{email}")
def assign_admin(email: str, request: Request):
    user = users_collection.find_one({"email": email})
    if not user:
        request.session["flash"] = "User not found."
        return RedirectResponse("/user_management", status_code=status.HTTP_302_FOUND)
    result = users_collection.update_one({"email": email}, {"$set": {"role": "admin"}})
    if result.modified_count == 1:
        request.session["flash"] = f"{email} is now an admin."
    else:
        request.session["flash"] = "No changes made or user already admin."
    return RedirectResponse("/user_management", status_code=status.HTTP_302_FOUND)

# ...existing code...
import logging

# Create a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create a file handler and a stream handler
file_handler = logging.FileHandler('app.log')
stream_handler = logging.StreamHandler()

# Create a formatter and set it for the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# Add logs to the existing code
@app.get("/", response_class=HTMLResponse)
def root():
    logger.info('Root endpoint accessed')
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse, name="login")
def get_login(request: Request):
    logger.info('Login endpoint accessed')
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("login.html", {"request": request, "site_key": RECAPTCHA_SITE_KEY, "flash": flash})

@app.get("/signup", response_class=HTMLResponse, name="signup")
def get_signup(request: Request):
    logger.info('Signup endpoint accessed')
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
    logger.info('Signup form submitted')
    if password != confirm_password:
        request.session["flash"] = "Passwords do not match."
        logger.warning('Passwords do not match')
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    if users_collection.find_one({"email": email}):
        request.session["flash"] = "Email already registered."
        logger.warning('Email already registered')
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
    logger.info('Account created successfully')
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@app.post("/login")
async def post_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    g_recaptcha_response: str = Form(alias="g-recaptcha-response")
):
    logger.info('Login form submitted')
    recaptcha_verify = requests.post(
        "https://www.google.com/recaptcha/api/siteverify",
        data={"secret": RECAPTCHA_SECRET_KEY, "response": g_recaptcha_response}
    )
    result = recaptcha_verify.json()

    if not result.get("success"):
        request.session["flash"] = "reCAPTCHA failed. Try again."
        logger.warning('reCAPTCHA failed')
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

        logger.info('Login successful')
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
    logger.warning('Invalid credentials')
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

# Add logs to the rest of the endpoints in a similar manner
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

@app.get("/delete-shipment/{shipment_id}")
def delete_shipment(shipment_id: str, request: Request):
    username = request.session.get("username")
    role = request.session.get("role")
    if not username or role != "admin":
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    result = shipment_collection.delete_one({"shipment_id": shipment_id})
    if result.deleted_count > 0:
        request.session["flash"] = "Shipment deleted successfully."
    else:
        request.session["flash"] = "Shipment not found or already deleted."

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

@app.get("/device-data", response_class=HTMLResponse)
async def device_data(request: Request):
    data = list(collection.find().sort([('_id', -1)]).limit(10))
    # Convert ObjectId to string
    formatted_data = []
    for item in data:
        item['_id'] = str(item['_id'])
        formatted_data.append(item)
    return templates.TemplateResponse("device_data.html", {
        "request": request, 
        "data": formatted_data
    })

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    request.session["flash"] = "Logged out successfully."
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)