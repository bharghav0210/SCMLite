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