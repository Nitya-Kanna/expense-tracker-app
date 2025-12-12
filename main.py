# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone, date
from contextlib import asynccontextmanager
from typing import Optional
import sqlite3
import hashlib


from database import init_db, get_db
from models import (
    UserRegister, UserLogin, ExpenseCreate, ExpenseUpdate,
    UserResponse, TokenResponse, ExpenseResponse, MessageResponse,
    VALID_CATEGORIES, VALID_CURRENCIES
)
from currency_service import convert_currency, get_exchange_rates, get_supported_currencies

# ============================================
# LIFESPAN EVENTS
# ============================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events.
    Runs once when app starts, once when app stops.
    """
    # Startup: Initialize database
    print("🚀 Starting up...")
    init_db()
    
    # Create tokens table if it doesn't exist
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at DATETIME NOT NULL,
                revoked INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        conn.commit()
    
    print("✅ Database initialized")
    yield  # App runs here
    
    # Shutdown
    print("👋 Shutting down...")

# ============================================
# APP CONFIGURATION
# ============================================

app = FastAPI(
    title="Expense Tracker API",
    description="Track your expenses with multi-currency support",
    version="1.0.0",
    lifespan=lifespan
)

# Security configuration
SECRET_KEY = "your-secret-key-change-in-production-use-openssl-rand-hex-32"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# Password hashing
#pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")


# Security scheme for bearer token
security = HTTPBearer()

# ============================================
# HELPER FUNCTIONS
# ============================================

#def hash_password(password: str) -> str:
#   """
#    Hash a password using bcrypt.
    
#    Args:
#        password: Plain text password
    
#    Returns:
 #       Hashed password string
    
#    Example:
#        >>> hash_password("mypassword123")
#        "$2b$12$EixZaYvKJqg9..."
#    """

#    return pwd_context.hash(password)
#    #password_bytes = password.encode('utf-8')[:72]
 #   #return pwd_context.hash(password_bytes.decode('utf-8', errors='ignore'))


#def verify_password(plain_password: str, hashed_password: str) -> bool:
#    """
#    Verify a password against its hash.
    
#    Args:
#        plain_password: Password user entered
#        hashed_password: Stored hash from database
    
#    Returns:
#        True if password matches, False otherwise
 #   """
#    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    # Pre-hash with SHA-256 to handle any length
    sha_hash = hashlib.sha256(password.encode()).hexdigest()
    # Then bcrypt the SHA hash (always 64 chars, well under 72 bytes)
    return pwd_context.hash(sha_hash)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Pre-hash the plain password the same way
    sha_hash = hashlib.sha256(plain_password.encode()).hexdigest()
    return pwd_context.verify(sha_hash, hashed_password)


def create_access_token(data: dict) -> str:
    """
    Create JWT access token.
    
    Args:
        data: Dictionary to encode in token (usually user_id, username)
    
    Returns:
        JWT token string
    
    Example:
        >>> token = create_access_token({"user_id": 1, "username": "alice"})
        >>> print(token)
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Dependency to get current authenticated user from JWT token.
    This runs automatically on protected routes.
    
    Args:
        credentials: HTTPBearer credentials from request header
    
    Returns:
        Dictionary with user info: {user_id, username, home_currency, token}
    
    Raises:
        HTTPException: If token is invalid, expired, or revoked
    
    Usage:
        @app.get("/protected")
        async def protected_route(current_user: dict = Depends(get_current_user)):
            # current_user is automatically available here
            user_id = current_user["user_id"]
    """
    token = credentials.credentials
    
    try:
        # Decode JWT
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        username: str = payload.get("username")
        
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials"
            )
        
        # Check if token is in database and not revoked
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT * FROM tokens 
                   WHERE token = ? 
                   AND revoked = 0 
                   AND expires_at > datetime('now')""",
                (token,)
            )
            token_record = cursor.fetchone()
            
            if not token_record:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token expired or revoked"
                )
            
            # Get user's home currency
            cursor.execute(
                "SELECT home_currency FROM users WHERE id = ?",
                (user_id,)
            )
            user = cursor.fetchone()
        
        # Return user info
        return {
            "user_id": user_id,
            "username": username,
            "home_currency": user["home_currency"],
            "token": token
        }
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

# ============================================
# ROUTES: UTILITY
# ============================================

@app.get("/")
async def root():
    """Welcome endpoint"""
    return {
        "message": "Welcome to Expense Tracker API",
        "version": "1.0.0",
        "docs": "/docs",
        "features": [
            "Multi-currency expense tracking",
            "Automatic currency conversion",
            "View expenses in any currency",
            "JWT authentication"
        ]
    }


@app.get("/categories")
async def get_categories():
    """
    Get list of valid expense categories.
    
    Returns:
        List of category names and count
    
    Example:
        GET /categories
        
        Response:
        {
            "categories": ["Food", "Transport", "Shopping", ...],
            "count": 7
        }
    """
    return {
        "categories": VALID_CATEGORIES,
        "count": len(VALID_CATEGORIES)
    }


@app.get("/currencies")
async def get_currencies():
    """
    Get list of supported currencies.
    
    Returns:
        List of currency codes and count
    
    Example:
        GET /currencies
        
        Response:
        {
            "currencies": ["USD", "SGD", "EUR", ...],
            "count": 8
        }
    """
    return {
        "currencies": VALID_CURRENCIES,
        "count": len(VALID_CURRENCIES)
    }


@app.get("/exchange-rates")
async def get_current_exchange_rates(base_currency: str = "USD"):
    """
    Get all current exchange rates for a base currency.
    Useful for frontend to cache and do client-side conversions.
    
    Args:
        base_currency: Base currency code (default: USD)
    
    Returns:
        Dictionary of exchange rates and metadata
    
    Example:
        GET /exchange-rates?base_currency=SGD
        
        Response:
        {
            "base_currency": "SGD",
            "rates": {
                "USD": 0.74,
                "MYR": 3.31,
                "EUR": 0.68,
                ...
            },
            "timestamp": "2024-12-10T10:30:00Z",
            "count": 161
        }
    """
    if base_currency not in VALID_CURRENCIES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid currency. Valid options: {', '.join(VALID_CURRENCIES)}"
        )
    
    try:
        rates = get_exchange_rates(base_currency)
        return {
            "base_currency": base_currency,
            "rates": rates,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "count": len(rates)
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unable to fetch exchange rates: {str(e)}"
        )

# ============================================
# ROUTES: AUTHENTICATION
# ============================================

@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user: UserRegister):
    """
    Register a new user.
    
    Args:
        user: UserRegister model with username, email, password, home_currency
    
    Returns:
        UserResponse with user details (no password!)
    
    Raises:
        409: Username or email already exists
    
    Example:
        POST /register
        {
            "username": "alice",
            "email": "alice@example.com",
            "password": "SecurePass123!",
            "home_currency": "MYR"
        }
        
        Response (201):
        {
            "id": 1,
            "username": "alice",
            "email": "alice@example.com",
            "home_currency": "MYR",
            "created_at": "2024-12-10T10:30:00"
        }
    """
    # Hash password
    password_hash = hash_password(user.password)
    
    # Insert into database
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO users (username, email, password_hash, home_currency) 
                   VALUES (?, ?, ?, ?)""",
                (user.username, user.email, password_hash, user.home_currency)
            )
            conn.commit()
            user_id = cursor.lastrowid
            
            # Get created user
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            created_user = cursor.fetchone()
            
            return UserResponse(
                id=created_user['id'],
                username=created_user['username'],
                email=created_user['email'],
                home_currency=created_user['home_currency'],
                created_at=created_user['created_at']
            )
            
        except sqlite3.IntegrityError as e:
            error_msg = str(e).lower()
            if "username" in error_msg:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Username already exists"
                )
            elif "email" in error_msg:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email already exists"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Username or email already exists"
                )


@app.post("/login", response_model=TokenResponse)
async def login(user: UserLogin):
    """
    Login and get access token.
    
    Args:
        user: UserLogin model with username and password
    
    Returns:
        TokenResponse with access token and user details
    
    Raises:
        401: Invalid username or password
    
    Example:
        POST /login
        {
            "username": "alice",
            "password": "SecurePass123!"
        }
        
        Response (200):
        {
            "access_token": "eyJhbGci...",
            "token_type": "bearer",
            "expires_in": 86400,
            "user": {
                "id": 1,
                "username": "alice",
                "email": "alice@example.com",
                "home_currency": "MYR",
                "created_at": "2024-12-10T10:30:00"
            }
        }
    """
    # Find user
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (user.username,)
        )
        db_user = cursor.fetchone()
        
        if not db_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Verify password
        if not verify_password(user.password, db_user['password_hash']):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Create token
        token_data = {
            "user_id": db_user['id'],
            "username": db_user['username']
        }
        access_token = create_access_token(token_data)
        
        # Store token in database
        expires_at = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
        cursor.execute(
            """INSERT INTO tokens (user_id, token, expires_at) 
               VALUES (?, ?, ?)""",
            (db_user['id'], access_token, expires_at)
        )
        conn.commit()
        
        # Return response
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_EXPIRE_HOURS * 3600,
            user=UserResponse(
                id=db_user['id'],
                username=db_user['username'],
                email=db_user['email'],
                home_currency=db_user['home_currency'],
                created_at=db_user['created_at']
            )
        )


@app.post("/logout", response_model=MessageResponse)
async def logout(current_user: dict = Depends(get_current_user)):
    """
    Logout by revoking current token.
    
    Args:
        current_user: Automatically injected by Depends(get_current_user)
    
    Returns:
        Success message
    
    Example:
        POST /logout
        Headers: Authorization: Bearer <token>
        
        Response (200):
        {
            "message": "Logged out successfully"
        }
    """
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE tokens SET revoked = 1 WHERE token = ?",
            (current_user['token'],)
        )
        conn.commit()
    
    return MessageResponse(message="Logged out successfully")

# ============================================
# ROUTES: EXPENSES (CRUD)
# ============================================

@app.post("/expenses", status_code=status.HTTP_201_CREATED)
async def create_expense(
    expense: ExpenseCreate,
    current_user: dict = Depends(get_current_user)
):
    """
    Create new expense with automatic currency conversion.
    
    This endpoint:
    1. Takes the expense in original currency
    2. Automatically converts to user's home currency
    3. Saves BOTH amounts to database
    4. Returns both original and converted amounts
    
    Args:
        expense: ExpenseCreate model
        current_user: Authenticated user (auto-injected)
    
    Returns:
        Created expense with both original and home currency amounts
    
    Example:
        POST /expenses
        Headers: Authorization: Bearer <token>
        Body:
        {
            "amount": 3.00,
            "currency": "SGD",
            "description": "Coffee at Starbucks",
            "category": "Food",
            "date": "2024-12-10"
        }
        
        Response (201):
        {
            "id": 1,
            "message": "Expense created successfully",
            "expense": {
                "id": 1,
                "amount": 3.00,
                "currency": "SGD",
                "amount_home": 9.93,
                "home_currency": "MYR",
                "description": "Coffee at Starbucks",
                "category": "Food",
                "date": "2024-12-10",
                "created_at": "2024-12-10T10:30:00"
            },
            "display": {
                "original": "3.00 SGD",
                "in_home_currency": "9.93 MYR"
            }
        }
    """
    user_home_currency = current_user["home_currency"]
    
    # Convert to home currency
    try:
        if expense.currency != user_home_currency:
            # Different currency - convert it!
            print(f"💱 Converting {expense.amount} {expense.currency} to {user_home_currency}")
            amount_home = convert_currency(
                amount=expense.amount,
                from_currency=expense.currency,
                to_currency=user_home_currency
            )
            print(f"✅ Converted: {amount_home} {user_home_currency}")
        else:
            # Same currency - no conversion needed
            amount_home = expense.amount
            print(f"✅ No conversion needed (same currency)")
    
    except Exception as e:
        # If conversion fails, log warning but still create expense
        print(f"⚠️ Conversion failed: {e}")
        print(f"⚠️ Saving expense without conversion")
        amount_home = expense.amount
    
    # Save to database
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO expenses 
               (user_id, amount, currency, amount_home, description, category, date) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                current_user["user_id"],
                expense.amount,
                expense.currency,
                amount_home,
                expense.description,
                expense.category,
                expense.date
            )
        )
        conn.commit()
        expense_id = cursor.lastrowid
        
        # Get created expense
        cursor.execute("SELECT * FROM expenses WHERE id = ?", (expense_id,))
        created_expense = cursor.fetchone()
    
    return {
        "id": expense_id,
        "message": "Expense created successfully",
        "expense": {
            "id": created_expense['id'],
            "amount": created_expense['amount'],
            "currency": created_expense['currency'],
            "amount_home": created_expense['amount_home'],
            "home_currency": user_home_currency,
            "description": created_expense['description'],
            "category": created_expense['category'],
            "date": created_expense['date'],
            "created_at": created_expense['created_at']
        },
        "display": {
            "original": f"{created_expense['amount']} {created_expense['currency']}",
            "in_home_currency": f"{created_expense['amount_home']} {user_home_currency}"
        }
    }


@app.get("/expenses")
async def get_expenses(
    month: Optional[str] = None,
    category: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """
    Get all expenses for current user.
    
    Optional filters:
    - month: Filter by month (YYYY-MM format)
    - category: Filter by category
    
    Args:
        month: Optional month filter (e.g., "2024-12")
        category: Optional category filter (e.g., "Food")
        current_user: Authenticated user (auto-injected)
    
    Returns:
        List of expenses with summary
    
    Example:
        GET /expenses?month=2024-12&category=Food
        Headers: Authorization: Bearer <token>
        
        Response (200):
        {
            "expenses": [
                {
                    "id": 1,
                    "amount": 3.00,
                    "currency": "SGD",
                    "amount_home": 9.93,
                    "description": "Coffee",
                    "category": "Food",
                    "date": "2024-12-10",
                    ...
                }
            ],
            "count": 1,
            "summary": {
                "total": 9.93,
                "currency": "MYR"
            },
            "filters": {
                "month": "2024-12",
                "category": "Food"
            }
        }
    """
    # Build query
    query = "SELECT * FROM expenses WHERE user_id = ?"
    params = [current_user["user_id"]]
    
    if month:
        query += " AND strftime('%Y-%m', date) = ?"
        params.append(month)
    
    if category:
        if category not in VALID_CATEGORIES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid category. Valid options: {', '.join(VALID_CATEGORIES)}"
            )
        query += " AND category = ?"
        params.append(category)
    
    query += " ORDER BY date DESC, created_at DESC"
    
    # Execute query
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        expenses = cursor.fetchall()
    
    # Convert to list of dicts
    expense_list = []
    total_home = 0
    
    for expense in expenses:
        expense_list.append({
            "id": expense['id'],
            "amount": expense['amount'],
            "currency": expense['currency'],
            "amount_home": expense['amount_home'],
            "description": expense['description'],
            "category": expense['category'],
            "date": expense['date'],
            "created_at": expense['created_at'],
            "updated_at": expense['updated_at']
        })
        total_home += expense['amount_home']
    
    return {
        "expenses": expense_list,
        "count": len(expense_list),
        "summary": {
            "total": round(total_home, 2),
            "currency": current_user["home_currency"]
        },
        "filters": {
            "month": month,
            "category": category
        }
    }


@app.get("/expenses/{expense_id}")
async def get_expense(
    expense_id: int,
    current_user: dict = Depends(get_current_user)
):
    """
    Get a single expense by ID.
    
    Args:
        expense_id: The expense ID
        current_user: Authenticated user (auto-injected)
    
    Returns:
        Expense details
    
    Raises:
        404: Expense not found
    
    Example:
        GET /expenses/1
        Headers: Authorization: Bearer <token>
        
        Response (200):
        {
            "id": 1,
            "amount": 3.00,
            "currency": "SGD",
            "amount_home": 9.93,
            "home_currency": "MYR",
            ...
        }
    """
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM expenses WHERE id = ? AND user_id = ?",
            (expense_id, current_user["user_id"])
        )
        expense = cursor.fetchone()
        
        if not expense:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Expense not found"
            )
    
    return {
        "id": expense['id'],
        "amount": expense['amount'],
        "currency": expense['currency'],
        "amount_home": expense['amount_home'],
        "home_currency": current_user["home_currency"],
        "description": expense['description'],
        "category": expense['category'],
        "date": expense['date'],
        "created_at": expense['created_at'],
        "updated_at": expense['updated_at']
    }


@app.put("/expenses/{expense_id}")
async def update_expense(
    expense_id: int,
    expense_update: ExpenseUpdate,
    current_user: dict = Depends(get_current_user)
):
    """
    Update an existing expense.
    
    If currency or amount changes, automatically recalculates home currency amount.
    
    Args:
        expense_id: The expense ID
        expense_update: ExpenseUpdate model (all fields optional)
        current_user: Authenticated user (auto-injected)
    
    Returns:
        Updated expense
    
    Raises:
        404: Expense not found
    
    Example:
        PUT /expenses/1
        Headers: Authorization: Bearer <token>
        Body:
        {
            "amount": 5.00,
            "description": "Coffee and Croissant"
        }
        
        Response (200):
        {
            "id": 1,
            "message": "Expense updated successfully",
            "expense": {
                "id": 1,
                "amount": 5.00,
                "currency": "SGD",
                "amount_home": 16.55,
                "description": "Coffee and Croissant",
                ...
            }
        }
    """
    # Get existing expense
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM expenses WHERE id = ? AND user_id = ?",
            (expense_id, current_user["user_id"])
        )
        existing_expense = cursor.fetchone()
        
        if not existing_expense:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Expense not found"
            )
        
        # Prepare update data
        update_fields = []
        update_values = []
        
        # Check each field
        if expense_update.amount is not None:
            update_fields.append("amount = ?")
            update_values.append(expense_update.amount)
        
        if expense_update.currency is not None:
            update_fields.append("currency = ?")
            update_values.append(expense_update.currency)
        
        if expense_update.description is not None:
            update_fields.append("description = ?")
            update_values.append(expense_update.description)
        
        if expense_update.category is not None:
            update_fields.append("category = ?")
            update_values.append(expense_update.category)
        
        if expense_update.date is not None:
            update_fields.append("date = ?")
            update_values.append(expense_update.date)
        
        # Update updated_at
        update_fields.append("updated_at = datetime('now')")
        
        # If amount or currency changed, recalculate amount_home
        new_amount = expense_update.amount if expense_update.amount is not None else existing_expense['amount']
        new_currency = expense_update.currency if expense_update.currency is not None else existing_expense['currency']
        
        if (expense_update.amount is not None or expense_update.currency is not None):
            # Recalculate
            try:
                if new_currency != current_user["home_currency"]:
                    amount_home = convert_currency(
                        amount=new_amount,
                        from_currency=new_currency,
                        to_currency=current_user["home_currency"]
                    )
                else:
                    amount_home = new_amount
                
                update_fields.append("amount_home = ?")
                update_values.append(amount_home)
            except Exception as e:
                print(f"⚠️ Conversion failed during update: {e}")
        
        # Build and execute update query
        if update_fields:
            query = f"UPDATE expenses SET {', '.join(update_fields)} WHERE id = ?"
            update_values.append(expense_id)
            cursor.execute(query, update_values)
            conn.commit()
        
        # Get updated expense
        cursor.execute("SELECT * FROM expenses WHERE id = ?", (expense_id,))
        updated_expense = cursor.fetchone()
    
    return {
        "id": expense_id,
        "message": "Expense updated successfully",
        "expense": {
            "id": updated_expense['id'],
            "amount": updated_expense['amount'],
            "currency": updated_expense['currency'],
            "amount_home": updated_expense['amount_home'],
            "home_currency": current_user["home_currency"],
            "description": updated_expense['description'],
            "category": updated_expense['category'],
            "date": updated_expense['date'],
            "created_at": updated_expense['created_at'],
            "updated_at": updated_expense['updated_at']
        }
    }


@app.delete("/expenses/{expense_id}", response_model=MessageResponse)
async def delete_expense(
    expense_id: int,
    current_user: dict = Depends(get_current_user)
):
    """
    Delete an expense.
    
    Args:
        expense_id: The expense ID
        current_user: Authenticated user (auto-injected)
    
    Returns:
        Success message
    
    Raises:
        404: Expense not found
    
    Example:
        DELETE /expenses/1
        Headers: Authorization: Bearer <token>
        
        Response (200):
        {
            "message": "Expense deleted successfully"
        }
    """
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Check if expense exists
        cursor.execute(
            "SELECT id FROM expenses WHERE id = ? AND user_id = ?",
            (expense_id, current_user["user_id"])
        )
        expense = cursor.fetchone()
        
        if not expense:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Expense not found"
            )
        
        # Delete
        cursor.execute(
            "DELETE FROM expenses WHERE id = ?",
            (expense_id,)
        )
        conn.commit()
    
    return MessageResponse(message="Expense deleted successfully")

# ============================================
# ROUTES: CURRENCY CONVERSION (YOUR IDEA!)
# ============================================

@app.get("/expenses/convert")
async def convert_expenses_to_currency(
    to_currency: str,
    month: Optional[str] = None,
    category: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """
    Convert expenses to a different currency (VIEW ONLY - not saved).
    
    This is your excellent design idea!
    
    Shows expenses in any currency without changing stored data.
    Useful for:
    - "How much did I spend in USD?"
    - "What's my total in EUR?"
    - Comparing spending across currencies
    
    Optional filters:
    - month: Filter by month (YYYY-MM format)
    - category: Filter by category
    
    Args:
        to_currency: Currency to convert to (e.g., "USD", "EUR")
        month: Optional month filter
        category: Optional category filter
        current_user: Authenticated user (auto-injected)
    
    Returns:
        Expenses with original, home, and converted amounts
    
    Example:
        GET /expenses/convert?to_currency=USD&month=2024-12
        Headers: Authorization: Bearer <token>
        
        Response (200):
        {
            "expenses": [
                {
                    "id": 1,
                    "original": {
                        "amount": 3.00,
                        "currency": "SGD"
                    },
                    "home": {
                        "amount": 9.93,
                        "currency": "MYR"
                    },
                    "converted": {
                        "amount": 2.22,
                        "currency": "USD"
                    },
                    "description": "Coffee",
                    "category": "Food",
                    "date": "2024-12-10"
                }
            ],
            "summary": {
                "total_in_home": 9.93,
                "home_currency": "MYR",
                "total_converted": 2.22,
                "converted_currency": "USD"
            },
            "note": "Conversion is for viewing only and not saved",
            "filters": {
                "month": "2024-12",
                "category": null
            }
        }
    """
    # Validate currency
    if to_currency not in VALID_CURRENCIES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid currency. Valid options: {', '.join(VALID_CURRENCIES)}"
        )
    
    # Build query (same as get_expenses)
    query = "SELECT * FROM expenses WHERE user_id = ?"
    params = [current_user["user_id"]]
    
    if month:
        query += " AND strftime('%Y-%m', date) = ?"
        params.append(month)
    
    if category:
        if category not in VALID_CATEGORIES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid category. Valid options: {', '.join(VALID_CATEGORIES)}"
            )
        query += " AND category = ?"
        params.append(category)
    
    query += " ORDER BY date DESC, created_at DESC"
    
    # Get expenses
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        expenses = cursor.fetchall()
    
    # Convert each expense
    converted_expenses = []
    total_home = 0
    total_converted = 0
    
    for expense in expenses:
        # Convert from original currency to target currency
        try:
            if expense['currency'] != to_currency:
                converted_amount = convert_currency(
                    amount=expense['amount'],
                    from_currency=expense['currency'],
                    to_currency=to_currency
                )
            else:
                converted_amount = expense['amount']
        except Exception as e:
            # If conversion fails, skip this expense or use original amount
            print(f"⚠️ Failed to convert expense {expense['id']}: {e}")
            converted_amount = None
        
        converted_expenses.append({
            "id": expense['id'],
            "original": {
                "amount": expense['amount'],
                "currency": expense['currency']
            },
            "home": {
                "amount": expense['amount_home'],
                "currency": current_user["home_currency"]
            },
            "converted": {
                "amount": converted_amount,
                "currency": to_currency
            } if converted_amount is not None else None,
            "description": expense['description'],
            "category": expense['category'],
            "date": expense['date']
        })
        
        total_home += expense['amount_home']
        if converted_amount is not None:
            total_converted += converted_amount
    
    return {
        "expenses": converted_expenses,
        "count": len(converted_expenses),
        "summary": {
            "total_in_home": round(total_home, 2),
            "home_currency": current_user["home_currency"],
            "total_converted": round(total_converted, 2),
            "converted_currency": to_currency
        },
        "note": "Conversion is for viewing only and not saved",
        "filters": {
            "month": month,
            "category": category
        }
    }

# ============================================
# ROUTES: USER SETTINGS
# ============================================

@app.put("/user/home-currency")
async def update_home_currency(
    new_currency: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Change user's home currency preference.
    
    This affects FUTURE expenses only.
    Existing expenses keep their original conversion.
    
    Args:
        new_currency: New home currency code
        current_user: Authenticated user (auto-injected)
    
    Returns:
        Success message with new currency
    
    Example:
        PUT /user/home-currency?new_currency=SGD
        Headers: Authorization: Bearer <token>
        
        Response (200):
        {
            "message": "Home currency updated successfully",
            "old_currency": "MYR",
            "new_currency": "SGD",
            "note": "This affects future expenses only. Use POST /expenses/recalculate-all to update existing expenses."
        }
    """
    # Validate currency
    if new_currency not in VALID_CURRENCIES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid currency. Valid options: {', '.join(VALID_CURRENCIES)}"
        )
    
    old_currency = current_user["home_currency"]
    
    # Update in database
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET home_currency = ? WHERE id = ?",
            (new_currency, current_user["user_id"])
        )
        conn.commit()
    
    return {
        "message": "Home currency updated successfully",
        "old_currency": old_currency,
        "new_currency": new_currency,
        "note": "This affects future expenses only. Use POST /expenses/recalculate-all to update existing expenses."
    }