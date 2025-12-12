# models.py
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
from datetime import date, datetime, timezone



VALID_CATEGORIES = [    
    
        "Food",           # Groceries, restaurants, cafes
        "Transport",      # Taxi, bus, train, gas, parking
        "Shopping",       # Clothes, electronics, general shopping
        "Bills",          # Rent, utilities, phone, internet
        "Entertainment",  # Movies, games, hobbies, subscriptions
        "Health",         # Doctor, medicine, gym, wellness
        "Other"           # Anything else 
    ]

VALID_CURRENCIES = [

        "USD",  # US Dollar
        "SGD",  # Singapore Dollar
        "EUR",  # Euro
        "GBP",  # British Pound
        "JPY",  # Japanese Yen
        "AUD",  # Australian Dollar
        "CNY",  # Chinese Yuan
        "MYR"   # Malaysian Ringgit

]



#REQUEST MODELS - WHAT USERS WILL SEND 


class UserRegister(BaseModel):
    """
    Model for User Registration

    Example:

            {
            "username": "alice",
            "email": "alice@example.com",
            "password": "SecurePass123!",
            "home_currency": "SGD"
        }

    """


    username: str
    email: EmailStr
    password: str
    home_currency: str = "MYR"  


    @field_validator('username')
    @classmethod
    def validate_username(cls, value):
        if len(value) < 3:
            raise ValueError('Username must be at least 3 characters')
        if len(value) > 20:
            raise ValueError('Username must be at most 20 characters')
        if not value.isalnum():
            raise ValueError('Username can only contain letters and numbers')
        return value
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, value):
        if len(value) < 6:
            raise ValueError('Password must be at least 6 characters')
        if len(value) > 72:
            raise ValueError('Password must be at most 72 characters')
        return value
    
    @field_validator('home_currency')
    @classmethod
    def validate_home_currency(cls, value):
        if value not in VALID_CURRENCIES:
            raise ValueError(f'Currency must be one of: {", ".join(VALID_CURRENCIES)}')
        return value
    


class UserLogin(BaseModel):
    """
    Model for user login.
    
    Example:
        {
            "username": "alice",
            "password": "SecurePass123!"
        }
    """
    username: str
    password: str


class ExpenseCreate(BaseModel):
    """
    Model for creating a new expense.
    
    Example:
        {
            "amount": 50.00,
            "currency": "USD",
            "description": "Coffee maker from Amazon",
            "category": "Shopping",
            "date": "2024-12-09"
        }
    """
    amount: float
    currency: str
    description: Optional[str] = None
    category: str
    date: date  # YYYY-MM-DD format
    
    @field_validator('amount')
    @classmethod
    def validate_amount(cls, value):
        if value <= 0:
            raise ValueError('Amount must be greater than 0')
        if value > 1000000:
            raise ValueError('Amount too large (max: 1,000,000)')
        return round(value, 2)  # Round to 2 decimal places
    
    @field_validator('currency')
    @classmethod
    def validate_currency(cls, value):
        value = value.upper()  # Convert to uppercase
        if value not in VALID_CURRENCIES:
            raise ValueError(f'Currency must be one of: {", ".join(VALID_CURRENCIES)}')
        return value
    
    @field_validator('category')
    @classmethod
    def validate_category(cls, value):
        if value not in VALID_CATEGORIES:
            raise ValueError(f'Category must be one of: {", ".join(VALID_CATEGORIES)}')
        return value
    
    @field_validator('date')
    @classmethod
    def validate_date(cls, value):
        if value > date.today():
            raise ValueError('Date cannot be in the future')
        # Optional: limit how far back
        if value.year < 2000:
            raise ValueError('Date cannot be before year 2000')
        return value
    
    @field_validator('description')
    @classmethod
    def validate_description(cls, value):
        if value is not None:
            if len(value) > 200:
                raise ValueError('Description must be at most 200 characters')
            if len(value.strip()) == 0:
                return None  # Empty string becomes None
        return value



class ExpenseUpdate(BaseModel):
    """
    Model for updating an existing expense.
    All fields are optional - only update what's provided.
    
    Example:
        {
            "amount": 55.00,
            "description": "Updated: Coffee maker from Best Buy"
        }
    """
    amount: Optional[float] = None
    currency: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    date: Optional[date] = None
    
    @field_validator('amount')
    @classmethod
    def validate_amount(cls, value):
        if value is not None:
            if value <= 0:
                raise ValueError('Amount must be greater than 0')
            if value > 1000000:
                raise ValueError('Amount too large (max: 1,000,000)')
            return round(value, 2)
        return value
    
    @field_validator('currency')
    @classmethod
    def validate_currency(cls, value):
        if value is not None:
            value = value.upper()
            if value not in VALID_CURRENCIES:
                raise ValueError(f'Currency must be one of: {", ".join(VALID_CURRENCIES)}')
        return value
    
    @field_validator('category')
    @classmethod
    def validate_category(cls, value):
        if value is not None:
            if value not in VALID_CATEGORIES:
                raise ValueError(f'Category must be one of: {", ".join(VALID_CATEGORIES)}')
        return value
    
    @field_validator('date')
    @classmethod
    def validate_date(cls, value):
        if value is not None:
            if value > date.today():
                raise ValueError('Date cannot be in the future')
            if value.year < 2000:
                raise ValueError('Date cannot be before year 2000')
        return value
    
    @field_validator('description')
    @classmethod
    def validate_description(cls, value):
        if value is not None:
            if len(value) > 200:
                raise ValueError('Description must be at most 200 characters')
            if len(value.strip()) == 0:
                return None
        return value



#response models - what users receive 

class UserResponse(BaseModel):
    """
    Model for user information in responses.
    Note: password_hash is NEVER included in responses!
    
    Example:
        {
            "id": 1,
            "username": "alice",
            "email": "alice@example.com",
            "home_currency": "SGD",
            "created_at": "2024-12-09T10:30:00"
        }
    """
    id: int
    username: str
    email: str
    home_currency: str
    created_at: str


class TokenResponse(BaseModel):
    """
    Model for login response with JWT token.
    
    Example:
        {
            "access_token": "eyJhbGci...",
            "token_type": "bearer",
            "expires_in": 86400,
            "user": {
                "id": 1,
                "username": "alice",
                ...
            }
        }
    """
    access_token: str
    token_type: str
    expires_in: int
    user: UserResponse


class ExpenseResponse(BaseModel):
    """
    Model for expense information in responses.
    
    Example:
        {
            "id": 1,
            "amount": 50.00,
            "currency": "USD",
            "description": "Coffee maker",
            "category": "Shopping",
            "date": "2024-12-09",
            "created_at": "2024-12-09T10:30:00",
            "updated_at": "2024-12-09T10:30:00"
        }
    """
    id: int
    amount: float
    currency: str
    description: Optional[str]
    category: str
    date: str
    created_at: str
    updated_at: str


class MessageResponse(BaseModel):
    """
    Generic message response.
    
    Example:
        {
            "message": "Expense deleted successfully"
        }
    """
    message: str



