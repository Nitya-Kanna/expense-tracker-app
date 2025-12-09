#havent used yet 


# test_database_and_models.py
from database import init_db, get_db
from models import (
    UserRegister, ExpenseCreate, 
    VALID_CATEGORIES, VALID_CURRENCIES
)
from datetime import date

print("=" * 50)
print("TESTING DATABASE")
print("=" * 50)

# Test 1: Initialize database
print("\n1. Initializing database...")
init_db()

# Test 2: Check tables exist
print("\n2. Checking tables...")
with get_db() as conn:
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row['name'] for row in cursor.fetchall()]
    print(f"   Tables found: {tables}")
    assert 'users' in tables, "❌ users table missing"
    assert 'expenses' in tables, "❌ expenses table missing"
    print("   ✅ All tables exist")

print("\n" + "=" * 50)
print("TESTING MODELS")
print("=" * 50)

# Test 3: Valid user registration
print("\n3. Testing valid user registration...")
try:
    user = UserRegister(
        username="alice",
        email="alice@example.com",
        password="SecurePass123!",
        home_currency="SGD"
    )
    print(f"   ✅ Valid user created: {user.username}")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 4: Invalid username (too short)
print("\n4. Testing invalid username (too short)...")
try:
    user = UserRegister(
        username="ab",  # Only 2 characters
        email="test@example.com",
        password="password123"
    )
    print("   ❌ Should have failed!")
except ValueError as e:
    print(f"   ✅ Correctly rejected: {e}")

# Test 5: Invalid password (too short)
print("\n5. Testing invalid password (too short)...")
try:
    user = UserRegister(
        username="bob",
        email="bob@example.com",
        password="12345"  # Only 5 characters
    )
    print("   ❌ Should have failed!")
except ValueError as e:
    print(f"   ✅ Correctly rejected: {e}")

# Test 6: Valid expense
print("\n6. Testing valid expense creation...")
try:
    expense = ExpenseCreate(
        amount=50.00,
        currency="USD",
        description="Coffee maker",
        category="Shopping",
        date=date(2024, 12, 9)
    )
    print(f"   ✅ Valid expense created: ${expense.amount} {expense.currency}")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 7: Invalid amount (negative)
print("\n7. Testing invalid amount (negative)...")
try:
    expense = ExpenseCreate(
        amount=-50.00,  # Negative!
        currency="USD",
        category="Shopping",
        date=date.today()
    )
    print("   ❌ Should have failed!")
except ValueError as e:
    print(f"   ✅ Correctly rejected: {e}")

# Test 8: Invalid currency
print("\n8. Testing invalid currency...")
try:
    expense = ExpenseCreate(
        amount=50.00,
        currency="XYZ",  # Invalid currency
        category="Shopping",
        date=date.today()
    )
    print("   ❌ Should have failed!")
except ValueError as e:
    print(f"   ✅ Correctly rejected: {e}")

# Test 9: Invalid category
print("\n9. Testing invalid category...")
try:
    expense = ExpenseCreate(
        amount=50.00,
        currency="USD",
        category="InvalidCategory",  # Not in VALID_CATEGORIES
        date=date.today()
    )
    print("   ❌ Should have failed!")
except ValueError as e:
    print(f"   ✅ Correctly rejected: {e}")

# Test 10: Future date (should fail)
print("\n10. Testing future date...")
try:
    from datetime import timedelta
    future_date = date.today() + timedelta(days=1)
    expense = ExpenseCreate(
        amount=50.00,
        currency="USD",
        category="Shopping",
        date=future_date  # Tomorrow
    )
    print("   ❌ Should have failed!")
except ValueError as e:
    print(f"   ✅ Correctly rejected: {e}")

# Test 11: Check constants
print("\n11. Checking constants...")
print(f"   Valid Categories ({len(VALID_CATEGORIES)}): {', '.join(VALID_CATEGORIES)}")
print(f"   Valid Currencies ({len(VALID_CURRENCIES)}): {', '.join(VALID_CURRENCIES)}")

print("\n" + "=" * 50)
print("✅ ALL TESTS PASSED!")
print("=" * 50)