# currency_service.py
import requests
from typing import Dict

BASE_URL = "https://api.exchangerate-api.com/v4/latest"

def get_exchange_rates(base_currency: str = "USD") -> Dict[str, float]:
    """
    Fetch exchange rates from Exchange Rate API.
    
    Args:
        base_currency: The base currency code (e.g., "USD", "SGD")
    
    Returns:
        Dictionary of exchange rates
        Example: {"SGD": 1.35, "EUR": 0.92, "GBP": 0.79, ...}
    
    Raises:
        Exception: If API call fails
    """
    try:
        url = f"{BASE_URL}/{base_currency}"
        print(f"🌐 Fetching exchange rates for {base_currency}...")
        
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if "rates" not in data:
            raise Exception("Invalid response from API")
        
        print(f"✅ Got rates for {len(data['rates'])} currencies")
        return data["rates"]
        
    except requests.RequestException as e:
        print(f"❌ Error: {e}")
        raise Exception(f"Unable to fetch exchange rates: {e}")


def convert_currency(amount: float, from_currency: str, to_currency: str) -> float:
    """
    Convert amount from one currency to another.
    
    Args:
        amount: The amount to convert
        from_currency: Source currency code (e.g., "USD")
        to_currency: Target currency code (e.g., "SGD")
    
    Returns:
        Converted amount rounded to 2 decimal places
    
    Example:
        >>> convert_currency(100, "USD", "SGD")
        135.00
    """
    # Same currency, no conversion needed
    if from_currency == to_currency:
        return amount
    
    # Get exchange rates
    rates = get_exchange_rates(from_currency)
    
    # Check if target currency exists
    if to_currency not in rates:
        available = ", ".join(sorted(rates.keys())[:10])
        raise ValueError(
            f"Currency '{to_currency}' not supported. "
            f"Available currencies include: {available}..."
        )
    
    # Convert and round
    converted = amount * rates[to_currency]
    return round(converted, 2)


def get_supported_currencies() -> list:
    """
    Get list of all supported currencies.
    
    Returns:
        Sorted list of currency codes
    """
    rates = get_exchange_rates("USD")
    return sorted(rates.keys())