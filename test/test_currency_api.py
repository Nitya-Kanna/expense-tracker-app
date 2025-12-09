import requests

url = "https://api.exchangerate-api.com/v4/latest/MYR"

response = requests.get(url)

print(response.json())


