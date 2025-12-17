import requests
url='fe2ct.update.microsoft.com'
conn = requests.get(url)
print(conn.status_code)
