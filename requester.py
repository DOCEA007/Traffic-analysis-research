import requests
url='https://example.com'
conn = requests.get(url)
print(conn.status_code)
