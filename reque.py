import requests as req

'''
username = 'felix'
password='12345'

data = req.post('http://127.0.0.1:8000/token',{
    'username':username,
    'password':password,
})


print(data.text)
'''

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmZWxpeCIsImV4cCI6MTc0NzEzMzExN30.sdLIfXe0zF3xl1je2Ao4aUx1FsXQv4x9uhE7Uqz4nM0"

url = 'http://127.0.0.1:8000/users/me/'

headers = {
    'Authorization': f'Bearer {token}',
    'Content-Type': 'application/json'
}

response = req.get(url, headers=headers)

print(response.text)