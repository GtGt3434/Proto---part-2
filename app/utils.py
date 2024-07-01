import requests
import os

def fetch_unsplash_image(query):
    access_key = os.getenv('UNSPLASH_ACCESS_KEY')
    url = f"https://api.unsplash.com/photos/random?query={query}&client_id={access_key}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data['urls']['regular']
    else:
        return None
