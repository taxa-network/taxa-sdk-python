import requests

def main(input_obj):
    response = requests.get("https://aviationweather.gov/api/data/metar?ids=KELP&format=json")
    return response.json()[0]['icaoId']
