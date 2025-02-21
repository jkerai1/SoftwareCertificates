import requests
from bs4 import BeautifulSoup
import pandas as pd
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_extension_name(url):
    try:
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            print(soup.prettify())  
            possible_class_names = ['e-f-w', 'Pa2dE', 'g-c-t', 'a-b-c']
            for class_name in possible_class_names:
                name_tag = soup.find('h1', class_=class_name)
                if name_tag:
                    return name_tag.text.strip()
            print(f'No extension name found for URL: {url}')
        else:
            get_extension_name(url.replace("https://chrome.google.com/webstore/detail/","https://microsoftedge.microsoft.com/addons/detail/"))
    except Exception as e:
        print(f'Error occurred for URL: {url} - {e}')
    return None

csv_file = 'ExtensionIDs with URLs.csv' 
df = pd.read_csv(csv_file)

df['ExtensionName'] = df['ExtensionURL'].apply(get_extension_name)
df.to_csv('extensions_with_names.csv', index=False)
