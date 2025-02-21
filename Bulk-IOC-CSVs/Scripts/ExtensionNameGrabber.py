import requests
from bs4 import BeautifulSoup
import pandas as pd
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
}

def get_extension_name(url):
    try:
        response = requests.get(url, verify=False,headers=HEADERS)
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

csv_file = './Bulk-IOC-CSVs/Intune/Intune Browser Extension_IDs_the_user_should_be_prevented_from_installing.csv' # Change path accordingly
df = pd.read_csv(csv_file, names=['ExtensionID'], header=None)

df['ExtensionURL'] = "https://chrome.google.com/webstore/detail/" + df['ExtensionID']
df['ExtensionName'] = df['ExtensionURL'].apply(get_extension_name)

output_file = './Bulk-IOC-CSVs/Intune/Unsanctioned_extensions_with_names.csv'
df.to_csv(output_file, index=False)
