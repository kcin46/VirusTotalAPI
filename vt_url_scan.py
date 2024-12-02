from ansible_vault import Vault
import getpass, requests, json

#Get Ansible-Vault password from user to retrieve Virus Total API Key
vault_pass = getpass.getpass("Enter password for Vault key: ")

#Takes password and uses to decrypt file via Ansible-Vault 
vault = Vault(vault_pass)
api_key = vault.load(open('vt_api').read())

#Build HTTP POST request for Virus Total API
#Submits URL to Virus Total and returns an analysis ID
url = "https://www.virustotal.com/api/v3/urls"
payload = { "url": "http://42.86.67.28:36211/i"}
#payload = { "url": "https://eicar.org"}
headers = {
    "accept": "application/json",
    "content-type": "application/x-www-form-urlencoded",
    "x-apikey": api_key
}

#Parse the response to get the Analysis ID
response = requests.post(url, data=payload, headers=headers)
analysis_id = (response.json()["data"])["id"]

#Build HTTP GET request for getting analysis
url = "https://www.virustotal.com/api/v3/analyses/" + analysis_id

headers = {
	"accept": "application/json",
	"x-apikey": api_key
}

response = requests.get(url, headers=headers)
response = json.loads(response.text)

print(json.dumps(response, indent=4))

