"""
This script is designed to handle the process of sending a push notification for authorization,
verifying the push, obtaining an access token, and signing a PDF document using the obtained token.

The main steps involved are:
1. Generate a PKCE (Proof Key for Code Exchange) code_verifier and code_challenge.
2. Send an authorization request via push notification.
3. Verify the status of the push notification authorization.
4. Obtain an access token using the authorization code.
5. Sign a PDF document and save the signed version.

Dependencies:
- requests: For making HTTP requests.
- hashlib: For generating SHA256 hashes.
- base64: For encoding and decoding base64.
- os: For accessing environment variables.
- time: For adding delays between requests.
- dotenv: For loading environment variables from a .env file.

Make sure to set up a .env file with the following variables:
- CLIENT_ID: Your client ID.
- CLIENT_SECRET: Your client secret.
- LOGINHINT: The login hint (e.g., CPF or CNPJ).

Example .env file:
CLIENT_ID=4c9fb552-0387-4e5f-8727-6676fa88dce1
CLIENT_SECRET=Ny2n3hq67gQEFvH7
LOGINHINT=12345678901

Documentation link:
https://valid-sa.atlassian.net/wiki/spaces/PDD/pages/958365697/Manual+de+Integra+o+com+VIDaaS+-+Certificado+em+Nuvem
"""
import requests
import hashlib
import base64
import os
import time
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
BASE_URL = "https://certificado.vidaas.com.br"
LOGINHINT = os.getenv("LOGINHINT")

def generate_pkce():
    """
    Generates a PKCE (Proof Key for Code Exchange) code_verifier and code_challenge.

    PKCE is a security measure used in OAuth 2.0 authorization flows to prevent authorization code interception attacks.

    Returns:
        tuple: A tuple containing:
            - code_verifier (str): A high-entropy cryptographic random string.
            - code_challenge (str): A hashed and base64-encoded version of the code_verifier.

    Example:
        code_verifier, code_challenge = generate_pkce()
        print("Code Verifier:", code_verifier)
        print("Code Challenge:", code_challenge)
    """
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8').rstrip("=")
    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8').rstrip("=")
    return code_verifier, code_challenge

code_verifier, code_challenge = generate_pkce()

# Define the authorization request parameters
params = {
    "client_id": CLIENT_ID,  # The unique identifier for the client application
    "code_challenge": code_challenge,  # PKCE code challenge generated from the code verifier
    "code_challenge_method": "S256",  # Specifies SHA-256 as the transformation method for PKCE
    "response_type": "code",  # Indicates that an authorization code will be returned
    "scope": "signature_session",  # Specifies the requested permission scope
    "login_hint": LOGINHINT,  # Provides a hint for the authentication process (e.g., CPF or CNPJ)
    "redirect_uri": "push://",  # The URI where the authorization server will redirect after authentication
    "lifetime": 1000  # Sets the validity duration of the authorization request in seconds
}

# Send the authorization request to the OAuth 2.0 endpoint
response = requests.get(f"{BASE_URL}/v0/oauth/authorize", params=params)
"""
OAuth 2.0 Authorization Request

This request initiates the OAuth 2.0 authorization process using the Proof Key for Code Exchange (PKCE) mechanism.

Endpoint:
    Path: <BASE-URI>/v0/oauth/authorize
    Method: GET

Documentation: https://valid-sa.atlassian.net/wiki/spaces/PDD/pages/958365697/Manual+de+Integra+o+com+VIDaaS+-+Certificado+em+Nuvem#3.1.2.-Solicita%C3%A7%C3%A3o-por-notifica%C3%A7%C3%A3o-no-celular-(Push)

Expected Response:
    - If successful, the response will contain an authorization code that can be exchanged for an access token.
    - If there is an error, the response will contain error details.

Example Usage:
    response = requests.get(f"{BASE_URL}/v0/oauth/authorize", params=params)
    print(response.url)  # Check the redirect URL with the authorization code
"""

# Check if the authorization request was successful
if response.status_code == 200:
    # Extract the authorization code from the response
    # The expected response contains the string "code=<authorization_code>"
    auth_code = response.text.split("code=")[1].split("&")[0]  # Extract the authorization code
else:
    # In case of an error, print the error message and exit the program
    print(f"Error: {response.text}")
    exit(1)

# Check the authentication status
def check_authentication_status(auth_code):
    url = f"{BASE_URL}/valid/api/v1/trusted-services/authentications"
    params = {"code": auth_code}

    while True:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            if "authorizationToken" in data:
                return data["authorizationToken"]
        else:
            print("Authorization pending...")
            

        # Wait for 2 seconds before trying again
        time.sleep(2)

auth_token = check_authentication_status(auth_code)
if not auth_token:
    exit(1)


# Obtains the access_token using the auth_token
def get_access_token(auth_token):
    url = f"{BASE_URL}/v0/oauth/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "authorization_code",
        "code": auth_token,
        "redirect_uri": "push://",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code_verifier": code_verifier
    }

    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        return response.json().get("access_token")
    else:
        print(f"Error obtaining access_token: {response.text}")
        return None

access_token = get_access_token(auth_token)
if not access_token:
    exit(1)

# Função para assinar e salvar o PDF
def sign_and_save_pdf(access_token, pdf_path, output_path):
    """
    Signs a PDF document using the provided access token and saves the signed version.

    Args:
        access_token (str): The access token obtained from the authorization process.
        pdf_path (str): The path to the PDF file to be signed.
        output_path (str): The path where the signed PDF file will be saved.

    Returns:
        bool: True if the PDF was signed and saved successfully, False otherwise.
    """
    try:
        # 1. Read the PDF and validate the file
        with open(pdf_path, "rb") as file:
            pdf_content = file.read()
            if len(pdf_content) == 0:
                raise ValueError("PDF file is empty")

        # 2. Generate SHA256 hash and base64 of the content
        hash_bytes = hashlib.sha256(pdf_content).digest()
        hash_base64 = base64.b64encode(hash_bytes).decode("utf-8")
        pdf_base64 = base64.b64encode(pdf_content).decode("utf-8")

        # 3. Prepare the payload with validation
        payload = {
            "hashes": [{
                "id": "doc1",
                "alias": "documento.pdf",
                "hash": hash_base64,
                "hash_algorithm": "2.16.840.1.101.3.4.2.1",
                "signature_format": "PAdES_AD_RT",
                "pdf_signature_page": "true",
                "base64_content": pdf_base64  # Formato específico para PDF assinado
            }],
        }

        # 4. Configure headers with User-Agent
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "User-Agent": "Python-SDK/1.0"  # Adicione identificação da aplicação
        }

        # 5. Send request with timeout
        response = requests.post(
            url=f"{BASE_URL}/v0/oauth/signature",
            json=payload,
            headers=headers,
            timeout=30  # 30 seconds timeout
        )

        # 6. Process response
        response_data = response.json()

        # 7. Validate and save the signed PDF
        if "file_base64_signed" not in response_data["signatures"][0]:
            raise KeyError("Response does not contain 'file_base64_signed'")

        signed_content = base64.b64decode(response_data["signatures"][0]["file_base64_signed"].replace("\r\n", ""))
        
        with open(output_path, "wb") as file:
            file.write(signed_content)
            
        print(f"✅ Signed PDF saved at: {output_path}")
        return True
        
    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP Error {e.response.status_code}: {e.response.text}")
    except KeyError as e:
        print(f"❌ Missing field in response: {str(e)}")
    except IOError as e:
        print(f"❌ I/O Error: {str(e)}")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
    
    return False

# Usage:
sign_and_save_pdf(
    access_token=access_token,
    pdf_path="./mydocument.pdf",
    output_path="./mydocument_signed.pdf"
)