# PDF Signing Script with PSC Valid

This script is designed to handle the process of sending a push notification for authorization, verifying the push, obtaining an access token, and signing a PDF document using the obtained token with PSC Valid.

## Main Steps

1. Generate a PKCE (Proof Key for Code Exchange) code_verifier and code_challenge.
2. Send an authorization request via push notification.
3. Verify the status of the push notification authorization.
4. Obtain an access token using the authorization code.
5. Sign a PDF document and save the signed version.

## Documentation

For more details, refer to the official PSC Valid API documentation:  
[PSC Valid API Documentation](https://valid-sa.atlassian.net/wiki/spaces/PDD/pages/958365697/Manual+de+Integra+o+com+VIDaaS+-+Certificado+em+Nuvem)

## Dependencies

- `requests`: For making HTTP requests.
- `hashlib`: For generating SHA256 hashes.
- `base64`: For encoding and decoding base64.
- `os`: For accessing environment variables.
- `time`: For adding delays between requests.
- `dotenv`: For loading environment variables from a .env file.

## Setup

Make sure to set up a `.env` file with the following variables:

- `CLIENT_ID`: Your client ID.
- `CLIENT_SECRET`: Your client secret.
- `LOGINHINT`: The login hint (e.g., CPF or CNPJ).

### Example .env file

```plaintext
CLIENT_ID=4c9fb552-0387-4e5f-8727-6676fa88dce1
CLIENT_SECRET=Ny2n3hq67gQEFvH7
LOGINHINT=12345678901