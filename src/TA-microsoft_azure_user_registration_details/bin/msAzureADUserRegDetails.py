import sys
import json
import requests
import time
import socket
from splunklib.modularinput import *
import splunklib.client as client


class MsAzureADUserRegDetails(Script):

    MASK = "***ENCRYPTED***"
    CREDENTIALS = None

    def get_scheme(self):

        scheme = Scheme("Microsoft Azure AD - User Registration Details")
        scheme.use_external_validation = False
        scheme.use_single_instance = False
        scheme.description = "Dump of User Registration Details from Azure AD"

        client_id = Argument("client_id")
        client_id.title = "Application/Client ID"
        client_id.data_type = Argument.data_type_string
        client_id.description = "Microsoft Graph App Registered ID"
        client_id.required_on_create = True
        client_id.required_on_edit = False
        scheme.add_argument(client_id)

        client_secret = Argument("client_secret")
        client_secret.title = "Client Secret"
        client_secret.data_type = Argument.data_type_string
        client_secret.description = "Client Secret"
        client_secret.required_on_create = True
        client_secret.required_on_edit = True
        scheme.add_argument(client_secret)

        tenant_id = Argument("tenant_id")
        tenant_id.title = "Tenant/Directory ID"
        tenant_id.data_type = Argument.data_type_string
        tenant_id.description = "Tenant ID"
        tenant_id.required_on_create = True
        tenant_id.required_on_edit = False
        scheme.add_argument(tenant_id)

        return scheme

    def list_user_registration_details(self, ew, _client_id, _client_secret, _tenant_id):
        
        # Azure App credentials
        client_id = _client_id
        client_secret = _client_secret
        tenant_id = _tenant_id
        
        token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
        
        # Prepare the data for token request
        token_data = {
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }
        
        # Request an access token
        token_response = requests.post(token_url, data=token_data)
        token_response_data = token_response.json()
        
        # Extract access token
        access_token = token_response_data['access_token']
        
        # Construct the URL for Microsoft Graph API endpoint
        graph_url = 'https://graph.microsoft.com/beta/'
        
        # Construct the URL for user registration details endpoint
        user_registration_url = graph_url + 'reports/authenticationMethods/userRegistrationDetails'

        # Prepare the headers for the request
        headers = {
            'Authorization': 'Bearer ' + access_token,
            'Content-Type': 'application/json'
        }
        
        # Placeholder to store all user registration details
        all_user_registration_details = []
        
        try:
            # Make the initial request to retrieve user registration details
            response = requests.get(user_registration_url, headers=headers)
            if response.status_code == 200:
                
                ew.log("INFO", f"MS Azure AD userRegistrationDetails first page successfully collected.")
                
                user_registration_details = response.json()
                all_user_registration_details.extend(user_registration_details['value'])
                
                counter = 1

                # Check if there are more pages
                while '@odata.nextLink' in user_registration_details:
                    next_link = user_registration_details['@odata.nextLink']
                    response = requests.get(next_link, headers=headers)
                    if response.status_code == 200:
                        
                        counter = counter + 1
                        
                        ew.log("INFO", f"MS Azure AD userRegistrationDetails page {str(counter)} successfully collected.")
                        
                        user_registration_details = response.json()
                        all_user_registration_details.extend(user_registration_details['value'])
                    else:
                        break
            else:
                ew.log("ERROR", f"Unsuccessful MS Graph Request. status_code={str(response.status_code)}")
        except Exception as e:
            ew.log("ERROR", f"Unsuccessful MS Graph Request. Error: {str(e)}")
            sys.exit(1)
        
        ew.log("INFO", "Successful MS Graph Request.")
        
        return all_user_registration_details

    def validate_input(self, definition):
        pass

    def encrypt_keys(self, _client_id, _client_secret, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        credentials = {"clientId": _client_id, "clientSecret": _client_secret}

        try:
            for storage_password in service.storage_passwords:
                if storage_password.username == _client_id:
                    service.storage_passwords.delete(
                        username=storage_password.username)
                    break

            service.storage_passwords.create(json.dumps(credentials), _client_id)

        except Exception as e:
            raise Exception("Error encrypting: %s" % str(e))

    def mask_credentials(self, _input_name, _client_id, _tenant_id, _session_key):

        try:
            args = {'token': _session_key}
            service = client.connect(**args)

            kind, _input_name = _input_name.split("://")
            item = service.inputs.__getitem__((_input_name, kind))

            kwargs = {
                "client_id": _client_id,
                "client_secret": self.MASK,
                "tenant_id": _tenant_id,
            }

            item.update(**kwargs).refresh()

        except Exception as e:
            raise Exception("Error updating inputs.conf: %s" % str(e))

    def decrypt_keys(self, _client_id, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        for storage_password in service.storage_passwords:
            if storage_password.username == _client_id:
                return storage_password.content.clear_password

    def stream_events(self, inputs, ew):
        
        start = time.time()
        
        self.input_name, self.input_items = inputs.inputs.popitem()
        session_key = self._input_definition.metadata["session_key"]

        client_id = self.input_items["client_id"]
        client_secret = self.input_items["client_secret"]
        tenant_id = self.input_items["tenant_id"]

        ew.log("INFO", f'Start of collecting MS Azure AD userRegistrationDetails.')

        try:
            
            if client_secret != self.MASK:
                self.encrypt_keys(client_id, client_secret, session_key)
                self.mask_credentials(self.input_name, client_id, tenant_id, session_key)

            decrypted = self.decrypt_keys(client_id, session_key)
            self.CREDENTIALS = json.loads(decrypted)

            client_secret = self.CREDENTIALS["clientSecret"]

            user_registration_details_dumps = self.list_user_registration_details(ew, client_id, client_secret, tenant_id)
            
            apiScriptHost = socket.gethostname()

            for user_details in user_registration_details_dumps:
                user_details["clientId"] = client_id
                user_details["tenantId"] = tenant_id
                user_details["apiScriptHost"] = apiScriptHost
                user_details_event = Event()
                user_details_event.stanza = self.input_name
                user_details_event.sourceType = "ms:aad:userRegistrationDetails"
                user_details_event.data = json.dumps(user_details)
                ew.write_event(user_details_event)
        
        except Exception as e:
            ew.log("ERROR", "[MS Azure AD userRegistrationDetails] Error: %s" % str(e))
        
        end = time.time()
        elapsed = round((end - start) * 1000, 2)
        ew.log("INFO", f'Process completed in {str(elapsed)} ms. input_name="{self.input_name}"')


if __name__ == "__main__":
    sys.exit(MsAzureADUserRegDetails().run(sys.argv))
