
import os
import tempfile
import unittest
import yaml

from mojo.credentials.credentialmanager import CredentialManager
from mojo.credentials.sshcredential import is_ssh_credential

from mojo.credentials.apitokencredential import ApiTokenCredential
from mojo.credentials.awsaccesskeycredential import AwsAccessKeyCredential
from mojo.credentials.azureclientsecretcredential import AzureClientSecretCredential
from mojo.credentials.basiccredential import BasicCredential
from mojo.credentials.personalapitokencredential import PersonalApiTokenCredential
from mojo.credentials.publickeycredential import PublicKeyCredential
from mojo.credentials.sshcredential import SshCredential
from mojo.credentials.wifichoicecredential import WifiChoiceCredential

CREDENTIAL_CONTENT = """
credentials:
    -   identifier: adminuser
        category:
            - basic
            - ssh
            - rest-basic
        username: admin
        password: "something"
    
    -   identifier: datauser
        category: basic
        username: datauser
        password: "datadata"

    -   identifier: pi-cluster
        category: ssh
        username: pi
        password: "pipass"
        primitive: True

    -   identifier: cred-api
        categories: api-token
        token: '55FB9FFAB6EF4499AD432BCC6D6001985B7DFC3FE1F247308C6BBC8187102E71'
    
    -   identifier: cred-access-key
        categories: aws-access-key
        keyid: 'FETD64DUFYLUFY'
        secret: '55FB9FFAB6EF4499AD432BCC6D6001985B7DFC3FE1F247308C6BBC8187102E71'
    
    -   identifier: cred-azure
        categories: azure-client-secret
        client_id: 'FETD64DUFYLUFY'
        client_secret: '55FB9FFAB6EF4499AD432BCC6D6001985B7DFC3FE1F247308C6BBC8187102E71'
        tenant_id: 7DFC3FE1F247

    -   "identifier": "jira-token"
        "category": "personal-api-token"
        "username": "some.guy@google.com"
        "token": "B130909CD9744F1E8679755034F9E70B08519F16C3DE46FCBFE82117F2794BA1"

    -   "identifier": cred-pk
        "category": "public-key"
        "public": "FETD64DUFYLUFY"
        "private": "B130909CD9744F1E8679755034F9E70B08519F16C3DE46FCBFE82117F2794BA1"
    
    -   identifier: cred-ssh-keyfile
        category: ssh
        username: pi
        keyfile: '~/id_tempkey_rsa'
        primitive: True
    
    -   identifier: cred-ssh-keyraw
        category: ssh
        username: pi
        keyraw: "B130909CD9744F1E8679755034F9E70B08519F16C3DE46FCBFE82117F2794BA1"
        primitive: True
    
    -   identifier: "my-wifi-networks"
        category: "wifi-choice"
        networks:
            - ssid: SOMENETWORK
              password: BlahBlah!!
"""

class TestCredentials(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:

        cls.key_file = os.path.expanduser("~/id_tempkey_rsa")
        with open(cls.key_file, 'w') as kf:
            kf.write("Doesn't matter whats in the file, we just need to make sure it exists.")

        cls.cred_file = tempfile.mktemp(suffix=".yaml")

        with open(cls.cred_file, 'w') as cf:
            cf.write(CREDENTIAL_CONTENT)

        cred_info = None
        with open(cls.cred_file, 'r') as cf:
            cred_info = yaml.safe_load(cf)

        cls.cred_mgr = CredentialManager()
        cls.cred_mgr.load_credentials(cred_info, source_uris=[cls.cred_file])

        return
    
    @classmethod
    def tearDownClass(cls) -> None:
        os.remove(cls.cred_file)
        os.remove(cls.key_file)
        return
    
    def test_common_credential(self):

        credentials = self.cred_mgr.credentials

        cred_name = 'adminuser'
        assert cred_name in credentials, "There should have been a 'adminuser' credential."

        testcred = self.cred_mgr.lookup_credential(cred_name)

        assert "basic" in testcred.categories, f"The '{cred_name}' credential should include the 'basic' category."
        assert "ssh" in testcred.categories, f"The '{cred_name}' credential should include the 'ssh' category."
        assert "rest-basic" in testcred.categories, f"The '{cred_name}' credential should include the 'rest-basic' category."

        assert is_ssh_credential(testcred), f"The '{cred_name}' should be considered an SSH credential."

        assert testcred.username == 'admin', f"The username for '{cred_name}' should 'admin'."
        assert testcred.password == 'something', f"The username for '{cred_name}' should 'something'."

        assert isinstance(testcred, BasicCredential), "The credential returned should have been an 'BasicCredential'"

        return
    
    def test_api_token_credential(self):

        credentials = self.cred_mgr.credentials

        cred_name = 'cred-api'
        assert cred_name in credentials, f"There should have been a '{cred_name}' credential."

        testcred = self.cred_mgr.lookup_credential(cred_name)

        assert isinstance(testcred, ApiTokenCredential), "The credential returned should have been an 'ApiTokenCredential'"

        return

    def test_access_key_credential(self):

        credentials = self.cred_mgr.credentials

        cred_name = 'cred-access-key'
        assert cred_name in credentials, f"There should have been a '{cred_name}' credential."

        testcred = self.cred_mgr.lookup_credential(cred_name)

        assert isinstance(testcred, AwsAccessKeyCredential), "The credential returned should have been an 'AwsAccessKeyCredential'"

        return
    
    def test_azure_client_credential(self):

        credentials = self.cred_mgr.credentials

        cred_name = 'cred-azure'
        assert cred_name in credentials, f"There should have been a '{cred_name}' credential."

        testcred = self.cred_mgr.lookup_credential(cred_name)

        assert isinstance(testcred, AzureClientSecretCredential), "The credential returned should have been an 'AzureClientSecretCredential'"

        return
    
    def test_basic_credential(self):

        credentials = self.cred_mgr.credentials

        cred_name = 'datauser'
        assert cred_name in credentials, f"There should have been a '{cred_name}' credential."

        testcred = self.cred_mgr.lookup_credential(cred_name)

        assert isinstance(testcred, BasicCredential), "The credential returned should have been an 'BasicCredential'"

        return
    
    def test_personal_api_token_credential(self):

        credentials = self.cred_mgr.credentials

        cred_name = 'jira-token'
        assert cred_name in credentials, f"There should have been a '{cred_name}' credential."

        testcred = self.cred_mgr.lookup_credential(cred_name)

        assert isinstance(testcred, PersonalApiTokenCredential), "The credential returned should have been an 'PersonalApiTokenCredential'"

        return
    
    def test_public_key_credential(self):

        credentials = self.cred_mgr.credentials

        cred_name = 'cred-pk'
        assert cred_name in credentials, f"There should have been a '{cred_name}' credential."

        testcred = self.cred_mgr.lookup_credential(cred_name)

        assert isinstance(testcred, PublicKeyCredential), "The credential returned should have been an 'PublicKeyCredential'"

        return

    def test_ssh_key_credential_username_and_password(self):

        credentials = self.cred_mgr.credentials

        cred_name = 'pi-cluster'
        assert cred_name in credentials, f"There should have been a '{cred_name}' credential."

        testcred = self.cred_mgr.lookup_credential(cred_name)

        assert isinstance(testcred, SshCredential), "The credential returned should have been an 'SshCredential'"

        return
    
    def test_ssh_key_credential_username_and_keyfile(self):

        credentials = self.cred_mgr.credentials

        cred_name = 'cred-ssh-keyfile'
        assert cred_name in credentials, f"There should have been a '{cred_name}' credential."

        testcred = self.cred_mgr.lookup_credential(cred_name)

        assert isinstance(testcred, SshCredential), "The credential returned should have been an 'SshCredential'"

        return
    
    def test_ssh_key_credential_username_and_keyraw(self):

        credentials = self.cred_mgr.credentials

        cred_name = 'cred-ssh-keyraw'
        assert cred_name in credentials, f"There should have been a '{cred_name}' credential."

        testcred = self.cred_mgr.lookup_credential(cred_name)

        assert isinstance(testcred, SshCredential), "The credential returned should have been an 'SshCredential'"

        return
    
    def test_wifi_credential(self):

        credentials = self.cred_mgr.credentials

        cred_name = 'my-wifi-networks'
        assert cred_name in credentials, f"There should have been a '{cred_name}' credential."

        testcred = self.cred_mgr.lookup_credential(cred_name)

        assert isinstance(testcred, WifiChoiceCredential), "The credential returned should have been an 'WifiChoiceCredential'"

        return


if __name__ == '__main__':
    unittest.main()
