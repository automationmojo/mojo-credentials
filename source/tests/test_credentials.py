
import os
import tempfile
import unittest

from mojo.config.configurationmaps import resolve_configuration_maps
from mojo.config.optionoverrides import MOJO_CONFIG_OPTION_OVERRIDES
from mojo.config.variables import resolve_configuration_variables

from mojo.collections.contextpaths import ContextPaths
from mojo.collections.wellknown import ContextSingleton

from mojo.credentials.credentialmanager import CredentialManager
from mojo.credentials.sshcredential import is_ssh_credential

CREDENTIAL_CONTENT = """
credentials:
    -   identifier: adminuser
        category:
            - basic
            - ssh
        username: adminuser
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
"""

class TestCredentials(unittest.TestCase):

    def setUp(self) -> None:
        self._cred_file = tempfile.mktemp(suffix=".yaml")

        with open(self._cred_file, 'w') as cf:
            cf.write(CREDENTIAL_CONTENT)

        credential_files = [self._cred_file]

        resolve_configuration_variables()

        MOJO_CONFIG_OPTION_OVERRIDES.override_config_credentials_files(credential_files)

        resolve_configuration_maps(use_credentials=True)

        return
    
    def tearDown(self) -> None:
        os.remove(self._cred_file)
        return
    
    def test_initialize_credentials(self):

        cred_mgr = CredentialManager()

        credentials = cred_mgr.credentials

        assert "adminuser" in credentials, "There should have been a 'adminuser' credential."
        assert "datauser" in credentials, "There should have been a 'datauser' credential."
        assert "pi-cluster" in credentials, "There should have been a 'pi-cluster' credential."

        admincred = credentials["adminuser"]

        assert "basic" in admincred.categories, "The 'adminuser' credential should include the 'basic' category."
        assert "ssh" in admincred.categories, "The 'adminuser' credential should include the 'basic' category."

        assert is_ssh_credential(admincred), "The 'adminuser' should be considered an SSH credential."

        return

if __name__ == '__main__':
    unittest.main()
