
__author__ = "Myron Walker"
__copyright__ = "Copyright 2023, Myron W Walker"
__credits__ = []
__version__ = "1.0.0"
__maintainer__ = "Myron Walker"
__email__ = "myron.walker@gmail.com"
__status__ = "Development" # Prototype, Development or Production
__license__ = "MIT"

from typing import TYPE_CHECKING

from threading import RLock


if TYPE_CHECKING:
    from mojo.credentials.credentialmanager import CredentialManager


CREDENTIAL_MANAGER_SINGLETON = None


SINGLETON_LOCK = RLock()



def CredentialManagerSingleton() -> "CredentialManager":
    """
        Instantiates and gets a global instance of the :class:`CredentialManager` class.  The
        :class:`CredentialManager` provides for management of credentials.
    """
    global CREDENTIAL_MANAGER_SINGLETON

    if CREDENTIAL_MANAGER_SINGLETON is None:
        SINGLETON_LOCK.acquire()
        try:
            from mojo.credentials.credentialmanager import CredentialManager

            if CREDENTIAL_MANAGER_SINGLETON is None:
                CREDENTIAL_MANAGER_SINGLETON = CredentialManager()
        finally:
            SINGLETON_LOCK.release()
    
    return CREDENTIAL_MANAGER_SINGLETON
