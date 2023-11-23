"""
.. module:: basecredential
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Module that contains the :class:`BaseCredential` object which is the
               common base class that all other credential objects inherit from.

.. moduleauthor:: Myron Walker <myron.walker@gmail.com>
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2023, Myron W Walker"
__credits__ = []
__version__ = "1.0.0"
__maintainer__ = "Myron Walker"
__email__ = "myron.walker@gmail.com"
__status__ = "Development" # Prototype, Development or Production
__license__ = "MIT"

from typing import List, Optional

class BaseCredential:
    """
        The :class:`BaseCredential` is the base container object for credentials passed in the landscape
        configuration file.

        .. code:: yaml
            "identifier": "player-ssh"
            "category": "(category)"
    """
    def __init__(self, *, identifier: str, categories: List[str], role: Optional[str]="priv"):
        """
            :param identifier: The identifier that is used to reference this credential.  (required)
            :param categories: The categories of authentication that the credential can
                               be used for.
            :param role: Identifies the role of the credential
        """
        if len(identifier) == 0:
            raise ValueError("The BaseCredential constructor requires a 'identifier' parameter be provided.")
        if len(categories) == 0:
            raise ValueError("The BaseCredential constructor requires a 'categories' parameter be provided.")

        self._identifier = identifier
        self._categories = categories
        self._role = role
        return

    @property
    def categories(self):
        return self._categories

    @property
    def identifier(self):
        return self._identifier

    @property
    def role(self):
        return self._role
