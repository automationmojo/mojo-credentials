"""
.. module:: apitokencredential
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Module that contains the :class:`BasicCredential` which is a simple
               username and password based credential.

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

import os

from mojo.errors.exceptions import ConfigurationError

from mojo.credentials.basecredential import BaseCredential

class ApiTokenCredential(BaseCredential):
    """
        The :class:`ApiTokenCredential` is a container object for an api token credential.

        .. code:: yaml
            "identifier": "jira-token"
            "category": "api-token"
            "token": "B130909CD9744F1E8679755034F9E70B08519F16C3DE46FCBFE82117F2794BA1"

    """

    def __init__(self, *, identifier: str, categories: List[str], token: str, role: Optional[str] = "priv"):
        """
            :param identifier: The identifier that is used to reference this credential.  (required)
            :param categories: The categories of authentication that are supported by the credential
            :param token: A token that services as an identity and authenticate to allow the use of specific APIs.
        """
        super().__init__(identifier=identifier, categories=categories, role=role)

        if "api-token" not in categories:
            raise ValueError("The ApiTokenCredential should only be given credentials of category 'api-token'.")
        if len(token) == 0:
            raise ValueError("The ApiTokenCredential constructor requires a 'token' parameter be provided.")
        
        self._token = token
        return

    @property
    def token(self):
        return self._token

    @classmethod
    def validate(cls, cred_info):

        errmsg_lines = []

        if "token" not in cred_info:
                errmsg_lines.append("    * missing 'token' in api token credential.")

        if len(errmsg_lines) > 0:
            identifier = "????"
            if "identifier" in cred_info:
                identifier = cred_info["identifier"]

            errmsg = "Errors found while validating the '{}' basic credential:".format(identifier)
            errmsg_lines.insert(0, errmsg)
            errmsg = os.linesep.join(errmsg_lines)

            raise ConfigurationError(errmsg) from None

        return
