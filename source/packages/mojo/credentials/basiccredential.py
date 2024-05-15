"""
.. module:: basiccredential
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Module that contains the :class:`BasicCredential` which is a simple
               username and password based credential.

.. moduleauthor:: Myron Walker <myron.walker@gmail.com>
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2023, Myron W Walker"
__credits__ = []


from typing import Any, Dict, List, Optional

import os

from mojo.errors.exceptions import ConfigurationError

from mojo.credentials.basecredential import BaseCredential

class BasicCredential(BaseCredential):
    """
        The :class:`BasicCredential` is a container object for a basic username and password based credential.

        .. code:: yaml
            "identifier": "basic-login"
            "category": "basic"
            "username": "ubuntu"
            "password": "@@&_@@&_LetMeComeIn"

    """

    def __init__(self, *, identifier: str, categories: List[str], username: str, password: str,
                 role: Optional[str] = "priv"):
        """
            :param identifier: The identifier that is used to reference this credential.  (required)
            :param categories: The categories of authentication that are supported by the credential
            :param username: The username associated with this credential.
            :param password: The password associated with this credential.  A password is not required if a
                             keyfile parameter is provided or if 'allow_agent' is passed as 'True'.
        """
        super().__init__(identifier=identifier, categories=categories, role=role)

        if "basic" not in categories and "rest-basic" not in categories:
            raise ConfigurationError("The BasicCredential should only be given credentials of category 'basic'.")
        if len(username) == 0:
            raise ConfigurationError("The BasicCredential constructor requires a 'username' parameter be provided.")
        if len(password) == 0:
            raise ConfigurationError("The BasicCredential constructor requires one of: 'password is not None'.")

        self._username = username
        self._password = password
        return

    @property
    def password(self):
        return self._password

    @property
    def username(self):
        return self._username

    @classmethod
    def validate(cls, cred_info):

        errmsg_lines = []

        if "password" not in cred_info:
                errmsg_lines.append("    * missing 'password' in basic credential.")

        if "username" not in cred_info:
                errmsg_lines.append("    * missing 'username' in basic credential.")

        if len(errmsg_lines) > 0:
            identifier = "????"
            if "identifier" in cred_info:
                identifier = cred_info["identifier"]

            errmsg = "Errors found while validating the '{}' basic credential:".format(identifier)
            errmsg_lines.insert(0, errmsg)
            errmsg = os.linesep.join(errmsg_lines)

            raise ConfigurationError(errmsg) from None

        return

    def as_dict(self) -> Dict[str, Any]:
        """
            Returns a dictionary representation of this credential object.
        """
        rtnval = super().as_dict()

        rtnval["username"] = self._username
        rtnval["password"] = self._password

        return rtnval