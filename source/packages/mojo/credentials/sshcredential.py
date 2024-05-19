"""
.. module:: basiccredential
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Module that contains the :class:`SshCredential` which provides support
               for SSH credentials including support for public key based SSH authentication.

.. moduleauthor:: Myron Walker <myron.walker@gmail.com>
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2023, Myron W Walker"
__credits__ = []


from typing import Any, Dict, List, Optional, Union

import os

from mojo.errors.exceptions import ConfigurationError

from mojo.credentials.basecredential import BaseCredential

class SshCredential(BaseCredential):
    """
        The :class:`SshCredential` is a container object for SSH credentials passed in the landscape
        configuration file.

        .. code:: yaml
            "identifier": "straw-node"
            "scheme": "ssh"
            "username": "ubuntu"
            "password": "@@&_@@&_LetMeComeIn"
            "keyfile": "~/.ssh/id_blah_rsa"
            "keypasswd": "@@&_@@&_LetMeComeIn"
            "allow_agent": False
    """

    def __init__(self, *, identifier: str, categories: List[str], username: str, role: Optional[str] = "priv",
                 password: Optional[str] = None, keyfile: Optional[str] = None, keyraw: Optional[str]= None, 
                 keypasswd: Optional[str] = None, allow_agent: bool = False, primitive: bool=False):
        """
            :param identifier: The identifier that is used to reference this credential.  (required)
            :param categories: The categories of authentication that are supported by the credential
            :param role: An optional parameter that identifies the role that the credential is assigned to.
            :param username: The username associated with this credential.
            :param password: The password associated with this credential.  A password is not required if a
                             keyfile parameter is provided or if 'allow_agent' is passed as 'True'.
            :param keyfile: The private key file to use for authentication with this credential.  A keyfile
                            is not required if a password was passed or if 'allow_agent' is passed as 'True'.
            :param keyraw: The raw private key in base64 or other text encoded format.
            :param keypasswd: The password to decrypt the keyfile if required by the keyfile.
            :param allow_agent: Indicates if the SSH Agent can be used to authenticate connections.
            :param primitive: When True, simulate file transfers and directory services with ssh commands.
        """
        super().__init__(identifier=identifier, categories=categories, role=role)

        if "ssh" not in categories:
            raise ConfigurationError("The SshCredential should only be given credentials of category 'ssh'.")
        if len(username) == 0:
            raise ConfigurationError("The SshCredential constructor requires a 'username' parameter be provided.")
        if password is None:
            if not allow_agent:
                if keyfile is None and keyraw is None:
                    raise ConfigurationError("The SshCredential constructor requires one of: 'password is not None', 'keyfile is not None', 'keyraw is not None', 'allow_agent == True'.")
                elif keyfile is not None and keyraw is not None:
                    raise ConfigurationError("The SshCredential constructor should only have either a keyfile or keyraw parameter but not both.")

        self._username = username
        self._password = password
        self._keyfile = keyfile
        self._keyraw = keyraw
        self._keypasswd = keypasswd
        self._allow_agent = allow_agent
        self._primitive = primitive
        return

    @property
    def allow_agent(self) -> bool:
        return self._allow_agent

    @property
    def keyfile(self) -> Union[str, None]:
        return self._keyfile
    
    @property
    def keyraw(self) -> Union[str, None]:
        return self._keyfile

    @property
    def keypasswd(self) -> Union[str, None]:
        return self._keypasswd

    @property
    def password(self) -> Union[str, None]:
        return self._password

    @property
    def primitive(self) -> bool:
        return self._primitive

    @property
    def username(self) -> str:
        return self._username

    @classmethod
    def validate(cls, cred_info):

        errmsg_lines = []

        allow_agent = False
        if "allow_agent" in cred_info:
            allow_agent = cred_info["allow_agent"]

        if "identifier" not in cred_info:
            errmsg_lines.append("    * missing 'identifier' parameter")

        if "username" not in cred_info:
            errmsg_lines.append("    * missing 'username' parameter")

        if "password" not in cred_info:
            if  not allow_agent:
                if "keyfile" not in cred_info and "keyraw" not in cred_info:
                    errmsg_lines.append("    * missing 'password' or 'keyfile' when allow_agent is 'False'")
        
        if "keyfile" in cred_info and "keyraw" in cred_info:
            errmsg_lines.append("    * both 'keyfile' and 'keyraw' found in ssh credential.")

        if "keyfile" in cred_info:
            keyfile = os.path.abspath(os.path.expandvars(os.path.expanduser(cred_info["keyfile"])))
            if not os.path.exists(keyfile):
                errmsg_lines.append("    * specified 'keyfile={}' not found.".format(keyfile))

        if len(errmsg_lines) > 0:
            identifier = "????"
            if "identifier" in cred_info:
                identifier = cred_info["identifier"]

            errmsg = "Errors found while validating the '{}' SSH credential:".format(identifier)
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
        rtnval["allow_agent"] = self._allow_agent
        rtnval["pimitive"] = self._primitive

        if self._password is not None:
            rtnval["password"] =  self._password

        if self._keyfile is not None:
            rtnval["keyfile"] = self._keyfile
        
        if self._keypasswd is not None:
            rtnval["keypasswd"] = self._keypasswd
        
        if self._keyraw is not None:
            rtnval["keyraw"] = self._keyraw

        return rtnval


def is_ssh_credential(cred: BaseCredential) -> bool:
    """
        Checks to see if a credential is a credential that has been designated
        for use with SSH.

        :returns: A boolean value representing if the credential has been marked as an SSH credential.
    """
    rtnval = False
    
    if "ssh" in cred.categories:
        rtnval = True
    
    return rtnval
