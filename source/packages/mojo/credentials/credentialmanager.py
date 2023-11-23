"""
.. module:: basiccredential
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Module that contains the :class:`CredentialManager` which is used to
               load credentials.

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

import logging
import os

from mojo.errors.exceptions import ConfigurationError

from mojo.collections.contextpaths import ContextPaths
from mojo.collections.wellknown import ContextSingleton

from mojo.config.configurationmaps import CONFIGURATION_MAPS

from mojo.credentials.azureclientsecretcredential import AzureClientSecretCredential
from mojo.credentials.basiccredential import BasicCredential
from mojo.credentials.sshcredential import SshCredential
from mojo.credentials.wifichoicecredential import WifiChoiceCredential

logger = logging.getLogger()

class CredentialManager:

    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(CredentialManager, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        thisType = type(self)

        if not thisType._initialized:
            thisType._initialized = True

            self._credentials = {}
            self._initialize_credentials()

        return

    @property
    def credentials(self):
        return self._credentials

    def lookup_credential(self, credkey: str) -> BasicCredential:
        """
            Lookup a credential by key.
        """
        
        if credkey not in self._credentials:
            ctx = ContextSingleton()

            errmsg_lines = [
                f"Error missing credential '{credkey}'.",
                "CREDENTIAL URIS:"
            ]
        
            for cfile in ctx.lookup(ContextPaths.CONFIG_CREDENTIAL_URIS, []):
                errmsg_lines.append(f"    {cfile}")

            errmsg = os.linesep.join(errmsg_lines)
            raise ConfigurationError(errmsg)
        
        cred = self._credentials[credkey]
        
        return cred

    def _initialize_credentials(self):
        """
        """

        if CONFIGURATION_MAPS.CREDENTIAL_CONFIGURATION_MAP is not None and \
            len(CONFIGURATION_MAPS.CREDENTIAL_CONFIGURATION_MAP) > 0:

            credential_info = CONFIGURATION_MAPS.CREDENTIAL_CONFIGURATION_MAP

            try:
                credentials_list = credential_info["credentials"]
                errors, warnings = self._validate_credentials(credentials_list)

                if len(errors) == 0:
                    for credential in credentials_list:
                        # Copy the credential so if we modify it, we dont modify the
                        # original declaration.
                        credential = credential.copy()

                        if "identifier" not in credential:
                            errmsg = "Credential items in 'environment/credentials' must have an 'identifier' member."
                            raise ConfigurationError(errmsg)
                        ident = credential["identifier"]

                        if "category" not in credential:
                            errmsg = "Credential items in 'environment/credentials' must have an 'category' member."
                            raise ConfigurationError(errmsg)
                        category = credential["category"]
                        del credential["category"]

                        if isinstance(category, list):
                            categories = list(category)
                            credential["categories"] = categories

                            username = credential["username"]
                            password = credential["password"]

                            BasicCredential.validate(credential)
                            credobj = BasicCredential(identifier=ident, categories=categories,
                                                        username=username, password=password)
                            self._credentials[ident] = credobj

                        else:
                            credential["categories"] = [category]

                            if category == 'azure-client-secret':
                                AzureClientSecretCredential.validate(credential)
                                credobj = AzureClientSecretCredential(**credential)
                                self._credentials[ident] = credobj
                            elif category == "basic" or category == "rest-basic":
                                BasicCredential.validate(credential)
                                credobj = BasicCredential(**credential)
                                self._credentials[ident] = credobj
                            elif category == "ssh":
                                SshCredential.validate(credential)
                                credobj = SshCredential(**credential)
                                self._credentials[ident] = credobj
                            elif category == "wifi-choice":
                                WifiChoiceCredential.validate(credential)
                                credobj = WifiChoiceCredential(**credential)
                                self._credentials[ident] = credobj
                            else:
                                warnmsg = f"Unknown category '{category}' found in credential '{ident}'"
                                logger.warn(warnmsg)

                else:
                    errmsg_lines = [
                        f"Errors found in credentials.",
                        "ERRORS:"
                    ]
                    for err in errors:
                        errmsg_lines.append(f"    {err}")

                    errmsg_lines.append("WARNINGS:")
                    for warn in warnings:
                        errmsg_lines.append(f"    {warn}")

                    errmsg = os.linesep.join(errmsg_lines)
                    raise ConfigurationError(errmsg)

            except KeyError:
                errmsg = f"No 'credentials' field found."
                raise ConfigurationError(errmsg)

        return

    def _validate_credentials(self, cred_list):
        errors = []
        warnings = []

        identifier_set = set()

        for cinfo in cred_list:
            if "identifier" in cinfo:
                identifier = cinfo["identifier"]
                if identifier in identifier_set:
                    errmsg = f"Duplicate identifer found. identifier={identifier}"
                    errors.append(errmsg)
                else:
                    identifier_set.add(identifier)
            else:
                errmsg = f"All credentials must have an identifier field. cinfo={cinfo}"
                errors.append(errmsg)

            if "category" in cinfo:
                category = cinfo["category"]
                if category == "basic":
                    child_errors, child_warnings =  self._validate_credential_basic(cinfo)
                    errors.extend(child_errors)
                    warnings.extend(child_warnings)
                elif category == "ssh":
                    child_errors, child_warnings =  self._validate_credential_ssh(cinfo)
                    errors.extend(child_errors)
                    warnings.extend(child_warnings)
                else:
                    warnmsg = f"Unknown credential category={category}. info={cinfo}"
                    warnings.append(warnmsg)
            else:
                errmsg = "Credential info has no category. info=%r" % cinfo
                errors.append(errmsg)

        return errors, warnings

    def _validate_credential_basic(self, cred):
        """
            Validates the non-common fields of a 'basic' credential.
        """
        errors = []
        warnings = []

        if "username" in cred:
            if len(cred["username"].strip()) == 0:
                errmsg = "The 'username' for a basic credential cannot be empty."
                errors.append(errmsg)
        else:
            errmsg = "Basic credentials must have a 'username' field."
            errors.append(errmsg)

        if "password" not in cred:
            errmsg = "Basic credentials must have a 'password' field."
            errors.append(errmsg)

        return errors, warnings

    def _validate_credential_ssh(self, cred):
        """
            Validates the non-common fields of an 'ssh' credential.
        """
        """
        -   "identifier": "some-node"
            "category": "ssh"
            "username": "ubuntu"
            "password": "blahblah"
            "keyfile": "~/.ssh/id_somenode_rsa"

        """
        errors = []
        warnings = []

        if "username" in cred:
            if len(cred["username"].strip()) == 0:
                errmsg = "The 'username' for an SSH credential cannot be empty."
                errors.append(errmsg)
        else:
            errmsg = "SSH credentials must have a 'username' field."
            errors.append(errmsg)

        if "password" not in cred and "keyfile" not in cred:
            errmsg = "SSH credentials must have a 'password' or 'keyfile' field."
            errors.append(errmsg)
        elif "keyfile" in cred:
            keyfile = os.path.abspath(os.path.expanduser(os.path.expandvars(cred["keyfile"])))
            if not os.path.exists(keyfile):
                errmsg = "The specified SSH keyfile does not exist. file=%s" % keyfile
                errors.append(errmsg)

        return errors, warnings
