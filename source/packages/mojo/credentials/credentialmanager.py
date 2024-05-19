"""
.. module:: credentialmanager
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Module that contains the :class:`CredentialManager` which is used to
               load credentials.

.. moduleauthor:: Myron Walker <myron.walker@gmail.com>
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2023, Myron W Walker"
__credits__ = []


from typing import List, Optional, Union

import logging
import os

from mojo.errors.exceptions import ConfigurationError

from mojo.credentials.apitokencredential import ApiTokenCredential
from mojo.credentials.awsaccesskeycredential import AwsAccessKeyCredential
from mojo.credentials.azureclientsecretcredential import AzureClientSecretCredential
from mojo.credentials.basiccredential import BasicCredential
from mojo.credentials.personalapitokencredential import PersonalApiTokenCredential
from mojo.credentials.publickeycredential import PublicKeyCredential
from mojo.credentials.sshcredential import SshCredential
from mojo.credentials.wifichoicecredential import WifiChoiceCredential

logger = logging.getLogger()

class CredentialManager:

    def __init__(self):

        self._credentials = {}
        self._source_uris = []

        return

    @property
    def credentials(self):
        return self._credentials

    def lookup_credential(self, credkey: str) -> Union[ApiTokenCredential, AzureClientSecretCredential, BasicCredential, PersonalApiTokenCredential, SshCredential, WifiChoiceCredential]:
        """
            Lookup a credential by key.
        """
        
        if credkey not in self._credentials:

            errmsg_lines = [
                f"Error missing credential '{credkey}'."
            ]
        
            if len(self._source_uris) > 0:
                errmsg_lines.append("CREDENTIAL URIS:")

                for cfile in self._source_uris:
                    errmsg_lines.append(f"    {cfile}")

            errmsg = os.linesep.join(errmsg_lines)

            raise ConfigurationError(errmsg)
        
        cred = self._credentials[credkey]
        
        return cred

    def load_credentials(self, credential_info: dict, source_uris: Optional[List[str]] = None):
        """
        """

        if source_uris != None:
            self._source_uris.extend(source_uris)

        if credential_info is not None and len(credential_info) > 0:
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

                        if "category" not in credential and "categories" not in credential:
                            errmsg = "Credential items in 'environment/credentials' must have an 'category' or categories member."
                            raise ConfigurationError(errmsg)

                        # If we find a 'category' or 'categories' parameter we need to pass the categories along as a single
                        # list parameter 
                        categories = []
                        if "category" in credential:
                            category = credential["category"]
                            del credential["category"]

                            if isinstance(category, list):
                                categories = category
                            else:
                                categories = [ category]

                            credential["categories"] = categories
                        
                        elif "categories" in credential:
                            categories = credential["categories"]

                            if isinstance(categories, str):
                                categories = [ categories ]


                        # If the credential has more than one category, we create a simple `BasicCredential` which has a common set of
                        # attributes.  The only credential we support with common attributes is a simple 'username' and 'password' credetial 
                        if len(categories) > 1:

                            for category in categories:
                                if category not in ['basic', 'ssh', 'rest-basic']:
                                    errmsg = "The only categories of credentials that can be used together are ['basic', 'ssh (with password)', 'rest-basic']"
                                    raise ConfigurationError(errmsg)

                            if "username" in credential and "password" in credential:

                                username = credential["username"]
                                password = credential["password"]

                                BasicCredential.validate(credential)
                                credobj = BasicCredential(identifier=ident, categories=categories, username=username, password=password)
                                
                                self._credentials[ident] = credobj
                            
                            else:
                                errmsg = "Multi category credentials must have common attributes. Currently, the only common credential supporte is a 'username' and 'password' credential."
                                raise ConfigurationError(errmsg)

                        else:
                            category = categories[0]

                            if category == "api-token":
                                ApiTokenCredential.validate(credential)
                                credobj = ApiTokenCredential(**credential)
                                self._credentials[ident] = credobj

                            elif category == "aws-access-key":
                                AwsAccessKeyCredential.validate(credential)
                                credobj = AwsAccessKeyCredential(**credential)
                                self._credentials[ident] = credobj

                            elif category == 'azure-client-secret':
                                AzureClientSecretCredential.validate(credential)
                                credobj = AzureClientSecretCredential(**credential)
                                self._credentials[ident] = credobj

                            elif category == "basic" or category == "rest-basic":
                                BasicCredential.validate(credential)
                                credobj = BasicCredential(**credential)
                                self._credentials[ident] = credobj

                            elif category == "personal-api-token":
                                PersonalApiTokenCredential.validate(credential)
                                credobj = PersonalApiTokenCredential(**credential)
                                self._credentials[ident] = credobj

                            elif category == "public-key":
                                PublicKeyCredential.validate(credential)
                                credobj = PublicKeyCredential(**credential)
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

                    errmsg_lines.append("SOURCE_URIS:")
                    for suri in self._source_uris:
                        errmsg_lines.append(f"    {suri}")

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

            if "category" in cinfo or "categories" in cinfo:

                if 'category' in cinfo and 'categories' in cinfo:
                    errmsg = "A credetial should not have both a 'category' and 'categories' field.  The newest method is to just use a 'catagories' field."
                    raise ConfigurationError(errmsg)

                categories = None

                if "category" in cinfo:
                    category = cinfo["category"]
                    del cinfo["category"]

                    if isinstance(category, list):
                        categories = category
                    else:
                        categories = [ category]

                    cinfo["categories"] = categories
            
                elif "categories" in cinfo:
                    categories = cinfo["categories"]
                    if isinstance(categories, str):
                        categories = [ categories]

                if len(categories) > 1:
                    for category in categories:
                        if category not in ['basic', 'ssh', 'rest-basic']:
                            errmsg = "The only categories of credentials that can be used together are ['basic', 'ssh (with password)', 'rest-basic']"
                            raise ConfigurationError(errmsg)
                    
                    if "username" not in cinfo or "password" not in cinfo:
                        errmsg = "Multi category credentials must have common attributes. Currently, the only common credential supporte is a 'username' and 'password' credential."
                        raise ConfigurationError(errmsg)

                else:
                    category = categories[0]

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

        if "password" not in cred and "keyfile" not in cred and "keyraw" not in cred:
            if "allow_agent" not in cred or cred["allow_agent"] == False:
                errmsg = "SSH credentials must have a 'password, keyfile, keyraw, or allow_agent == True' field."
                errors.append(errmsg)
        elif "keyfile" in cred:
            keyfile = os.path.abspath(os.path.expanduser(os.path.expandvars(cred["keyfile"])))
            if not os.path.exists(keyfile):
                errmsg = "The specified SSH keyfile does not exist. file=%s" % keyfile
                errors.append(errmsg)

        return errors, warnings
