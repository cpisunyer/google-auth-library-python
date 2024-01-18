import abc
from dataclasses import dataclass
import json
import os
import struct
import subprocess
from typing import List, Dict, Optional

from google.auth import exceptions

@dataclass(frozen=True)
class PublicKeyCredentialDescriptor:
<<<<<<< HEAD
    """PublicKeyCredentialDescriptor
=======
    """Descriptor for a security key based credential.

    https://www.w3.org/TR/webauthn-3/#dictionary-credential-descriptor
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)

    Args:
        id: <url-safe base64-encoded> credential id (key handle).
        transports: <'usb'|'nfc'|'ble'|'internal'> List of supported transports.
    """
    id: str
    transports: Optional[List[str]] = None

    def to_dict(self):
        cred = {
            'type': 'public-key',
            'id': self.id
        }
        if self.transports:
            cred['trasnports'] = self.transports
        return cred

<<<<<<< HEAD
<<<<<<< HEAD

@dataclass
class AuthenticationExtensionsClientInputs:
    """AuthenticationExtensionsClientInputs

    Args:
        appid: app id that can be asserted with in addition to rpid.
=======
=======

>>>>>>> 6c444f5 (feat: Integrate webauthn handler.)
@dataclass
class AuthenticationExtensionsClientInputs:
    """Client extensions inputs for WebAuthn extensions.

    Args:
        appid: app id that can be asserted with in addition to rpid.
            https://www.w3.org/TR/webauthn-3/#sctn-appid-extension
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)
    """
    appid: Optional[str] = None

    def to_dict(self):
        extensions = {}
        if self.appid:
            extensions['appid'] = self.appid
        return extensions

<<<<<<< HEAD
<<<<<<< HEAD

=======
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)
=======

>>>>>>> 6c444f5 (feat: Integrate webauthn handler.)
@dataclass
class GetRequest:
    """WebAuthn get request

    Args:
        origin: Origin where the WebAuthn get assertion takes place.
<<<<<<< HEAD
        timeout_ms: Timeout number in millisecond.
        rpid: Relying Party ID.
        challenge: <url-safe base64-encoded> raw challenge.
=======
        rpid: Relying Party ID.
        challenge: <url-safe base64-encoded> raw challenge.
        timeout_ms: Timeout number in millisecond.
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)
        allow_credentials: List of allowed credentials.
        user_verification: <'required'|'preferred'|'discouraged'> User verification requirement.
        extensions: WebAuthn authentication extensions inputs.
    """
    origin: str
<<<<<<< HEAD
    timeout_ms: Optional[int] = None
    rpid: str = None
    challenge: str = None
=======
    rpid: str
    challenge: str
    timeout_ms: Optional[int] = None
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)
    allow_credentials: Optional[List[PublicKeyCredentialDescriptor]] = None
    user_verification: Optional[str] = None
    extensions: Optional[AuthenticationExtensionsClientInputs] = None

    def to_json(self) -> str:
        req_options = {
            'rpid': self.rpid,
            'challenge': self.challenge
        }
        if self.timeout_ms:
            req_options['timeout'] = self.timeout_ms
        if self.allow_credentials:
            req_options['allowCredentials'] = [c.to_dict() for c in self.allow_credentials]
        if self.user_verification:
            req_options['userVerification'] = self.user_verification
        if self.extensions:
            req_options['extensions'] = self.extensions.to_dict()
        return json.dumps({
            'type': 'get',
            'origin': self.origin,
            'requestData': req_options,
        })

@dataclass(frozen=True)
class AuthenticatorAssertionResponse:
<<<<<<< HEAD
    """WebAuthn AuthenticatorAssertionResponse
=======
    """Authenticator response to a WebAuthn get (assertion) request.

    https://www.w3.org/TR/webauthn-3/#authenticatorassertionresponse
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)
    
    Args:
        client_data_json: <url-safe base64-encoded> client data JSON.
        authenticator_data: <url-safe base64-encoded> authenticator data.
        signature: <url-safe base64-encoded> signature.
        user_handle: <url-safe base64-encoded> user handle.
    """
    client_data_json: str
    authenticator_data: str
    signature: str
    user_handle: Optional[str]

@dataclass(frozen=True)
class GetResponse:
<<<<<<< HEAD
    """WebAuthn get response
=======
    """WebAuthn get (assertion) response.
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)
    
    Args:
        id: <url-safe base64-encoded> credential id (key handle).
        response: The authenticator assertion response.
        authenticator_attachment: <'cross-platform'|'platform'> The attachment status of the authenticator.
        client_extension_results: WebAuthn authentication extensions output results in a dictionary.
    """
    id: str
    response: AuthenticatorAssertionResponse
    authenticator_attachment: Optional[str]
<<<<<<< HEAD
    client_extension_results: Dict
=======
    client_extension_results: Optional[Dict]
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)

    @staticmethod
    def from_json(json_str: str):
        """Verify and construct GetResponse from a JSON string."""
        try:
            resp_json = json.loads(json_str)
        except ValueError:
            raise exceptions.MalformedError('Invalid Get JSON response')
        if resp_json['type'] != 'getResponse':
            raise exceptions.InvalidOperation('Invalid Get response type: {}'.format(resp_json['type']))
        pk_cred = resp_json['responseData']
        if pk_cred is None:
            if resp_json['error']:
                raise exceptions.ReauthFailError('WebAuthn.get failure: {}'.format(resp_json['error']))
            else:
                raise exceptions.InvalidValue('Get response is empty')
        if pk_cred['type'] != 'public-key':
            raise exceptions.InvalidValue('Invalid credential type: {}'.format(pk_cred['type']))
        assertion_json = pk_cred['response']
        assertion_resp = AuthenticatorAssertionResponse(
            client_data_json=assertion_json['clientDataJSON'],
            authenticator_data=assertion_json['authenticatorData'],
            signature=assertion_json['signature'],
            user_handle=assertion_json['userHandle'])
        return GetResponse(
            id=pk_cred['id'],
            response=assertion_resp,
            authenticator_attachment=pk_cred['authenticatorAttachment'],
            client_extension_results=pk_cred['clientExtensionResults'])

class WebAuthnHandler(abc.ABC):
    @abc.abstractmethod
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> 6c444f5 (feat: Integrate webauthn handler.)
    def is_available() -> bool:
        raise NotImplementedError("is_available method must be implemented")

    @abc.abstractmethod
<<<<<<< HEAD
    def get(get_request: GetRequest) -> GetResponse:
        """WebAuthn get"""
=======
=======
>>>>>>> 6c444f5 (feat: Integrate webauthn handler.)
    def get(get_request: GetRequest) -> GetResponse:
        """WebAuthn get (assertion)"""
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)
        raise NotImplementedError("get method must be implemented")
    
class PluginHandler(WebAuthnHandler):
    """Offloads WebAuthn get reqeust to a pluggable command-line tool.

    Offloads WebAuthn get to a plugin which takes the form of a
    command-line tool. The command-line tool is configurable via the
    PluginHandler._ENV_VAR environment variable.

    The WebAuthn plugin should implement the following interface:

    Communication occurs over stdin/stdout, and messages are both sent and
    received in the form:

    [4 bytes - payload size (little-endian)][variable bytes - json payload]
    The struct definition of the request and response JSON can be found in
    webauthn_plugin_message.d.ts
    """
<<<<<<< HEAD
    _ENV_VAR = 'GCLOUD_WEBAUTHN_PLUGIN'

    def is_available(self) -> bool:
        return os.environ.get(PluginHandler._ENV_VAR) is not None
=======
    _ENV_VAR = 'GOOGLE_AUTH_WEBAUTHN_PLUGIN'
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)

    def is_available(self) -> bool:
        return os.environ.get(PluginHandler._ENV_VAR) is not None

    def get(self, get_request: GetRequest) -> GetResponse:
        request_json = get_request.to_json()
        cmd = self._find_plugin()
        response_json = self._call_plugin(cmd, request_json)
        return GetResponse.from_json(request_json)

    def _call_plugin(self, cmd: str, input_json: str) -> str:
        # Calculate length of input
        input_length = len(input_json)
        length_bytes_le = struct.pack('<I', input_length)
        request = length_bytes_le + input_json.encode()

        # Call plugin
        process_result = subprocess.run([cmd],
                                        input=request,
                                        capture_output=True,
                                        check=True)
        
        # Check length of response
        response_len_le = process_result.stdout[:4]
        response_len = struct.unpack('<I', response_len_le)[0]
        response = process_result.stdout[4:]
        if response_len != len(response):
            raise exceptions.MalformedError(
                'Plugin response length {} does not match data {}'
                .format(response_len, len(response)))
        return response.decode()
    
    def _find_plugin(self) -> str:
        plugin_cmd = os.environ.get(PluginHandler._ENV_VAR)
        if plugin_cmd is None:
            raise exceptions.InvalidResource('{} env var is not set'
                                             .format(PluginHandler._ENV_VAR))
        return plugin_cmd
