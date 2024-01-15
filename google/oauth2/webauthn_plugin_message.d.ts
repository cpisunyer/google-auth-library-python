<<<<<<< HEAD
=======
// WebAuthn get request JSON to a plugin.
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)
interface GetRequest {
  type: 'get';
  requestData: PublicKeyCredentialRequestOptions;
  origin: string;
}

<<<<<<< HEAD
// PublicKeyCredentialRequestOptionsJSON definition from w3c.
=======
// Partial PublicKeyCredentialRequestOptionsJSON from
// https://www.w3.org/TR/webauthn-3/#sctn-parseRequestOptionsFromJSON
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)
interface PublicKeyCredentialRequestOptions {
  rpid: string;
  timeout?: number; // unsigned long in milliseconds
  challenge: string; // base64 encoded bytes
  allowCredentials?: PublicKeyCredentialDescriptor[];
  userVerification?: 'required'|'preferred'|'discouraged';
  extensions?: AuthenticationExtensionsClientInputs;
}

<<<<<<< HEAD
interface PublicKeyCredentialDescriptor {
  type: 'public-key';
  id: string; // based64 encoded bytes of credential
  transports?: ('usb'|'nfc'|'ble'|'internal')[];
}

// dictionary like type
=======
// PublicKeyCredentialDescriptorJSON from
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptorjson
interface PublicKeyCredentialDescriptor {
  type: 'public-key';
  id: string; // base64 encoded bytes of credential
  transports?: ('usb'|'nfc'|'ble'|'internal')[];
}

// Refer to https://www.w3.org/TR/webauthn-3/#sctn-extensions-inputs-outputs
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)
interface AuthenticationExtensionsClientInputs {
  appid?: string;
}

<<<<<<< HEAD
interface GetResponse {
  type: 'getResponse';
  responseData?: PublicKeyCredential;
  error?: string;
}

interface PublicKeyCredential {
  type: 'public-key';
  id: string; // based64 encoded of credential
=======
// WebAuthn get response JSON from a plugin.
interface GetResponse {
  type: 'getResponse';
  responseData?: AuthenticationResponse;
  error?: string;
}

// Partial AuthenticationResponseJSON from
// https://www.w3.org/TR/webauthn-3/#dictdef-authenticationresponsejson
interface AuthenticationResponse {
  type: 'public-key';
  id: string; // base64 encoded of credential
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)
  // rawId can be derived from id
  response: AuthenticatorAssertionResponse;
  authenticatorAttachment: 'cross-platform'|'platform'|null;
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
}

<<<<<<< HEAD
=======
// Partial AuthenticatorAssertionResponseJSON from
// https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorassertionresponsejson
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)
interface AuthenticatorAssertionResponse {
  clientDataJSON: string; // base64 encoded bytes of clientData JSON format
  authenticatorData: string; // base64 encoded bytes of authenticator data
  signature: string; // base64 encoded bytes
  userHandle: string|null; // base64 encoded bytes
}

<<<<<<< HEAD
// dictionary like type
=======
// Refer to https://www.w3.org/TR/webauthn-3/#sctn-extensions-inputs-outputs
>>>>>>> 365450c (feat: Add WebAuthn plugin component to handle WebAuthn get request)
interface AuthenticationExtensionsClientOutputs {
  appid?: boolean;
}
