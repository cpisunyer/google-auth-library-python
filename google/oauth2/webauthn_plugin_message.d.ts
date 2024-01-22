// WebAuthn get request JSON to a plugin.
interface GetRequest {
  type: 'get';
  requestData: PublicKeyCredentialRequestOptions;
  origin: string;
}

// Partial PublicKeyCredentialRequestOptionsJSON from
// https://www.w3.org/TR/webauthn-3/#sctn-parseRequestOptionsFromJSON
interface PublicKeyCredentialRequestOptions {
  rpid: string;
  timeout?: number; // unsigned long in milliseconds
  challenge: string; // base64 encoded bytes
  allowCredentials?: PublicKeyCredentialDescriptor[];
  userVerification?: 'required'|'preferred'|'discouraged';
  extensions?: AuthenticationExtensionsClientInputs;
}

// PublicKeyCredentialDescriptorJSON from
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptorjson
interface PublicKeyCredentialDescriptor {
  type: 'public-key';
  id: string; // base64 encoded bytes of credential
  transports?: ('usb'|'nfc'|'ble'|'internal')[];
}

// Refer to https://www.w3.org/TR/webauthn-3/#sctn-extensions-inputs-outputs
interface AuthenticationExtensionsClientInputs {
  appid?: string;
}

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
  // rawId can be derived from id
  response: AuthenticatorAssertionResponse;
  authenticatorAttachment: 'cross-platform'|'platform'|null;
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
}

// Partial AuthenticatorAssertionResponseJSON from
// https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorassertionresponsejson
interface AuthenticatorAssertionResponse {
  clientDataJSON: string; // base64 encoded bytes of clientData JSON format
  authenticatorData: string; // base64 encoded bytes of authenticator data
  signature: string; // base64 encoded bytes
  userHandle: string|null; // base64 encoded bytes
}

// Refer to https://www.w3.org/TR/webauthn-3/#sctn-extensions-inputs-outputs
interface AuthenticationExtensionsClientOutputs {
  appid?: boolean;
}