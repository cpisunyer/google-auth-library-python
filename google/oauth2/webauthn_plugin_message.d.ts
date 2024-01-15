interface GetRequest {
  type: 'get';
  requestData: PublicKeyCredentialRequestOptions;
  origin: string;
}

// PublicKeyCredentialRequestOptionsJSON definition from w3c.
interface PublicKeyCredentialRequestOptions {
  rpid: string;
  timeout?: number; // unsigned long in milliseconds
  challenge: string; // base64 encoded bytes
  allowCredentials?: PublicKeyCredentialDescriptor[];
  userVerification?: 'required'|'preferred'|'discouraged';
  extensions?: AuthenticationExtensionsClientInputs;
}

interface PublicKeyCredentialDescriptor {
  type: 'public-key';
  id: string; // based64 encoded bytes of credential
  transports?: ('usb'|'nfc'|'ble'|'internal')[];
}

// dictionary like type
interface AuthenticationExtensionsClientInputs {
  appid?: string;
}

interface GetResponse {
  type: 'getResponse';
  responseData?: PublicKeyCredential;
  error?: string;
}

interface PublicKeyCredential {
  type: 'public-key';
  id: string; // based64 encoded of credential
  // rawId can be derived from id
  response: AuthenticatorAssertionResponse;
  authenticatorAttachment: 'cross-platform'|'platform'|null;
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
}

interface AuthenticatorAssertionResponse {
  clientDataJSON: string; // base64 encoded bytes of clientData JSON format
  authenticatorData: string; // base64 encoded bytes of authenticator data
  signature: string; // base64 encoded bytes
  userHandle: string|null; // base64 encoded bytes
}

// dictionary like type
interface AuthenticationExtensionsClientOutputs {
  appid?: boolean;
}
