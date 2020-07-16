# mfa_biometrics
Demo of Web Authentication API with .net core

Overview: https://auth0.com/blog/web-authentication-webauthn-overview-demo-tool/#:~:text=What%20is%20WebAuthn,-WebAuthn%2C%20otherwise%20known&text=In%20summary%2C%20Web%20Authentication%20is,based%20on%20public%20key%20cryptography.

Notes:
1. to run the hostname must either be running under localhost or https.
1. Not a valid way to authenticate if the user shares a login on the trusted device
1. Need to update `pubKeyCredParams` on register and sign in if you prefer usb key to windows hello

Stolen heavily from 
1. https://github.com/MicrosoftEdge/webauthnsample/blob/fbe28c87a34c8d82c60c7be77e8f816c171eba14/fido.js
1. https://docs.microsoft.com/en-us/microsoft-edge/dev-guide/windows-integration/web-authentication#authenticate-your-user
1. https://www.w3.org/TR/webauthn-2/#public-key-credential-source
1. https://www.iana.org/assignments/cose/cose.xhtml#algorithms
1. https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider.signdata?view=netcore-3.1

TODO: 
1. clean up parsing
1. verify rest of `AuthenticatorAssertionResponse.authenticatorData` on sign in
1. Add a database

