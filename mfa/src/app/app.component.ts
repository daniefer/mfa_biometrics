import { Component } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';

const DEFAULT_TIMEOUT = 60000;

interface LoginResult {
  success: boolean;
  token: string;
  id: string;
  name: string;
  email: string;
}

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent {
  title = 'mfa';
  signin: any = null;
  register: any = null;
  loginResult: LoginResult = null;
  signInResult: LoginResult = null;

  constructor(private http: HttpClient) {

  }

  async login() {
    this.loginResult = await this.http.post<LoginResult>("http://localhost:5000/api/login", { username: "dan", password: "P@ssw0rd" }).toPromise();
  }

  async signInClick() {
    try {
      const challenge = await this.http.get<{ token: string, supportedAlg: number[] }>("http://localhost:5000/api/login/challenge").toPromise()
      const cred = await navigator.credentials.get({
        publicKey: {
          userVerification: "required",
          timeout: DEFAULT_TIMEOUT,
          challenge: this.stringToArrayBuffer(encodeURIComponent(challenge.token)),
          allowCredentials: this.mapCredentialDescriptors(),
          extensions: this.getExtensions(),
          rpId: window.location.hostname
        },
      }) as PublicKeyCredential;
      this.signin = this.mapPublicKeyCredential(cred);
      this.signInResult = await this.http.post<LoginResult>("http://localhost:5000/api/login/authenticate", this.signin).toPromise();
    }
    catch (err) {
      this.signin = this.mapError(err);
    }
    console.table(this.signin);
  }

  async registerClick() {
    try {
      const challenge = await this.http.get<{ token: string, supportedAlg: number[] }>("http://localhost:5000/api/login/challenge").toPromise()
      const cred = await navigator.credentials.create({
        publicKey: this.getCreatePublicKey(
          {
            id: this.loginResult.id,
            email: this.loginResult.email,
            name: this.loginResult.name
          },
          // [-7, -257],
          // [-7, -257, -259],
          challenge.supportedAlg,
          challenge.token
        ),
      }) as PublicKeyCredential;
      this.register = this.mapPublicKeyCredential(cred);
      await this.http.post("http://localhost:5000/api/login/register/authentication", this.register, {
        headers: {
          Authorization: "Bearer " + this.loginResult.token
        }
      }).toPromise();
      this.storeValidCredentialsId(this.register.id)
    }
    catch (err) {
      this.register = this.mapError(err);
    }
    console.table(this.register);
  }

  storeValidCredentialsId(id: string) {
    const knownIdsJson = window.localStorage.getItem("knownIds") || "[]";
    const knownIds = JSON.parse(knownIdsJson);
    knownIds.push(id);
    window.localStorage.setItem("knownIds", JSON.stringify(knownIds));
  }

  getCreatePublicKey(user: { email: string, name: string, id: string }, algorithms: number[], challenge: string): PublicKeyCredentialCreationOptions {
    return {
      rp: {
        id: window.location.hostname,
        name: "my example dot com",
        icon: "https://icons.iconarchive.com/icons/thalita-torres/office/32/office-school-rulers-icon.png"
      },
      user: {
        id: this.stringToArrayBuffer(user.id),
        name: user.email,
        displayName: user.name,
        icon: "https://gravatar.com/avatar/jdoe.png"
      },
      pubKeyCredParams: algorithms.map(alg => ({ type: "public-key", alg })),
      challenge: this.stringToArrayBuffer(encodeURIComponent(challenge)),
      authenticatorSelection: {
        //Select authenticators that support username-less flows
        requireResidentKey: true,
        //Select authenticators that have a second factor (e.g. PIN, Bio)
        userVerification: "required",
        //Selects between bound or detachable authenticators
        authenticatorAttachment: "cross-platform",
      },
      attestation: "none",
      excludeCredentials: undefined, // this.mapCredentialDescriptors(),
      timeout: DEFAULT_TIMEOUT,
      extensions: this.getExtensions(),
    };
  }

  getExtensions(): AuthenticationExtensionsClientInputs {
    return undefined;
    // return {
    //   appid: "my app", // legacy extension
    // }
  }

  mapCredentialDescriptors(): PublicKeyCredentialDescriptor[] {
    const knownIdsJson = window.localStorage.getItem("knownIds") || "[]";
    const knownIds = JSON.parse(knownIdsJson);
    return knownIds.map(id => ({
      id: this.base64decode(id),
      type: "public-key",
      transports: ["internal", "ble", "nfc", "usb"], // ("ble" | "internal" | "nfc" | "usb")[]
    }));
  }

  mapError(err: any) {
    return {
      message: err.message,
      name: err.name
    };
  }

  mapPublicKeyCredential(cred: PublicKeyCredential) {
    const ext = this.tryGetExtensions(cred);
    const clientData = JSON.parse(this.arrayBufferToString(cred.response.clientDataJSON) || "null");
    const assertion = cred.response as AuthenticatorAssertionResponse;
    const attestation = cred.response as AuthenticatorAttestationResponse;

    return {
      jsType: Object.getPrototypeOf(cred).name,
      id: this.base64encode(cred.rawId),
      type: cred.type,
      extensions: {
        appId: ext.appid,
        authnSel: ext.authnSel,
        exts: (ext.exts || []).map(x => x),
        loc: { ...(ext.loc || {}) },
        txAuthSimple: ext.txAuthSimple,
        txAuthGeneric: this.base64encode(ext.txAuthGeneric),
        uvi: this.base64encode(ext.uvi),
        uvm: ext.uvm,
      },
      clientData: {
        ...clientData,
        challenge: atob(clientData.challenge)
      },
      clientDataJSON: this.arrayBufferToString(cred.response.clientDataJSON),

      signature: this.base64encode(assertion.signature),
      userHandle: this.base64encode(assertion.userHandle),
      base64CborAssertion: this.base64encode(assertion.authenticatorData),

      base64CborAttestation: this.base64encode(attestation.attestationObject),
    };
  }

  tryGetExtensions(cred: PublicKeyCredential): AuthenticationExtensionsClientOutputs {
    try {
      return cred.getClientExtensionResults();
    } catch (error) {
      return {}
    }
  }

  base64encode(buffer: ArrayBuffer): string {
    if (!buffer || (<any>buffer as Array<any>).length == 0)
      return undefined;

    return btoa(this.arrayBufferToString(buffer));
  }

  base64decode(input: string): ArrayBuffer {
    return this.stringToArrayBuffer(atob(input));
  }

  arrayBufferToString(buffer: ArrayBuffer): string {
    return String.fromCharCode.apply(null, new Uint8Array(buffer));
  }

  stringToArrayBuffer(value: string): ArrayBuffer {
    return Uint8Array.from(value, c => c.charCodeAt(0)).buffer
  }
}
