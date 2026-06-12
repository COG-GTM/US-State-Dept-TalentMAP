const saml2 = require('saml2-js');
const fs = require('fs');
const path = require('path');

// load constants from env vars
const ENTITY_ID = process.env.ENTITY_ID || 'http://localhost:3000/talentmap/';
const ASSERT_ENDPOINT = process.env.ASSERT_ENDPOINT || 'http://localhost:3000/talentmap/';

// load certs
const certFile = process.env.CERT_FILE || path.join(__dirname, '../certs', 'talentmap-dev.crt');
const keyFile = process.env.KEY_FILE || path.join(__dirname, '../certs', 'talentmap-dev.key');

// identity provider config
const SSO_LOGIN_URL = process.env.SSO_LOGIN_URL || 'http://localhost:5000/login';
const SSO_LOGOUT_URL = process.env.SSO_LOGOUT_URL || 'http://localhost:5000/logout';
const ssoCertFile = process.env.SSO_CERT_FILE || path.join(__dirname, '../certs', 'talentmap-dev.crt');

let privateKey = null;
let cert = null;
let ssoCert = null;

if (fs.existsSync(keyFile)) { privateKey = fs.readFileSync(keyFile); }
if (fs.existsSync(certFile)) { cert = fs.readFileSync(certFile); }
if (fs.existsSync(ssoCertFile)) { ssoCert = fs.readFileSync(ssoCertFile); }

// saml2-js requires valid certificates; only configure the providers when
// certs are present (e.g. mock SAML mode and tests run without them)
const hasCerts = Boolean(privateKey && cert && ssoCert);

let metadata = null;
let serviceProvider = null;
let identityProvider = null;

if (hasCerts) {
  // Create service provider with options
  serviceProvider = new saml2.ServiceProvider({
    entity_id: ENTITY_ID,
    private_key: privateKey,
    certificate: cert,
    assert_endpoint: ASSERT_ENDPOINT,
    force_authn: true,
  });

  identityProvider = new saml2.IdentityProvider({
    sso_login_url: SSO_LOGIN_URL,
    sso_logout_url: SSO_LOGOUT_URL,
    certificates: [ssoCert],
  });

  // Call metadata to get XML metatadata used in configuration.
  metadata = serviceProvider.create_metadata();
}

const login = (handler) => {
  if (!hasCerts) {
    handler(new Error('SAML certificates are not configured'));
    return;
  }
  serviceProvider.create_login_request_url(identityProvider, {}, handler);
};

const logout = (handler) => {
  if (!hasCerts) {
    handler(new Error('SAML certificates are not configured'));
    return;
  }
  serviceProvider.create_logout_request_url(identityProvider, {}, handler);
};

module.exports = { metadata, login, logout };
