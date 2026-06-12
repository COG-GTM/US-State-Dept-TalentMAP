const express = require('express');
const bodyParser = require('body-parser');
const bunyan = require('bunyan');
const helmet = require('helmet');
const path = require('path');
const routesArray = require('./routes.js');
const { metadata, login } = require('./saml2-config');

// define full path to static build
const STATIC_PATH = process.env.STATIC_PATH || path.join(__dirname, '../build');

// Are we using a mock SAML for demo purposes?
// If so, the env var USE_MOCK_SAML should be 1.
const USE_MOCK_SAML = process.env.USE_MOCK_SAML === '1';

// define the API root url
const API_ROOT = process.env.API_ROOT || 'http://localhost:8000';

// define the prefix for the application
const PUBLIC_URL = process.env.PUBLIC_URL || '/talentmap/';

/* eslint-disable no-unused-vars */
// Define the SAML login redirect
let SAML_LOGIN = `${API_ROOT}/saml2/acs/`;
if (USE_MOCK_SAML) {
  SAML_LOGIN = `${PUBLIC_URL}login.html`;
}
/* eslint-enable no-unused-vars */

// Define the SAML logout redirect
let SAML_LOGOUT = `${API_ROOT}/saml2/logout/`;
if (USE_MOCK_SAML) {
  SAML_LOGOUT = `${PUBLIC_URL}login.html`;
}

// Routes from React, with wildcard added to the end if the route is not exact
const ROUTES = routesArray.map(route => `${PUBLIC_URL}${route.path}${route.exact ? '' : '*'}`.replace('//', '/'));

// define the OBC root url
// example: https://www.obcurl.gov
const OBC_URL = process.env.OBC_URL;

// path to external about page
const ABOUT_PAGE = process.env.ABOUT_PAGE || 'https://github.com/18F/State-TalentMAP';

// application port
const port = process.env.PORT || 3000;

// set up logger
const logger = bunyan.createLogger({ name: 'TalentMAP' });

// headers that must never be written to logs
const SENSITIVE_HEADERS = ['authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key'];

// return a copy of the headers with sensitive values redacted
const sanitizeHeaders = (headers) => {
  const sanitized = Object.assign({}, headers);
  SENSITIVE_HEADERS.forEach((header) => {
    if (sanitized[header] !== undefined) {
      sanitized[header] = '[REDACTED]';
    }
  });
  return sanitized;
};

// only allow alphanumeric ids (with dashes/underscores) in redirect paths
const isValidRedirectId = id => /^[A-Za-z0-9_-]+$/.test(id);

// read a single cookie value from the raw Cookie header
const getCookie = (request, name) => {
  const cookieHeader = request.headers.cookie || '';
  const match = cookieHeader.split(';')
    .map(part => part.trim())
    .find(part => part.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
};

// logging middleware
const loggingMiddleware = (request, response, next) => {
  // object to log
  const log = {
    method: request.method,
    headers: sanitizeHeaders(request.headers),
    url: request.url,
    query: request.query,
  };

  response.on('error', () => {
    logger.error(log);
  });

  response.on('finish', () => {
    logger.info(log);
  });

  next();
};

const app = express();

// body parser
app.use(bodyParser.urlencoded({ extended: false }));

// remove 'X-Powered-By' header
app.disable('x-powered-by');

// middleware for HTTP headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      fontSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", API_ROOT],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  referrerPolicy: { policy: 'no-referrer' },
}));

// disable caching of dynamic responses (replaces removed helmet.noCache())
app.use((request, response, next) => {
  response.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  response.set('Pragma', 'no-cache');
  response.set('Expires', '0');
  next();
});

// restrictive CORS: only allow the configured origin (same-origin by default)
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN;
app.use((request, response, next) => {
  if (ALLOWED_ORIGIN && request.headers.origin === ALLOWED_ORIGIN) {
    response.set('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
    response.set('Vary', 'Origin');
  }
  next();
});

// middleware for static assets
app.use(PUBLIC_URL, express.static(STATIC_PATH));

app.use(bodyParser.urlencoded({
  extended: true,
}));

// middleware for logging
app.use(loggingMiddleware);

// saml2 acs
app.post(PUBLIC_URL, (request, response) => {
  response.redirect(307, `${API_ROOT}/saml2/acs/`);
});

// saml2 login
app.get(`${PUBLIC_URL}login`, (request, response) => {
  // create handler
  // eslint-disable-next-line no-unused-vars
  const loginHandler = (err, loginUrl, requestId) => {
    if (err) {
      response.sendStatus(500);
    } else {
      response.redirect(loginUrl);
    }
  };

  login(loginHandler);
});


// logout: redirect based on auth mode (SAML vs mock/basic)
app.get(`${PUBLIC_URL}logout`, (request, response) => {
  response.clearCookie('tmApiToken', { path: PUBLIC_URL });
  response.redirect(SAML_LOGOUT);
});

// token validation: accept the API token in the request body, store it in an
// httpOnly cookie, and redirect to the app. This keeps the token out of URLs.
app.post(`${PUBLIC_URL}tokenValidation`, (request, response) => {
  // reject cross-origin POSTs so a third-party page cannot fixate a token cookie
  const origin = request.headers.origin;
  if (origin && origin !== `${request.protocol}://${request.headers.host}`) {
    response.sendStatus(403);
    return;
  }
  const token = request.body && request.body.token;
  if (!token || !/^[A-Za-z0-9._-]+$/.test(token)) {
    response.sendStatus(400);
    return;
  }
  response.cookie('tmApiToken', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: PUBLIC_URL,
  });
  response.redirect(`${PUBLIC_URL}tokenValidation`);
});

// expose the token from the httpOnly cookie to the same-origin SPA
app.get(`${PUBLIC_URL}tokenValidation/token`, (request, response) => {
  const token = getCookie(request, 'tmApiToken');
  if (!token) {
    response.sendStatus(404);
    return;
  }
  response.json({ token });
});

// saml2 metadata
app.get(`${PUBLIC_URL}metadata`, (request, response) => {
  response.type('application/xml');
  response.send(metadata);
});

// OBC redirect - post data detail
// endpoint for post-specific data points
app.get(`${PUBLIC_URL}obc/post/data/:id`, (request, response) => {
  // validate the id before passing it to the redirect
  const id = request.params.id;
  if (!isValidRedirectId(id)) {
    response.sendStatus(400);
    return;
  }
  response.redirect(`${OBC_URL}/post/postdatadetails/${encodeURIComponent(id)}`);
});

// OBC redirect - posts
// endpoint for post, ie landing page
app.get(`${PUBLIC_URL}obc/post/:id`, (request, response) => {
  // validate the id before passing it to the redirect
  const id = request.params.id;
  if (!isValidRedirectId(id)) {
    response.sendStatus(400);
    return;
  }
  response.redirect(`${OBC_URL}/post/detail/${encodeURIComponent(id)}`);
});

// OBC redirect - countries
// endpoint for country, ie landing page
app.get(`${PUBLIC_URL}obc/country/:id`, (request, response) => {
  // validate the id before passing it to the redirect
  const id = request.params.id;
  if (!isValidRedirectId(id)) {
    response.sendStatus(400);
    return;
  }
  response.redirect(`${OBC_URL}/country/detail/${encodeURIComponent(id)}`);
});

app.get(`${PUBLIC_URL}about/more`, (request, response) => {
  response.redirect(`${ABOUT_PAGE}`);
});

app.get(ROUTES, (request, response) => {
  response.sendFile(path.resolve(STATIC_PATH, 'index.html'));
});

// this is our wildcard, 404 route
app.get('*', (request, response) => {
  response.sendStatus(404).end();
});

const server = app.listen(port);

// export the the app and server separately
module.exports = { app, server };
