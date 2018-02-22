'use strict'

/**
 * Mutual TLS API handler
 */
const express = require('express')
const { LoginRequest } = require('../../requests/login-request')

var debug = require('../../debug').authentication
var x509 // optional dependency, load lazily
var base32 = require('base32-crockford-browser')

const CERTIFICATE_MATCHER = /^-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]+\n)+-----END CERTIFICATE-----$/m

function initialize (app, argv) {
  app.use('/', middleware(app ,argv))
  app.use('/', handler)
  if (argv.certificateHeader) {
    app.locals.certificateHeader = argv.certificateHeader.toLowerCase()
  }
  if (argv.caDomain) {
    app.locals.caDomain = argv.caDomain
  }
}

function middleware (req, res, next) {
  const router = express.Router('/')

  router.get('/login', LoginRequest.loginMtls)
  /*router.post('/login/tls', LoginRequest.loginTls)*/

  return router
}

function handler (req, res, next) {
  // User already logged in? skip
  if (req.session.userId) {
    debug('User: ' + req.session.userId)
    res.set('User', req.session.userId)
    return next()
  }

  // No certificate? skip
  const certificate = getCertificateViaTLS(req) || getCertificateViaHeader(req)
  if (!certificate) {
    setEmptySession(req)
    return next()
  }

  // Derive WebID
  try {
    // replace this with something local
    let accountName = deriveWebId(certificate, req.app.locals.caDomain).split('//')[1].split('/')[0]
    // TODO: confirm what this does in OIDC mode: is the userID on the session the *local* account, or the external WebId?
    req.session.userId = req.app.locals.accountManager.accountWebIdFor(accountName)
    res.set('User', req.session.userId)
    debug("mtls session userId: ["+req.session.userId+"]")

    return next()
  } catch (e) {
    debug('Error deriving WebID from certificate', e)
    setEmptySession(req)
    return next()
  }

}

// Tries to obtain a client certificate retrieved through the TLS handshake
function getCertificateViaTLS (req) {
  const certificate = req.connection.getPeerCertificate &&
    req.connection.getPeerCertificate()
  if (certificate && Object.keys(certificate).length > 0) {
    return certificate
  }
  debug('No peer certificate received during TLS handshake.')
}

// Tries to obtain a client certificate retrieved through an HTTP header
function getCertificateViaHeader (req) {
  // Only allow header-based certificates if explicitly enabled
  const headerName = req.app.locals.certificateHeader
  if (!headerName) return

  // Try to retrieve the certificate from the header
  const header = req.headers[headerName]
  if (!header) {
    return debug(`No certificate received through the ${headerName} header.`)
  }
  // The certificate's newlines have been replaced by tabs
  // in order to fit in an HTTP header (NGINX does this automatically)
  const rawCertificate = header.replace(/\t/g, '\n')

  // Ensure the header contains a valid certificate
  // (x509 unsafely interprets it as a file path otherwise)
  if (!CERTIFICATE_MATCHER.test(rawCertificate)) {
    return debug(`Invalid value for the ${headerName} header.`)
  }

  // Parse and convert the certificate to the format the webid library expects
  if (!x509) x509 = require('x509')
  try {
    const { publicKey, extensions } = x509.parseCert(rawCertificate)
    return {
      modulus: publicKey.n,
      exponent: '0x' + parseInt(publicKey.e, 10).toString(16),
      subjectaltname: extensions && extensions.subjectAlternativeName
    }
  } catch (error) {
    debug(`Invalid certificate received through the ${headerName} header.`)
  }
}

function setEmptySession (req) {
  req.session.userId = ''
}

/**
 * Sets the `WWW-Authenticate` response header for 401 error responses.
 * Used by error-pages handler.
 *
 * @param req {IncomingRequest}
 * @param res {ServerResponse}
 */
function setAuthenticateHeader (req, res) {
  let locals = req.app.locals

  res.set('WWW-Authenticate', `WebID-TLS realm="${locals.host.serverUri}"`)
}

/**
 * Derives a WebID from "username" from the Serial Number of the certificate, encoded in Crockford's base32.
 *
 * @param certificate {X509Certificate}
 */
function deriveWebId(certificate, caDomain) {
  let username = deriveWebIdUsername(certificate)
  debug("deriveWebId: ["+username+"] / ["+caDomain+"]")
  return "https://" + username + caDomain + "/profile/card#me"
}

/**
 * Derives a WebID "username" from the Serial Number of the given certificate, and encoding it in Crockford's base32
 *
 * @type {{initialize: initialize, handler: handler, setAuthenticateHeader: setAuthenticateHeader, setEmptySession: setEmptySession, deriveWebId: deriveWebId}}
 */
function deriveWebIdUsername(certificate) {
  if (certificate.serialNumber) {
    return base32.encode(certificate.serialNumber)
  } else {
    throw new Error('No Serial Number on certificate')
  }
}

module.exports = {
  initialize,
  handler,
  setAuthenticateHeader,
  setEmptySession,
  deriveWebId
}
