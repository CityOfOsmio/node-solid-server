'use strict'

const webidTls = require('webid')('tls')
const forge = require('node-forge')
const utils = require('../utils')

/**
 * Models a WebID-TLS crypto certificate, as generated at signup from a browser's
 * `<keygen>` element.
 *
 * @class WebIdTlsCertificate
 */
class WebIdTlsCertificate {
  /**
   * @param [options={}] {Object}
   * @param [options.spkac] {Buffer<string>}
   * @param [options.date] {Date}
   * @param [options.webId] {string}
   * @param [options.commonName] {string} Certificate name
   * @param [options.issuerName] {string}
   */
  constructor (options = {}) {
    this.spkac = options.spkac
    this.date = options.date || new Date()
    this.webId = options.webId
    this.commonName = options.commonName
    this.issuer = { commonName: options.issuerName }

    this.certificate = null  // gets initialized in `generateCertificate()`
  }

  /**
   * Factory method, used to construct a certificate instance from a browser-
   * based signup.
   *
   * @param spkac {string} Signed Public Key and Challenge from a browser's
   *   `<keygen>` element.
   * @param userAccount {UserAccount}
   * @param host {SolidHost}
   *
   * @throws {TypeError} If no `spkac` param provided (http 400)
   *
   * @return {WebIdTlsCertificate}
   */
  static fromSpkacPost (spkac, userAccount, host) {
    if (!spkac) {
      let error = new TypeError('Missing spkac parameter')
      error.status = 400
      throw error
    }

    let date = new Date()
    let commonName = `${userAccount.displayName} [on ${host.serverUri}, created ${date}]`

    let options = {
      spkac: WebIdTlsCertificate.prepPublicKey(spkac),
      webId: userAccount.webId,
      date,
      commonName,
      issuerName: host.serverUri
    }

    return new WebIdTlsCertificate(options)
  }

  static fromMtls (mtls_cert, userAccount) {

    let options = {
      webId: userAccount.webId,
      date: new Date(mtls_cert.valid_from),
      commonName: mtls_cert.subject.CN,
      issuerName: mtls_cert.issuer.CN
    }

//    var webid_cert = new WebIdTlsCertificate(options)
//    var pki_cert = pki.createCertificate()
//    pki_cert.serialNumber = mtls_cert.serialNumber
//    pki_cert.publicKey =
//
//    webid_cert.certificate =

    /**
     *

     var cert = pki.createCertificate()
     cert.serialNumber = (Date.now()).toString(16)

     // Get fields from SPKAC to populate new cert
     var publicKey = certificate.exportPublicKey(options.spkac).toString()
     cert.publicKey = pki.publicKeyFromPem(publicKey)

     // Validity of 10 years
     cert.validity.notBefore = new Date()
     cert.validity.notAfter = new Date()
     cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + options.duration)

     // `.` is default with the OpenSSL command line tool
     var commonName = options.commonName || url.parse(options.agent).hostname
     var attrsSubject = [{
    name: 'commonName',
    value: commonName
  }, {
    name: 'organizationName',
    value: options.organizationName || 'WebID'
  }]

     var attrsIssuer = [{
    name: 'commonName',
    value: commonName
  }, {
    name: 'organizationName',
    value: options.organizationName || 'WebID'
  }]

     if (options.issuer) {
    if (options.issuer.commonName) {
      attrsIssuer[0].value = options.issuer.commonName
    }
    if (options.issuer.organizationName) {
      attrsIssuer[1].value = options.issuer.organizationName
    }
  }

     // Set same fields for certificate and issuer
     cert.setSubject(attrsSubject)
     cert.setIssuer(attrsIssuer)
     */

  }

  /**
   * Formats a `<keygen>`-generated public key and converts it into a Buffer,
   * to use in TLS certificate generation.
   *
   * @param spkac {string} Signed Public Key and Challenge from a browser's
   *   `<keygen>` element.
   *
   * @return {Buffer<string>|null} UTF-8 string buffer of the public key, if one
   *   was passed in.
   */
  static prepPublicKey (spkac) {
    if (!spkac) { return null }

    spkac = utils.stripLineEndings(spkac)
    spkac = new Buffer(spkac, 'utf-8')
    return spkac
  }

  /**
   * Generates an X509Certificate from the passed-in `spkac` value.
   *
   * @throws {Error} See `webid` module's `generate()` function.
   *
   * @return {Promise<WebIdTlsCertificate>} Resolves to self (chainable), with
   *   the `.certificate` property initialized.
   */
  generateCertificate () {
    let certOptions = {
      spkac: this.spkac,
      agent: this.webId,
      commonName: this.commonName,
      issuer: this.issuer
    }

    return new Promise((resolve, reject) => {
      webidTls.generate(certOptions, (err, certificate) => {
        if (err) {
          reject(err)
        } else {
          this.certificate = certificate
          resolve(this)
        }
      })
    })
  }

  /**
   * Returns the URI (with hash fragment) for this certificate's public key,
   * to be used as a subject of RDF triples in a user's WebID Profile.
   *
   * @throws {TypeError} HTTP 400 error if no `webId` has been set.
   *
   * @return {string}
   */
  get keyUri () {
    if (!this.webId) {
      let error = new TypeError('Cannot construct key URI, WebID is missing')
      error.status = 400
      throw error
    }

    let profileUri = this.webId.split('#')[0]
    return profileUri + '#key-' + this.date.getTime()
  }

  /**
   * Returns the public key exponent (for adding to a user's WebID Profile)
   *
   * @throws {TypeError} HTTP 400 error if no certificate has been generated.
   *
   * @return {string}
   */
  get exponent () {
    if (!this.certificate) {
      let error = new TypeError('Cannot return exponent, certificate has not been generated')
      error.status = 400
      throw error
    }

    return this.certificate.publicKey.e.toString()
  }

  /**
   * Returns the public key modulus (for adding to a user's WebID Profile)
   *
   * @throws {TypeError} HTTP 400 error if no certificate has been generated.
   *
   * @return {string}
   */
  get modulus () {
    if (!this.certificate) {
      let error = new TypeError('Cannot return modulus, certificate has not been generated')
      error.status = 400
      throw error
    }

    return this.certificate.publicKey.n.toString(16).toUpperCase()
  }

  /**
   * Converts the generated cert to DER format and returns it.
   *
   * @return {X509Certificate|null} In DER format
   */
  toDER () {
    if (!this.certificate) {
      return null
    }

    let certificateAsn = forge.pki.certificateToAsn1(this.certificate)
    // Convert to DER
    let certificateDer = forge.asn1.toDer(certificateAsn).getBytes()
    // new Buffer(der, 'binary')
    return certificateDer
  }
}

module.exports = WebIdTlsCertificate
