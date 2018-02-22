'use strict'

const url = require('url')
const path = require('path')
const rdf = require('rdflib')
const ns = require('solid-namespace')(rdf)

const defaults = require('../../config/defaults')
const UserAccount = require('./user-account')
const AccountManager = require('./account-manager')
const AccountTemplate = require('./account-template')
const debug = require('./../debug').accounts
const API = require('../api')

const DEFAULT_PROFILE_CONTENT_TYPE = 'text/turtle'
const DEFAULT_ADMIN_USERNAME = 'admin'

/**
 * Manages account creation (determining whether accounts exist, creating
 * directory structures for new accounts, saving credentials).
 *
 * @class AccountManager
 */
class SimpleAccountManager extends AccountManager {
  /**
   * @constructor
   * @param [options={}] {Object}
   * @param [options.authMethod] {string} Primary authentication method (e.g. 'oidc')
   * @param [options.emailService] {EmailService}
   * @param [options.tokenService] {TokenService}
   * @param [options.host] {SolidHost}
   * @param [options.multiuser=false] {boolean} (argv.multiuser) Is the server running
   *   in multiuser mode (users can sign up for accounts) or single user
   *   (such as a personal website).
   * @param [options.store] {LDP}
   * @param [options.pathCard] {string}
   * @param [options.suffixURI] {string}
   * @param [options.accountTemplatePath] {string} Path to the account template
   *   directory (will be used as a template for default containers, etc, when
   *   creating new accounts).
   */
  constructor (options = {}) {
    super(options)
    this.caDomain = options.caDomain
    debug("Instantiating SimpleAccountManager - caDomain")
    debug(this.caDomain)
  }

  /**
   * Factory method for new account manager creation. Usage:
   *
   *   ```
   *   let options = { host, multiuser, store }
   *   let accontManager = AccountManager.from(options)
   *   ```
   *
   * @param [options={}] {Object} See the `constructor()` docstring.
   *
   * @return {AccountManager}
   */
  static from(options) {
    return new SimpleAccountManager(options)
  }

  /**
   * Tests whether an account already exists for a given username.
   * Usage:
   *
   *   ```
   *   accountManager.accountExists('alice')
   *     .then(exists => {
   *       console.log('answer: ', exists)
   *     })
   *   ```
   * @param accountName {string} Account username, e.g. 'alice'
   *
   * @return {Promise<boolean>}
   */
  accountExists (accountName) {
    let accountUri
    let rootAclPath

    try {
      accountUri = this.accountUriFor(accountName)
      accountUri = url.parse(accountUri).hostname

      rootAclPath = url.resolve('/', this.store.suffixAcl)
    } catch (err) {
      return Promise.reject(err)
    }

    return this.accountUriExists(accountUri, rootAclPath)
  }

  /**
   * Tests whether a given account URI (e.g. 'https://alice.example.com/')
   * already exists on the server.
   *
   * @param accountUri {string}
   * @param accountResource {string}
   *
   * @return {Promise<boolean>}
   */
  accountUriExists (accountUri, accountResource = '/') {
    return new Promise((resolve, reject) => {
      this.store.exists(accountUri, accountResource, (err, result) => {
        if (err && err.status === 404) {
          return resolve(false)
        }

        resolve(!!result)
      })
    })
  }

  /**
   * Constructs a directory path for a given account (used for account creation).
   * Usage:
   *
   *   ```
   *   // If solid-server was launched with '/accounts/' as the root directory
   *   // and serverUri: 'https://example.com'
   *
   *   accountManager.accountDirFor('alice')  // -> '/accounts/alice.example.com'
   *   ```
   *
   * @param accountName {string}
   *
   * @return {string}
   */
  accountDirFor (accountName) {
    let accountDir

    if (this.multiuser) {
      let uri = this.accountUriFor(accountName)
      let hostname = url.parse(uri).hostname
      accountDir = path.join(this.store.root, hostname)
    } else {
      // single user mode
      accountDir = this.store.root
    }
    return accountDir
  }

  /**
   * Composes an account URI for a given account name.
   * Usage (given a host with serverUri of 'https://example.com'):
   *
   *   ```
   *   // in multi user mode:
   *   acctMgr.accountUriFor('alice')
   *   // -> 'https://alice.example.com'
   *
   *   // in single user mode:
   *   acctMgr.accountUriFor()
   *   // -> 'https://example.com'
   *   ```
   *
   * @param [accountName] {string}
   *
   * @throws {Error} If `this.host` has not been initialized with serverUri,
   *   or if in multiuser mode and accountName is not provided.
   * @return {string}
   */
  accountUriFor (accountName) {
    let accountUri = this.multiuser
      ? this.host.accountUriFor(accountName)
      : this.host.serverUri  // single user mode

    return accountUri
  }
  
  /**
   * Creates and returns a `UserAccount` instance from submitted user data
   * (typically something like `req.body`, from a signup form).
   *
   * @param userData {Object} Options hashmap, like `req.body`.
   *   Either a `username` or a `webid` property is required.
   *
   * @param [userData.username] {string}
   * @param [uesrData.webid] {string}
   *
   * @param [userData.email] {string}
   * @param [userData.name] {string}
   *
   * @throws {Error} (via `accountWebIdFor()`) If in multiuser mode and no
   *   username passed
   *
   * @return {UserAccount}
   */
  userAccountFrom (userData) {
    debug("userAccountFrom:")
    debug(userData)
    var webId = API.authn["mtls"].deriveWebId(userData, this.caDomain)
    var username = webId.split('//')[1].split('/')[0]
    // TODO: clean up and verify these ar all being set appropriately?
    let userConfig = {
      username: username, // base32 SN + caDomain
      email: userData.subject.getField('CN').value,
      name: username.split('.')[0], // bare base32 SN
      externalWebId: webId, // Full WebId
      localAccountId: this.accountWebIdFor(username), // Local WebId
      webId: webId
    }

    if (userConfig.username) {
      if (userConfig.externalWebId && !userConfig.localAccountId) {
        // External Web ID exists, derive the local account id from username
        userConfig.localAccountId = this.accountWebIdFor(userConfig.username)
          .split('//')[1]  // drop the https://
      }
    } else {  // no username - derive it from web id
      if (userConfig.externalWebId) {
        userConfig.username = userConfig.externalWebId
      } else {
        userConfig.username = this.usernameFromWebId(userConfig.webId)
      }
    }

    return UserAccount.from(userConfig)
  }
}

module.exports = SimpleAccountManager
