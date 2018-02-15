'use strict'

module.exports = {
  oidc: require('./webid-oidc'),
  tls: require('./webid-tls'),
  mtls: require('./mtls'),
  forceUser: require('./force-user.js')
}
