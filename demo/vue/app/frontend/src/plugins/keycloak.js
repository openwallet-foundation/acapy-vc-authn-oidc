// Sourced from https://github.com/fredicious/vue-keycloak-js
import Keycloak from 'keycloak-js';

let installed = false;

export default {
  install: function (Vue, params = {}) {
    if (installed) return;
    installed = true;

    const defaultParams = {
      config: window.__BASEURL__ ? `${window.__BASEURL__}/config` : '/config',
      init: { onLoad: 'login-required' }
    };
    const options = Object.assign({}, defaultParams, params);
    if (assertOptions(options).hasError) throw new Error(`Invalid options given: ${assertOptions(options).error}`);

    const watch = new Vue({
      data() {
        return {
          ready: false,
          authenticated: false,
          userName: null,
          fullName: null,
          token: null,
          tokenParsed: null,
          logoutFn: null,
          loginFn: null,
          login: null,
          createLoginUrl: null,
          createLogoutUrl: null,
          createRegisterUrl: null,
          register: null,
          accountManagement: null,
          createAccountUrl: null,
          loadUserProfile: null,
          loadUserInfo: null,
          subject: null,
          idToken: null,
          idTokenParsed: null,
          realmAccess: null,
          resourceAccess: null,
          refreshToken: null,
          refreshTokenParsed: null,
          timeSkew: null,
          responseMode: null,
          responseType: null,
          hasRealmRole: null,
          hasResourceRole: null,
          keycloak: null
        };
      }
    });
    Object.defineProperty(Vue.prototype, '$keycloak', {
      get() {
        return watch;
      }
    });
    getConfig(options.config)
      .then(config => {
        init(config, watch, options);
      })
      .catch(err => {
        console.log(err); // eslint-disable-line no-console
      });
  }
};

function init(config, watch, options) {
  const ctor = sanitizeConfig(config);
  const keycloak = new Keycloak(ctor);
  keycloakInstance = keycloak;

  watch.$once('ready', function (cb) {
    cb && cb();
  });

  keycloak.onReady = function (authenticated) {
    updateWatchVariables(authenticated);
    watch.ready = true;
    typeof options.onReady === 'function' && watch.$emit('ready', options.onReady.bind(this, keycloak));
  };
  keycloak.onAuthSuccess = function () {
    // Check token validity every 10 seconds (10 000 ms) and, if necessary, update the token.
    // Refresh token if it's valid for less then 60 seconds
    const updateTokenInterval = setInterval(() => keycloak.updateToken(60).catch(() => {
      keycloak.clearToken();
    }), 10000);
    watch.logoutFn = () => {
      clearInterval(updateTokenInterval);
      keycloak.logout(options.logout || { 'redirectUri': config['logoutRedirectUri'] });
    };
  };
  keycloak.onAuthRefreshSuccess = function () {
    updateWatchVariables(true);
  };
  keycloak.onAuthLogout = function () {
    updateWatchVariables(false);
  };
  keycloak.init(options.init)
    .catch(err => {
      typeof options.onInitError === 'function' && options.onInitError(err);
    });

  function updateWatchVariables(isAuthenticated = false) {
    watch.authenticated = isAuthenticated;
    watch.keycloak = keycloak;
    watch.loginFn = async () => await keycloak.login();
    watch.login = async () => await keycloak.login();
    watch.createLoginUrl = async (options) => await keycloak.createLoginUrl(options);
    watch.createLogoutUrl = async (options) => await keycloak.createLogoutUrl(options);
    watch.createRegisterUrl = async (options) => await keycloak.createRegisterUrl(options);
    watch.register = async () => await keycloak.register();
    if (isAuthenticated) {
      watch.accountManagement = async () => await keycloak.accountManagement();
      watch.createAccountUrl = async (options) => await keycloak.createAccountUrl(options);
      watch.hasRealmRole = (role) => keycloak.hasRealmRole(role);
      watch.hasResourceRole = (role, resource) => keycloak.hasResourceRole(role, resource);
      watch.loadUserProfile = async () => await keycloak.loadUserProfile();
      watch.loadUserInfo = async () => await keycloak.loadUserInfo();
      watch.token = keycloak.token;
      watch.subject = keycloak.subject;
      watch.idToken = keycloak.idToken;
      watch.idTokenParsed = keycloak.idTokenParsed;
      watch.realmAccess = keycloak.realmAccess;
      watch.resourceAccess = keycloak.resourceAccess;
      watch.refreshToken = keycloak.refreshToken;
      watch.refreshTokenParsed = keycloak.refreshTokenParsed;
      watch.timeSkew = keycloak.timeSkew;
      watch.responseMode = keycloak.responseMode;
      watch.responseType = keycloak.responseType;
      watch.tokenParsed = keycloak.tokenParsed;
      watch.userName = keycloak.tokenParsed['preferred_username'];
      watch.fullName = keycloak.tokenParsed['name'];
    }
  }
}

function assertOptions(options) {
  const { config, init, onReady, onInitError } = options;
  if (typeof config !== 'string' && !_isObject(config)) {
    return { hasError: true, error: `'config' option must be a string or an object. Found: '${config}'` };
  }
  if (!_isObject(init) || typeof init.onLoad !== 'string') {
    return { hasError: true, error: `'init' option must be an object with an 'onLoad' property. Found: '${init}'` };
  }
  if (onReady && typeof onReady !== 'function') {
    return { hasError: true, error: `'onReady' option must be a function. Found: '${onReady}'` };
  }
  if (onInitError && typeof onInitError !== 'function') {
    return { hasError: true, error: `'onInitError' option must be a function. Found: '${onInitError}'` };
  }
  return {
    hasError: false,
    error: null
  };
}

function _isObject(obj) {
  return obj !== null && typeof obj === 'object' && Object.prototype.toString.call(obj) !== '[object Array]';
}

function getConfig(config) {
  if (_isObject(config)) return Promise.resolve(config);
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', config);
    xhr.setRequestHeader('Accept', 'application/json');
    xhr.onreadystatechange = () => {
      if (xhr.readyState === 4) {
        if (xhr.status === 200) {
          resolve(JSON.parse(xhr.responseText));
        } else {
          reject(Error(xhr.statusText));
        }
      }
    };
    xhr.send();
  });
}

function sanitizeConfig(config) {
  const renameProp = (oldProp, newProp, { [oldProp]: old, ...others }) => {
    return {
      [newProp]: old,
      ...others
    };
  };
  return Object.keys(config).reduce(function (previous, key) {
    if (['authRealm', 'authUrl', 'authClientId'].includes(key)) {
      const cleaned = key.replace('auth', '');
      const newKey = cleaned.charAt(0).toLowerCase() + cleaned.slice(1);
      return renameProp(key, newKey, previous);
    }
    return previous;
  }, config);
}
