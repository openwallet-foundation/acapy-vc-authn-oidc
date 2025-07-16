import Vue from 'vue';

/**
 * @function hasRoles
 * Checks if all elements in `roles` array exists in `tokenRoles` array
 * @param {string[]} tokenRoles An array of roles that exist in the token
 * @param {string[]} roles An array of roles to check
 * @returns {boolean} True if all `roles` exist in `tokenRoles`; false otherwise
 */
function hasRoles(tokenRoles, roles = []) {
  return roles
    .map((r) => tokenRoles.some((t) => t === r))
    .every((x) => x === true);
}

export default {
  namespaced: true,
  state: {
    // In most cases, when this becomes populated, we end up doing a redirect flow,
    // so when we return to the app, it is fresh again and undefined
    redirectUri: undefined,
    presReqConfId: 'showcase-person', //TODO: load this via config response
  },
  getters: {
    authenticated: () => Vue.prototype.$keycloak.authenticated,
    createLoginUrl: () => (options) =>
      Vue.prototype.$keycloak.createLoginUrl(options),
    createLogoutUrl: () => (options) =>
      Vue.prototype.$keycloak.createLogoutUrl(options),
    email: () =>
      Vue.prototype.$keycloak.tokenParsed
        ? Vue.prototype.$keycloak.tokenParsed.email
        : '',
    fullName: () => Vue.prototype.$keycloak.fullName,
    hasResourceRoles: (_state, getters) => (resource, roles) => {
      if (!getters.authenticated) return false;
      if (!roles.length) return true; // No roles to check against

      if (getters.resourceAccess[resource]) {
        return hasRoles(getters.resourceAccess[resource].roles, roles);
      }
      return false; // There are roles to check, but nothing in token to check against
    },
    identityProvider: () =>
      Vue.prototype.$keycloak.tokenParsed.identity_provider,
    keycloakReady: () => Vue.prototype.$keycloak.ready,
    keycloakSubject: () => Vue.prototype.$keycloak.subject,
    moduleLoaded: () => !!Vue.prototype.$keycloak,
    presReqConfId: () => Vue.prototype.$config.keycloak.presReqConfId,
    realmAccess: () => Vue.prototype.$keycloak.tokenParsed.realm_access,
    redirectUri: (state) => state.redirectUri,
    resourceAccess: () => Vue.prototype.$keycloak.tokenParsed.resource_access,
    token: () => Vue.prototype.$keycloak.token,
    tokenParsed: () => Vue.prototype.$keycloak.tokenParsed,
    userName: () => Vue.prototype.$keycloak.userName,
  },
  mutations: {
    SET_REDIRECTURI(state, redirectUri) {
      state.redirectUri = redirectUri;
    },
  },
  actions: {
    login({ commit, getters }, idpHint = undefined) {
      if (getters.keycloakReady) {
        // Use existing redirect uri if available
        if (!getters.redirectUri)
          commit('SET_REDIRECTURI', location.toString());

        const options = {
          redirectUri: getters.redirectUri,
        };

        // Determine idpHint based on input
        if (idpHint && typeof idpHint === 'string') options.idpHint = idpHint;

        // Redirect to Keycloak
        window.location.replace(
          getters.createLoginUrl(options) +
            '&pres_req_conf_id=' +
            getters.presReqConfId
        );
      }
    },
    logout({ getters }) {
      if (getters.keycloakReady) {
        window.location.replace(
          getters.createLogoutUrl({
            redirectUri: `${location.origin}/${Vue.prototype.$config.basePath}`,
          })
        );
      }
    },
  },
};
