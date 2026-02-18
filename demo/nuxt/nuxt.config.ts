export default defineNuxtConfig({
  future: { compatibilityVersion: 4 },

  modules: ['nuxt-oidc-auth'],

  imports: {
    autoImport: true
  },

  css: ['bootstrap/dist/css/bootstrap.min.css', '~/assets/css/main.css'],

  runtimeConfig: {
    public: {
      presReqConfId: '',
    },
  },

  oidc: {
    providers: {
      keycloak: {
        baseUrl: '',
        clientId: '',
        clientSecret: '',
        redirectUri: '',
        exposeAccessToken: true,
        logoutRedirectUri: process.env.NUXT_OIDC_PROVIDERS_KEYCLOAK_LOGOUT_REDIRECT_URI || 'http://localhost:8080',
        additionalAuthParameters: {
          pres_req_conf_id: process.env.NUXT_PUBLIC_PRES_REQ_CONF_ID || '',
        },
      },
    },
    middleware: {
      globalMiddlewareEnabled: true,
    },
  },

  telemetry: false,
  devtools: { enabled: false },
})
