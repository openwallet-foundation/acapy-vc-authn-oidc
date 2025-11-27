<template>
  <div v-if="keycloakReady">
    <v-btn v-if="authenticated" dark outlined @click="logout">
      <span>Logout</span>
    </v-btn>
    <v-btn v-else-if="hasLogin" dark outlined @click="login">
      <span>Login</span>
    </v-btn>
  </div>
</template>

<script>
import { mapGetters } from 'vuex';

export default {
  name: 'BaseAuthButton',
  computed: {
    ...mapGetters('auth', [
      'authenticated',
      'createLoginUrl',
      'createLogoutUrl',
      'keycloakReady',
      'presReqConfId',
    ]),
    hasLogin() {
      return this.$route && this.$route.meta && this.$route.meta.hasLogin;
    },
  },
  methods: {
    async login() {
      if (this.keycloakReady) {
        const loginUrl = await this.createLoginUrl();
        window.location.replace(
          loginUrl +
            '&pres_req_conf_id=' +
            this.presReqConfId +
            '&back_to_url=http://localhost:8080/',
        );
      }
    },
    async logout() {
      if (this.keycloakReady) {
        const logoutUrl = await this.createLogoutUrl({
          redirectUri: `${location.origin}/${this.$config.basePath}`,
        });
        window.location.replace(logoutUrl);
      }
    },
  },
};
</script>
