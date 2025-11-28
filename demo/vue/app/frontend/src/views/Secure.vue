<template>
  <v-container>
    <BaseSecure>
      <h1 class="my-6 text-center">Secure</h1>
      <HelloCall />

      <v-alert
        v-if="!tokenParsed.pres_req_conf_id"
        type="error"
        class="my-4"
      >
        <strong>Missing Required Claim:</strong> pres_req_conf_id is not present in the ID token.
        <br />
        Please verify the Identity Provider Mapper and Client Mapper configurations in Keycloak.
      </v-alert>

      <v-alert
        v-else-if="!tokenParsed.vc_presented_attributes"
        type="error"
        class="my-4"
      >
        <strong>Missing Required Claim:</strong> vc_presented_attributes is not present in the ID token.
        <br />
        Please verify the Identity Provider Mapper and Client Mapper configurations in Keycloak.
      </v-alert>

      <v-alert
        v-else-if="tokenParsed.pres_req_conf_id != presReqConfId"
        type="warning"
        class="my-4"
      >
        <strong>INVALID LOGIN:</strong> pres_req_conf_id mismatch
        <br />
        Expected: <code>{{ presReqConfId }}</code>
        <br />
        Received: <code>{{ tokenParsed.pres_req_conf_id }}</code>
      </v-alert>

      <v-alert v-else type="success" class="my-4">
        <strong>Login Valid</strong>
        <br />
        ✓ pres_req_conf_id: {{ tokenParsed.pres_req_conf_id }}
        <br />
        ✓ vc_presented_attributes: Present
      </v-alert>

      <v-expansion-panels class="my-4">
        <v-expansion-panel>
          <v-expansion-panel-title>
            View ID Token Claims
          </v-expansion-panel-title>
          <v-expansion-panel-text>
            <pre>{{ JSON.stringify(tokenParsed, null, 2) }}</pre>
          </v-expansion-panel-text>
        </v-expansion-panel>
      </v-expansion-panels>

      <ul>
        <li>
          If something in the verification configuration is missing, ensure it
          is being imported to the Keycloak user by the Identity Provider Mapper
          here.
        </li>
        <li>
          <a
            href="http://localhost:8880/auth/admin/master/console/#/realms/vc-authn/identity-provider-mappers/vc-authn/mappers"
          >http://localhost:8880/auth/admin/master/console/#/realms/vc-authn/identity-provider-mappers/vc-authn/mappers
          </a>
        </li>
        <li>
          and ensure is being added to the token by the client mappers here
          (click the link, then the 'vue-fe' client, then the 'Mappers' tab).
        </li>
        <li>
          <a
            href="http://localhost:8880/auth/admin/master/console/#/realms/vc-authn/clients/"
          >http://localhost:8880/auth/admin/master/console/#/realms/vc-authn/clients/4f4d8312-bdd0-4539-8c51-f8de81cf5f41/mapper</a
          >
        </li>
      </ul>
    </BaseSecure>
  </v-container>
</template>

<script>
import HelloCall from '@/components/HelloCall';
import { mapGetters } from 'vuex';

export default {
  name: 'Secure',
  components: {
    HelloCall,
  },
  computed: {
    ...mapGetters('auth', ['tokenParsed', 'presReqConfId']),
  },
};
</script>
