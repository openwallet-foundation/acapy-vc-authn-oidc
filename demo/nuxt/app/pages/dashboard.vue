<template>
  <div class="container py-4">
    <div class="alert alert-success d-flex align-items-center">
      <strong>You are logged in!</strong>
      <button
        class="btn btn-outline-danger btn-sm ms-auto"
        @click="logout('keycloak')"
      >
        Logout
      </button>
    </div>

    <!-- Claim validation -->
    <div v-if="!tokenClaims.pres_req_conf_id" class="alert alert-danger">
      <strong>Missing Required Claim:</strong> pres_req_conf_id is not present in the ID token.
      <br />
      Please verify the Identity Provider Mapper and Client Mapper configurations in Keycloak.
    </div>

    <div v-else-if="!tokenClaims.vc_presented_attributes" class="alert alert-danger">
      <strong>Missing Required Claim:</strong> vc_presented_attributes is not present in the ID token.
      <br />
      Please verify the Identity Provider Mapper and Client Mapper configurations in Keycloak.
    </div>

    <div v-else-if="presReqConfId && tokenClaims.pres_req_conf_id !== presReqConfId" class="alert alert-warning">
      <strong>INVALID LOGIN:</strong> pres_req_conf_id mismatch
      <br />
      Expected: <code>{{ presReqConfId }}</code>
      <br />
      Received: <code>{{ tokenClaims.pres_req_conf_id }}</code>
    </div>

    <div v-else class="alert alert-success">
      <strong>Login Valid</strong>
      <br />
      &#10003; pres_req_conf_id: {{ tokenClaims.pres_req_conf_id }}
      <br />
      &#10003; vc_presented_attributes: Present
    </div>

    <div class="card mb-3">
      <div
        class="card-header fw-semibold d-flex align-items-center"
        role="button"
        @click="showToken = !showToken"
      >
        View ID Token Claims
        <span class="ms-auto">{{ showToken ? '&#9660;' : '&#9654;' }}</span>
      </div>
      <div v-if="showToken" class="card-body">
        <pre class="token-decoded">{{ decodedToken }}</pre>
      </div>
    </div>

    <div class="card mb-3">
      <div
        class="card-header fw-semibold d-flex align-items-center"
        role="button"
        @click="showRawToken = !showRawToken"
      >
        View Encoded JWT
        <span class="ms-auto">{{ showRawToken ? '&#9660;' : '&#9654;' }}</span>
      </div>
      <div v-if="showRawToken" class="card-body">
        <code class="token-raw d-block">{{ rawToken }}</code>
      </div>
    </div>

    <button class="btn btn-primary" :disabled="secureApiLoading" @click="callSecureApi">
      {{ secureApiLoading ? 'Calling...' : 'Call Secured API Route' }}
    </button>

    <div v-if="secureApiResponse" class="card mt-3 border-success">
      <div class="card-header bg-success text-white fw-semibold d-flex align-items-center gap-2">
        &#10003; {{ secureApiResponse.message }}
      </div>
      <ul v-if="secureApiResponse.user" class="list-group list-group-flush">
        <li v-for="(value, key) in secureApiResponse.user" :key="key" class="list-group-item d-flex gap-3">
          <span class="text-muted text-nowrap">{{ key }}</span>
          <span class="ms-auto text-break text-end">{{ value }}</span>
        </li>
      </ul>
    </div>

    <div v-if="secureApiError" class="alert alert-danger mt-3">
      <strong>Secured Route Error:</strong> {{ secureApiError }}
    </div>

    <ul class="mt-4 text-muted small">
      <li>
        If a claim is missing, ensure it is being imported to the Keycloak user
        by the
        <a href="http://localhost:8880/auth/admin/master/console/#/realms/vc-authn/identity-provider-mappers/vc-authn/mappers">
          Identity Provider Mapper</a>.
      </li>
      <li>
        Ensure the claim is being added to the token by the
        <a href="http://localhost:8880/auth/admin/master/console/#/realms/vc-authn/clients/">
          Client Mappers</a>
        (click your client, then the "Mappers" tab).
      </li>
    </ul>
  </div>
</template>

<script setup>
definePageMeta({})

const { user, logout } = useOidcAuth()
const { public: { presReqConfId } } = useRuntimeConfig()

const secureApiResponse = ref(null)
const secureApiError = ref(null)
const secureApiLoading = ref(false)
const showToken = ref(false)
const showRawToken = ref(false)

const rawToken = computed(() => user.value?.accessToken || '')

const tokenClaims = computed(() => {
  if (!rawToken.value) return {}
  try {
    const payload = rawToken.value.split('.')[1]
    return JSON.parse(atob(payload))
  } catch {
    return {}
  }
})

const decodedToken = computed(() => {
  return Object.keys(tokenClaims.value).length
    ? JSON.stringify(tokenClaims.value, null, 2)
    : 'No token available'
})

async function callSecureApi() {
  secureApiLoading.value = true
  secureApiError.value = null
  try {
    secureApiResponse.value = await $fetch('/api/secure/profile')
  } catch (e) {
    secureApiError.value = e.data?.message || e.message || 'Request failed'
  } finally {
    secureApiLoading.value = false
  }
}
</script>
