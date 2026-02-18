<template>
  <div class="container py-5 text-center">
    <div class="card mx-auto" style="max-width: 500px">
      <div class="card-body py-5">
        <img
          src="~/assets/images/OpenWallet_Foundation_Logo_Color.svg"
          alt="OpenWallet Foundation"
          height="80"
          class="mb-4"
        />
        <h2 class="card-title mb-3">ACA-Py VC-AuthN OIDC Demo</h2>
        <p class="card-text text-muted mb-4">
          Demonstrates OpenID Connect authentication with Keycloak
          using Verifiable Credentials.
        </p>
        <button class="btn btn-primary btn-lg" @click="login('keycloak')">
          Login with Keycloak
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
definePageMeta({ oidcAuth: { enabled: false } })

const { loggedIn, login } = useOidcAuth()

// Redirect to dashboard if already logged in
if (loggedIn.value) {
  navigateTo('/dashboard')
}
</script>
