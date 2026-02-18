<template>
  <header class="owf-header d-flex align-items-center px-4 py-2">
    <a href="https://openwallet.foundation">
      <img
        src="~/assets/images/OpenWallet_Foundation_Logo_Color.svg"
        alt="OpenWallet Foundation Logo"
        height="56"
      />
    </a>
    <h1 class="fw-bold mb-0 ms-3">VC-AuthN OIDC Demo</h1>
    <div class="ms-auto">
      <button
        v-if="!loggedIn"
        class="btn btn-primary btn-sm"
        @click="login('keycloak')"
      >
        Login
      </button>
      <button
        v-else
        class="btn btn-outline-secondary btn-sm"
        @click="logout('keycloak')"
      >
        Logout
      </button>
    </div>
  </header>
</template>

<script setup>
const { loggedIn, login, logout } = useOidcAuth()
</script>
