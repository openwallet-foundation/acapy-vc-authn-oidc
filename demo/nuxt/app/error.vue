<template>
  <div class="d-flex flex-column min-vh-100">
    <OWFHeader />
    <main class="flex-grow-1">
      <div class="container py-5 text-center">
        <div class="card mx-auto" style="max-width: 600px">
          <div class="card-body py-4">
            <h2 class="text-danger mb-3">Something went wrong</h2>
            <p class="text-muted mb-3">{{ error.message }}</p>
            <div v-if="isAuthError" class="alert alert-warning text-start">
              <strong>Is Keycloak running?</strong>
              <p class="mb-0 mt-1">
                This demo requires Keycloak to be available. Make sure it is
                started and accessible at the configured URL before logging in.
              </p>
            </div>
            <button class="btn btn-primary" @click="handleError">
              Back to Home
            </button>
          </div>
        </div>
      </div>
    </main>
    <OWFFooter />
  </div>
</template>

<script setup>
const props = defineProps({
  error: Object,
})

const isAuthError = computed(() => {
  const msg = (props.error?.message || '').toLowerCase()
  return (
    msg.includes('fetch') ||
    msg.includes('connect') ||
    msg.includes('oidc') ||
    msg.includes('auth') ||
    props.error?.statusCode === 502 ||
    props.error?.statusCode === 503
  )
})

function handleError() {
  clearError({ redirect: '/' })
}
</script>
