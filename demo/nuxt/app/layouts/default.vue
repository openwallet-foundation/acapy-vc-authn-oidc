<template>
  <div class="d-flex flex-column min-vh-100">
    <OWFHeader />
    <main class="flex-grow-1">
      <slot />
    </main>
    <OWFFooter />
  </div>
</template>
