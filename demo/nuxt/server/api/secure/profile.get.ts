import { requireUserSession } from 'nuxt-oidc-auth/runtime/server/utils/session.js'

export default defineEventHandler(async (event) => {
  const session = await requireUserSession(event)

  return {
    message: 'Success! You are authenticated',
    user: session
  }
})
