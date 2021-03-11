import logger from '../../lib/logger'

export default async function dispatchEvent (event, message, opts) {
  try {
    await event(message, opts)
  } catch (e) {
    logger.error('EVENT_ERROR', e)
  }
}
