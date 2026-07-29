export async function runConversionRequest({
  source,
  generation,
  request,
  isCurrent,
  publishSuccess,
  publishError,
}) {
  try {
    const result = await request()
    if (!isCurrent(generation, source)) {
      return
    }
    publishSuccess(result)
  } catch (error) {
    if (!isCurrent(generation, source)) {
      return
    }
    publishError(error)
  }
}
