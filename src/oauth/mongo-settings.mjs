export function validateMongoSettings(env = process.env) {
  let url;
  try {
    url = new URL(env.MONGODB_URI ?? '');
  } catch {
    throw new Error('Invalid MongoDB configuration');
  }
  const allowed = (env.MONGODB_ALLOWED_HOSTS ?? '').split(',');
  const set = env.MONGODB_REPLICA_SET;
  if (
    url.protocol !== 'mongodb:' ||
    !url.username ||
    !url.password ||
    !url.pathname ||
    url.pathname === '/' ||
    !allowed.includes(url.hostname) ||
    !set ||
    url.searchParams.get('replicaSet') !== set ||
    !url.searchParams.get('authSource') ||
    url.searchParams.get('tls') !== 'true' ||
    !env.MONGODB_TLS_CA_FILE ||
    !env.MONGODB_TLS_CA_FILE.startsWith('/')
  )
    throw new Error(
      'Explicit authenticated TLS replica-set configuration required',
    );
  for (const key of [
    'tlsAllowInvalidCertificates',
    'tlsAllowInvalidHostnames',
    'tlsInsecure',
    'directConnection',
  ])
    if (url.searchParams.has(key)) throw new Error('Unsafe MongoDB option');
  // Options not listed here must be reviewed before expanding this fixed topology.
  for (const key of url.searchParams.keys())
    if (
      url.searchParams.getAll(key).length !== 1 ||
      !['replicaSet', 'authSource', 'tls'].includes(key)
    )
      throw new Error('Unsupported MongoDB option');
  return true;
}
