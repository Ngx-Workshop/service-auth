import mongoose from 'mongoose';
import { validateMongoSettings } from '../src/oauth/mongo-settings.mjs';
import { provisionOAuthSchema } from '../src/oauth/mongo-schema.mjs';
// Explicit offline/operator command; never invoked by bootstrap or CI deployment.
validateMongoSettings();
const client = new mongoose.mongo.MongoClient(process.env.MONGODB_URI, {
  tlsCAFile: process.env.MONGODB_TLS_CA_FILE,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 5000,
});
try {
  await client.connect();
  const hello = await client.db('admin').command({ hello: 1 });
  if (
    hello.setName !== process.env.MONGODB_REPLICA_SET ||
    !hello.isWritablePrimary
  )
    throw new Error('Configured primary required');
  await provisionOAuthSchema(client.db());
  console.log('OAuth schema provisioned; no users or grants changed.');
} catch {
  console.error('OAuth schema provisioning failed.');
  process.exitCode = 1;
} finally {
  await client.close();
}
