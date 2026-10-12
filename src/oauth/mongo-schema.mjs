import { isDeepStrictEqual } from 'node:util';
export const stateValidator = {
  $jsonSchema: {
    bsonType: 'object',
    required: ['_id', 'model', 'encrypted', 'expiresAt'],
    additionalProperties: false,
    properties: {
      _id: { bsonType: 'string' },
      model: { bsonType: 'string' },
      expiresAt: { bsonType: 'date' },
      accountHash: { bsonType: 'string' },
      grantHash: { bsonType: 'string' },
      uidHash: { bsonType: 'string' },
      userCodeHash: { bsonType: 'string' },
      consumed: { bsonType: ['int', 'long', 'double'] },
      touchedAt: { bsonType: 'date' },
      encrypted: {
        bsonType: 'object',
        required: ['kid', 'iv', 'tag', 'data'],
        additionalProperties: false,
        properties: {
          kid: { bsonType: 'string' },
          iv: { bsonType: 'string' },
          tag: { bsonType: 'string' },
          data: { bsonType: 'string' },
        },
      },
    },
  },
};
export const stateIndexes = [
  { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
  { key: { model: 1, grantHash: 1 } },
  { key: { model: 1, uidHash: 1 } },
  { key: { model: 1, accountHash: 1 } },
];
export async function provisionOAuthSchema(db) {
  await db.collection('oauth_state').createIndexes(stateIndexes);
  await db.command(
    {
      collMod: 'oauth_state',
      validationLevel: 'strict',
      validationAction: 'error',
      validator: stateValidator,
    },
    { maxTimeMS: 3000 },
  );
  for (const name of ['oauth_forms', 'oauth_revoked'])
    await db
      .collection(name)
      .createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
}
export async function validateOAuthSchema(db) {
  const info = await db
    .listCollections({ name: 'oauth_state' }, { maxTimeMS: 3000 })
    .toArray();
  if (
    info.length !== 1 ||
    info[0].options.validationLevel !== 'strict' ||
    info[0].options.validationAction !== 'error' ||
    !isDeepStrictEqual(info[0].options.validator, stateValidator)
  )
    throw new Error(
      'OAuth validator missing or mismatched; provision separately',
    );
  for (const name of ['oauth_state', 'oauth_forms', 'oauth_revoked']) {
    const actual = await db
      .collection(name)
      .listIndexes({ maxTimeMS: 3000 })
      .toArray();
    const required = name === 'oauth_state' ? stateIndexes : [stateIndexes[0]];
    for (const expected of required)
      if (
        !actual.some(
          (index) =>
            isDeepStrictEqual(index.key, expected.key) &&
            index.expireAfterSeconds === expected.expireAfterSeconds &&
            !index.unique &&
            !index.partialFilterExpression,
        )
      )
        throw new Error(
          'OAuth indexes missing or mismatched; provision separately',
        );
  }
}
