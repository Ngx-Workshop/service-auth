import { isDeepStrictEqual } from 'node:util';

export async function validateSocialSchema(db) {
  const transactions = await db
    .collection('social_login_transactions')
    .listIndexes()
    .toArray();
  const users = await db.collection('users').listIndexes().toArray();
  if (
    !transactions.some(
      (index) =>
        isDeepStrictEqual(index.key, { expiresAt: 1 }) &&
        index.expireAfterSeconds === 0 &&
        !index.unique &&
        !index.partialFilterExpression,
    ) ||
    !users.some(
      (index) =>
        isDeepStrictEqual(index.key, { externalIdentities: 1 }) &&
        index.unique === true &&
        index.sparse === true &&
        !index.partialFilterExpression,
    )
  )
    throw new Error(
      'Social login indexes missing; provision separately before deployment',
    );
}
