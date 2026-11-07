# Administrator account provisioning

POST /admin/users requires ordinary bearer-cookie authentication and Role.Admin.
It accepts email, password (12–100 characters, digit, supported sign-up characters),
role (regular/publisher/admin) and UUID-v4 requestId. It returns only uuid/email/role
with HTTP 201. It does not sign in, issue tokens, set cookies, send invitations or
return password hashes. Existing sign-up/sign-in routes are retained.

Auth owns credential hashing and identity storage. Email is normalized. A unique
sparse provisioningRequestId plus server-owned provisioningActor identify the
operation. Retrying the same actor/key/email/role returns the existing identity
without hashing again or changing its password. Another account/actor conflicts;
an unrelated existing email never becomes attached through retry. Concurrent calls
recover the same operation after a duplicate-key error.

service-user-metadata coordinates account then profile creation using the existing
administrator cookie. Profile failure can be retried with the original operation
key; no cross-database transaction or account-deletion rollback is claimed. The
frontend retains credentials only in transient form/request memory and clears them
on completion/destruction. Browser shutdown/reload does not preserve an unfinished
creation draft. Account password reset, sign-in email changes and invitation delivery
are separate capabilities and are not advertised by this UI.

## Local integration

With MongoDB running on loopback, run npm run start:admin-local alongside metadata's
npm run start:local and the MFE watcher. This binds port 3005 on 127.0.0.1 and uses
only auth_users_local. The explicit development flag, fixed database and disabled
OAuth are checked before startup. Existing auth mode is unchanged without the flag.
A synthetic admin is accepted only for POST /admin/users and PUT /role from loopback
with no browser Origin or the metadata-service origin. All other routes retain
normal authentication. This is an isolated developer process, never a production
configuration or a hosted sign-in bypass. Do not tunnel this listener.

Local accounts use real bcrypt hashes and the existing sign-in verifier. Metadata
calls only this local service; auth metadata calls are also pinned to local metadata
in this mode. Synthetic metadata seed IDs have no identity, while new 24-hex account
IDs synchronize role changes to this local auth database. Local account creation or
roles do not modify the hosted identity provider. The package script's fixed JWT
secret is development-only and must never be copied to a production configuration.

## Production handoff

Before deploying the metadata/MFE consumers:
1. Deploy auth's additive admin provisioning endpoint behind its existing trusted
   auth ingress. Supply the normal JWT/roles guards; never enable local flags.
2. On the auth users collection create the sparse unique index
   {provisioningRequestId:1} with {unique:true,sparse:true}. Production disables
   autoIndex; the existing unique email index must also remain. No index changes
   were performed against production during implementation.
3. Configure service-user-metadata AUTH_BASE_URL so /admin/users and /role reach this
   service, with the existing administrator accessToken cookie accepted. Deploy its
   additive endpoint and updated OpenAPI, then the MFE. No contracts were published.
4. Verify an authenticated admin can create a disposable account/profile without
   replacing their session, regular users cannot provision, duplicates conflict,
   and a profile-failure retry completes the same account. Existing JWTs retain their
   lifetime after role changes; fresh sign-in uses the updated role.

Local tests and isolated HTTP verification do not establish hosted ingress, indexes,
JWT compatibility or production account provisioning. No deployment is included.
