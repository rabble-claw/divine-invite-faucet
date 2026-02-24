# Divine Invite Faucet — Design

## Overview
Invite code system for diVine's controlled public launch. Fastly Compute service (Rust/WASM) with KV storage, modeled after divine-blossom.

## Ways to Get an Invite
1. **Admin grant** — admin allocates codes to a user's npub
2. **Social graph** — existing users share their allocated codes
3. **Waitlist** — users request an invite, admin approves
4. **Cashu payment** — pay ecash to buy an invite code

## Architecture
- **Runtime:** Fastly Compute@Edge (Rust, WASM)
- **Storage:** Fastly KV Store
- **Auth:** Nostr event signatures (same pattern as divine-blossom)
- **Admin auth:** Nostr event from allowlisted admin npubs

## KV Schema

### `code:{code}` — Invite code record
```json
{
  "code": "DIVINE-X4B2",
  "creator_npub": "npub1...",
  "invitee_npub": null,
  "created_at": 1771972000,
  "used_at": null,
  "source": "admin|social|waitlist|cashu"
}
```

### `user:{npub}` — User invite state
```json
{
  "npub": "npub1...",
  "codes_allocated": 5,
  "codes_generated": ["DIVINE-X4B2", "DIVINE-Y7K9"],
  "codes_used": 2,
  "invited_by": "npub1...",
  "joined_at": 1771972000
}
```

### `waitlist:{id}` — Waitlist entry
```json
{
  "id": "uuid",
  "contact": "email@example.com",
  "npub": null,
  "requested_at": 1771972000,
  "approved": false,
  "approved_by": null,
  "code_issued": null
}
```

### `stats` — Global counters
```json
{
  "total_codes": 500,
  "codes_used": 142,
  "waitlist_size": 2300,
  "total_users": 142
}
```

## API Endpoints

### Public
- `POST /waitlist` — Join waitlist (email/contact, no auth)
- `POST /validate` — Check if code is valid (no auth needed)

### Authenticated (Nostr event)
- `POST /consume` — Use a code to register (links inviter → invitee)
- `GET /my-codes` — Get my allocated invite codes
- `POST /generate-code` — Generate one of my allocated codes

### Admin (Nostr event from admin npub)
- `POST /admin/grant` — Allocate N codes to a npub
- `POST /admin/approve-waitlist` — Approve waitlist entry → issues code
- `GET /admin/tree` — View invite tree
- `GET /admin/waitlist` — View waitlist
- `GET /admin/stats` — Global stats
- `POST /admin/revoke` — Revoke a code

### Cashu
- `POST /buy` — Submit Cashu token, receive invite code
- Price configurable (e.g., 1000 sats)
- Verify Cashu token against mint, issue code if valid

## Invite Codes
- Format: `DIVINE-XXXX` (human-readable, 4 alphanumeric chars)
- Single-use, no expiration
- Collision-resistant: check KV before issuing

## Flutter Integration
- Invite code screen before account creation in signup flow
- Deep link: `divine.video/invite/CODE` → opens app with code pre-filled
- Validate server-side, fail closed if faucet down
- After successful consume: proceed to Keycast OAuth / key creation

## Invite Tree
- Each user record stores `invited_by` npub
- Admin endpoint returns tree structure for analytics
- Enables future: referral bonuses, growth tracking, influencer metrics

## Security
- Nostr event auth (same as divine-blossom)
- Admin npubs hardcoded in config (same pattern as blossom admin)
- Cashu token verification against configured mint
- Rate limiting on waitlist joins
- Fail closed: if KV unavailable, reject all requests

## Deployment
- Fastly Compute service, deployed via `fastly compute publish`
- KV stores created via Fastly CLI
- CORS headers for divine.video origins
