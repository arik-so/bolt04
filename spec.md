## Trampoline Packet Construction

A Trampoline entry hop payload is marked by having the following field:

- type: 66102
- data:
  - [`tu16`: `max_rewrap_amont`]

If a non-Trampoline-node unwraps a hop payload with that field, it should error the payment.

The Trampoline node should find a path towards the next hop in the onion.

The Trampoline node should encode that path by re-wrapping the onion, except instead of starting from the 0-byte
HMAC, it should start from the one for the next hop.

The re-wrapping should start with a distinct, newly generate random session private key.

The hop data immediately preceding the next hop (i.e. if the Trampoline node is Alice, and the next hop is Dave, and
the Trampoline node finds a pathway that is Alice -> Bob -> Charlie -> Dave), Charlie's hop should contain the following
field:

- type: 66104
- data:
	- [`point`: `trampoline_exit_pubkey`]

The `trampoline_exit_pubkey` should be set to Dave's ephemeral pubkey that Alice calculated from her hop payload.

All the additional shifts to the onion MUST NOT exceed `max_rewrap_amont`.

## Trampoline Onion Peeling

When a node receives a hop payload containing `trampoline_exit_pubkey`, if it's not a Trampoline node, it MUST fail the
payment.

When receiving a `trampoline_exit_pubkey`, a Trampoline node MUST use that to calculate its shared secret with the next
node.
