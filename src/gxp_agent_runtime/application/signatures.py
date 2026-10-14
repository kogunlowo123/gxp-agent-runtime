"""21 CFR Part 11 electronic signatures.

Two-step signing:

1. The signer asks for a challenge on a specific record and meaning. The
   challenge fixes the record digest the signer was shown and carries a
   random single-use nonce.
2. The signer re-authenticates at the enterprise IdP with that nonce and
   submits the resulting ID token. The runtime verifies identity, freshness,
   nonce binding and that the record has not changed, consumes the
   challenge exactly once, and issues a signature whose manifest (printed
   name, date and time, meaning, record digest) is signed with the runtime's
   Ed25519 key. The signature cannot be copied onto another record because
   it covers that record's digest (11.70); the audit chain makes it
   non-repudiable.
"""

from __future__ import annotations

import secrets
from datetime import timedelta

from agentic_core.domain.identifiers import new_id

from gxp_agent_runtime.domain.errors import NotFoundError, SignatureError
from gxp_agent_runtime.domain.models import (
    ElectronicSignature,
    RecordType,
    SignatureMeaning,
    SigningChallenge,
)
from gxp_agent_runtime.domain.ports import ChallengeRepository, Clock, SignatureRepository
from gxp_agent_runtime.security.humans import HumanAuthenticator, HumanPrincipal
from gxp_agent_runtime.security.keys import RecordSigner, SignatureVerifier


class SignatureService:
    def __init__(
        self,
        *,
        challenges: ChallengeRepository,
        signatures: SignatureRepository,
        humans: HumanAuthenticator,
        signer: RecordSigner,
        verifier: SignatureVerifier,
        clock: Clock,
        challenge_ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        self._challenges = challenges
        self._signatures = signatures
        self._humans = humans
        self._signer = signer
        self._verifier = verifier
        self._clock = clock
        self._ttl = challenge_ttl

    async def challenge(
        self,
        principal: HumanPrincipal,
        *,
        record_type: RecordType,
        record_id: str,
        record_digest: str,
        meaning: SignatureMeaning,
    ) -> SigningChallenge:
        now = self._clock.now()
        challenge = SigningChallenge(
            challenge_id=new_id(),
            nonce=secrets.token_urlsafe(32),
            record_type=record_type,
            record_id=record_id,
            record_digest=record_digest,
            meaning=meaning,
            subject=principal.subject,
            created_at=now,
            expires_at=now + self._ttl,
        )
        await self._challenges.add(challenge)
        return challenge

    async def pending_challenge(
        self, principal: HumanPrincipal, challenge_id: str
    ) -> SigningChallenge:
        challenge = await self._challenges.get(challenge_id)
        if challenge is None:
            raise NotFoundError("signing challenge not found")
        if challenge.subject != principal.subject:
            raise SignatureError("signing challenge was issued to a different user")
        if challenge.used_at is not None:
            raise SignatureError("signing challenge has already been used")
        if self._clock.now() > challenge.expires_at:
            raise SignatureError("signing challenge expired; request a new one")
        return challenge

    async def sign(
        self,
        principal: HumanPrincipal,
        challenge: SigningChallenge,
        *,
        reauthentication_token: str,
        reason: str,
        current_digest: str,
    ) -> ElectronicSignature:
        if current_digest != challenge.record_digest:
            raise SignatureError("record changed after the challenge was issued; review it again")
        reauth = await self._humans.verify_reauthentication(
            reauthentication_token, subject=principal.subject, nonce=challenge.nonce
        )
        now = self._clock.now()
        if not await self._challenges.consume(challenge.challenge_id, now):
            raise SignatureError("signing challenge has already been used")
        draft = ElectronicSignature(
            signature_id=new_id(),
            record_type=challenge.record_type,
            record_id=challenge.record_id,
            record_digest=challenge.record_digest,
            signer_subject=principal.subject,
            signer_name=reauth.name,
            meaning=challenge.meaning,
            reason=reason,
            signed_at=now,
            auth_time=reauth.auth_time,
            auth_methods=reauth.methods,
            challenge_id=challenge.challenge_id,
            key_id=self._signer.key_id,
        )
        signature = draft.model_copy(update={"value": self._signer.sign_document(draft.manifest())})
        await self._signatures.add(signature)
        return signature

    def verify(self, signature: ElectronicSignature) -> bool:
        return self._verifier.verify_document(
            signature.key_id, signature.manifest(), signature.value
        )
