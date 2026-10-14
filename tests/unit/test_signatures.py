"""Part 11 signing ceremony: challenge, re-authentication, linkage, single use."""

from __future__ import annotations

import pytest

from gxp_agent_runtime.application.commands import CreateChallenge
from gxp_agent_runtime.application.runtime import GxpRuntime
from gxp_agent_runtime.domain.errors import NotFoundError, SignatureError, UnauthorizedError
from gxp_agent_runtime.domain.models import RecordType, SignatureMeaning
from gxp_agent_runtime.runtime.container import Container
from tests.conftest import APPROVER, QA, FakeClock, FakeIdp, agent_principal, submission

pytestmark = pytest.mark.urs("URS-003")


async def pending(runtime: GxpRuntime, clock: FakeClock) -> str:
    view = await runtime.submit(agent_principal(), submission(clock, "lims.result.release"))
    return view.request_id


async def challenge_for(runtime: GxpRuntime, idp: FakeIdp, request_id: str) -> tuple[str, str]:
    view = await runtime.create_challenge(
        CreateChallenge(
            record_type=RecordType.ACTION_REQUEST,
            record_id=request_id,
            meaning=SignatureMeaning.APPROVAL,
        ),
        who=idp.principal(APPROVER),
    )
    assert view.statement.startswith("I approve")
    assert view.signer == "Adam Approver"
    return view.challenge_id, view.nonce


async def attempt(
    runtime: GxpRuntime, idp: FakeIdp, challenge_id: str, token: str, who: tuple = APPROVER
) -> None:
    await runtime.sign(
        who=idp.principal(who),
        challenge_id=challenge_id,
        reauthentication_token=token,
        reason="Approved after review of batch record.",
    )


async def test_signature_manifest_is_signed_and_verifiable(
    provisioned: GxpRuntime, container: Container, idp: FakeIdp, clock: FakeClock
) -> None:
    request_id = await pending(provisioned, clock)
    challenge_id, nonce = await challenge_for(provisioned, idp, request_id)
    outcome = await provisioned.sign(
        who=idp.principal(APPROVER),
        challenge_id=challenge_id,
        reauthentication_token=idp.reauth(APPROVER, nonce, amr=("pwd", "otp")),
        reason="Approved after review of batch record.",
    )
    signature = outcome.signature
    assert signature.auth_methods == ("pwd", "otp")
    assert signature.meaning is SignatureMeaning.APPROVAL
    assert signature.key_id == container.signer.key_id
    assert signature.signed_at == clock.now()
    signatures = provisioned._signatures
    assert signatures.verify(signature)
    forged = signature.model_copy(update={"meaning": SignatureMeaning.QUALITY_APPROVAL})
    assert not signatures.verify(forged)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"nonce": "wrong"}, "not bound"),
        ({"auth_age": 3600}, "re-entered within"),
        ({"amr": ()}, "accepted authentication method"),
    ],
)
async def test_reauthentication_must_be_fresh_bound_and_strong(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock, mutation: dict, message: str
) -> None:
    request_id = await pending(provisioned, clock)
    challenge_id, nonce = await challenge_for(provisioned, idp, request_id)
    token = idp.reauth(
        APPROVER,
        mutation.get("nonce", nonce),
        auth_age=mutation.get("auth_age", 5),
        amr=mutation.get("amr", ("pwd",)),
    )
    with pytest.raises(SignatureError, match=message):
        await attempt(provisioned, idp, challenge_id, token)


async def test_reauthentication_by_someone_else_is_rejected(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock
) -> None:
    request_id = await pending(provisioned, clock)
    challenge_id, nonce = await challenge_for(provisioned, idp, request_id)
    with pytest.raises(SignatureError, match="different user"):
        await attempt(provisioned, idp, challenge_id, idp.reauth(QA, nonce))
    with pytest.raises(SignatureError, match="issued to a different user"):
        await attempt(provisioned, idp, challenge_id, idp.reauth(QA, nonce), who=QA)


async def test_reauthentication_token_must_be_valid(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock
) -> None:
    request_id = await pending(provisioned, clock)
    challenge_id, _ = await challenge_for(provisioned, idp, request_id)
    with pytest.raises(SignatureError, match="invalid"):
        await attempt(provisioned, idp, challenge_id, "not-a-jwt-but-long-enough-to-pass")
    no_auth_time = idp.mint(sub=APPROVER[0], nonce="x")
    with pytest.raises(SignatureError):
        await attempt(provisioned, idp, challenge_id, no_auth_time)


async def test_challenge_is_single_use_and_expires(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock
) -> None:
    request_id = await pending(provisioned, clock)
    challenge_id, nonce = await challenge_for(provisioned, idp, request_id)
    await attempt(provisioned, idp, challenge_id, idp.reauth(APPROVER, nonce))
    with pytest.raises(SignatureError, match="already been used"):
        await attempt(provisioned, idp, challenge_id, idp.reauth(APPROVER, nonce))

    other = await pending(provisioned, clock)
    challenge_id, nonce = await challenge_for(provisioned, idp, other)
    clock.advance(minutes=6)
    with pytest.raises(SignatureError, match="expired"):
        await attempt(provisioned, idp, challenge_id, idp.reauth(APPROVER, nonce))
    with pytest.raises(NotFoundError):
        await attempt(provisioned, idp, "missing", idp.reauth(APPROVER, nonce))


async def test_record_changed_after_challenge_invalidates_signature(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock
) -> None:
    request_id = await pending(provisioned, clock)
    challenge_id, nonce = await challenge_for(provisioned, idp, request_id)
    request = await provisioned.get_request(request_id)
    tampered = request.model_copy(
        update={"justification": "Different reason entirely.", "revision": request.revision + 1}
    )
    await provisioned._requests.replace(tampered, expected_revision=request.revision)
    with pytest.raises(SignatureError, match="record changed"):
        await attempt(provisioned, idp, challenge_id, idp.reauth(APPROVER, nonce))


async def test_human_authentication(container: Container, idp: FakeIdp) -> None:
    humans = container.humans
    principal = await humans.authenticate(f"Bearer {idp.user(APPROVER)}")
    assert principal.name == "Adam Approver"
    assert principal.roles == frozenset({"gxp-approver"})
    nameless = await humans.authenticate(
        f"Bearer {idp.mint(sub='x@corp.test', roles='not-a-list')}"
    )
    assert nameless.name == "x@corp.test"
    assert nameless.roles == frozenset()
    for header in (None, "Basic abc", "Bearer a.b.c"):
        with pytest.raises(UnauthorizedError):
            await humans.authenticate(header)
    with pytest.raises(UnauthorizedError, match="Expired"):
        await humans.authenticate(f"Bearer {idp.mint(sub='x', ttl=-120)}")
    with pytest.raises(UnauthorizedError):
        await humans.authenticate(f"Bearer {idp.mint(sub='x', aud='other')}")
