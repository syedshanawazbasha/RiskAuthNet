from dataclasses import replace
from riskauthnet.crypto.certificates import CertificateAuthority
from riskauthnet.config import Settings
from riskauthnet.models import Context
from riskauthnet.rsu.load_control import EscalationLimiter
from riskauthnet.rsu.rsu import RoadsideUnit
from riskauthnet.pipeline import Receiver


def test_token_bucket_limits_and_event_coalesce():
    p=Settings();ca=CertificateAuthority();id=ca.issue("a")
    limiter=EscalationLimiter(p)
    one=id.create_message(timestamp_ms=100,seq=1)
    two=id.create_message(timestamp_ms=150,seq=2)
    assert limiter.admit(one,100).accepted
    assert limiter.admit(two,150).reason=="PSEUDONYM_BUDGET"
    three=id.create_message(timestamp_ms=2500,seq=3)
    assert limiter.admit(three,2500).accepted
    assert limiter.admitted==2
    q=Settings(rsu_max_per_second=1)
    limiter2=EscalationLimiter(q)
    id2=ca.issue("b")
    assert limiter2.admit(one,100).accepted
    assert limiter2.admit(id2.create_message(timestamp_ms=110),110).reason=="RSU_OVERLOAD"


def test_signed_rsu_tokens_and_binding():
    ca=CertificateAuthority();id=ca.issue("a");r=RoadsideUnit(ca,Settings())
    r.ensure_session(id,100)
    t=r.issue_token(id.pseudonym,0.93,110)
    assert r.verify_token(t,id.certificate,120,id.pseudonym)==0.9
    assert r.verify_token(t,id.certificate,120,"another") is None
    assert r.verify_token(t,id.certificate,30200,id.pseudonym) is None
    altered=dict(t,trust_quantized=0.5)
    assert r.verify_token(altered,id.certificate,120,id.pseudonym) is None


def test_receiver_replay_fails_without_poisoning_trust():
    ca=CertificateAuthority();id=ca.issue("a")
    rx=Receiver(ca,Settings(),identities={id.pseudonym:id})
    one=id.create_message(timestamp_ms=100,x=0,speed=10)
    result=rx.process(one,108,Context())
    before=rx.trust.get(id.pseudonym).trust
    result2=rx.process(one,109,Context())
    assert result.admitted and result2.final_status=="REJECT"
    assert rx.trust.get(id.pseudonym).trust==before


def test_signed_insider_attack_is_not_crypto_forgery():
    ca=CertificateAuthority();id=ca.issue("a")
    rx=Receiver(ca,Settings(),identities={id.pseudonym:id})
    x=0
    for k in range(12):
        rx.process(id.create_message(timestamp_ms=100*k,x=x,speed=10),100*k+8,Context())
        x+=1
    evil=id.create_message(timestamp_ms=1200,x=1000,speed=110)
    d=rx.process(evil,1208,Context())
    assert d.behavior_score<0.5
    assert d.final_status in ("REJECT","HOLD")


def test_override_for_signed_sequence_conflict():
    ca=CertificateAuthority();id=ca.issue("a")
    rx=Receiver(ca,Settings(),identities={id.pseudonym:id})
    a=id.create_message(timestamp_ms=100,seq=1,x=1)
    assert rx.process(a,106).admitted
    b=id.create_message(timestamp_ms=100,seq=1,x=500)
    d=rx.process(b,108)
    assert d.action=="ESCALATE" and d.final_status=="REJECT"
    assert rx.trust.get(id.pseudonym).quarantined


def test_pipeline_unsupported_method():
    import pytest
    with pytest.raises(ValueError):Receiver(CertificateAuthority(),Settings(),method="unlisted")


def test_cross_rsu_token_initialises_trust_cautiously():
    ca=CertificateAuthority();identity=ca.issue("a")
    old_rsu=RoadsideUnit(ca,Settings())
    old_rsu.ensure_session(identity,100)
    token=old_rsu.issue_token(identity.pseudonym,0.95,110)
    new_rsu=RoadsideUnit(ca,Settings())
    assert new_rsu.verify_token(token,identity.certificate,120,identity.pseudonym)==0.9
    rx=Receiver(ca,Settings(),identities={identity.pseudonym:identity},rsu=new_rsu)
    msg=identity.create_message(timestamp_ms=120,speed=10)
    out=rx.process(msg,125,Context(),trust_token=token)
    assert out.trust>=0.9 and out.level>=1
    no_token=Receiver(ca,Settings(),identities={identity.pseudonym:identity})
    assert no_token.process(msg,125,Context()).trust < out.trust


def test_authenticated_rsu_notice_forces_quarantine():
    ca=CertificateAuthority();ident=ca.issue("a")
    rsu=RoadsideUnit(ca,Settings())
    receiver=Receiver(ca,Settings(),rsu=rsu)
    notice=rsu.sign_misbehaviour_notice(ident.pseudonym,now_ms=100)
    forged=dict(notice,reason="FAKE")
    assert not receiver.accept_rsu_notice(forged,110)
    assert receiver.accept_rsu_notice(notice,110)
    assert receiver.trust.get(ident.pseudonym).quarantined
    assert not receiver.accept_rsu_notice(notice,111)
    msg=ident.create_message(timestamp_ms=120)
    d=receiver.process(msg,125,Context())
    assert not d.admitted


def test_signed_position_jump_is_not_admitted_at_l0():
    ca=CertificateAuthority();ident=ca.issue("a")
    rx=Receiver(ca,Settings(),identities={ident.pseudonym:ident})
    for i in range(15):
        msg=ident.create_message(timestamp_ms=i*100,x=i,speed=10)
        rx.process(msg,i*100+5,Context())
    # Position-only tampering can still yield S>0.5 because other feature
    # groups remain clean; the kinematic hard floor must block dissemination.
    bad=ident.create_message(timestamp_ms=1500,x=10000,speed=10)
    verdict=rx.process(bad,1505,Context())
    assert verdict.level>=2 and not verdict.admitted
