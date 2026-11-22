from dataclasses import replace
import pytest
from riskauthnet.crypto.certificates import CertificateAuthority
from riskauthnet.crypto.ecc import sign,verify,public_bytes,load_public
from riskauthnet.crypto.auth import CryptoGate
from riskauthnet.crypto.session import mutual_handshake
from riskauthnet.config import Settings
from riskauthnet.models import b64


def test_rfc6979_and_tampering():
    ca=CertificateAuthority(); ident=ca.issue("alice")
    a=sign(ident.private_key,b"abc")
    assert a==sign(ident.private_key,b"abc") and len(a)==64
    assert verify(ident.private_key.public_key(),b"abc",a)
    assert not verify(ident.private_key.public_key(),b"abd",a)
    assert not verify(ident.private_key.public_key(),b"abc",a[:62])


def test_gate_valid_replay_and_tampering():
    ca=CertificateAuthority(); ident=ca.issue("a")
    g=CryptoGate(ca,Settings())
    first=ident.create_message(timestamp_ms=100,seq=1)
    assert g.authenticate(first,110).valid
    assert g.authenticate(first,120).reason=="REPLAY"
    changed=replace(first,x=300)
    assert g.authenticate(changed,120).reason=="INVALID_SIGNATURE"
    second=ident.create_message(timestamp_ms=200,seq=2,include_certificate=False)
    assert g.authenticate(second,210).valid
    assert g.authenticate(second,350).reason=="STALE_OR_FUTURE"
    # Invalid packets never mutate a legitimate sender's highest trusted sequence.
    assert g.highest_seq[ident.pseudonym]==2


def test_sequence_conflict_instant_override():
    ca=CertificateAuthority();id=ca.issue("a");g=CryptoGate(ca,Settings())
    old=id.create_message(timestamp_ms=100,seq=1,x=10)
    assert g.authenticate(old,110).valid
    new=id.create_message(timestamp_ms=100,seq=1,x=500)
    result=g.authenticate(new,112)
    assert not result.valid and result.override=="CONFLICTING_SEQUENCE"


def test_signed_cert_expiry_and_crl():
    ca=CertificateAuthority();id=ca.issue("a",now_ms=0,lifetime_ms=200)
    assert ca.verify_certificate(id.certificate,100)
    cert=replace(id.certificate,not_after_ms=10_000)
    assert not ca.verify_certificate(cert,100)
    gate=CryptoGate(ca,Settings())
    assert gate.authenticate(id.create_message(timestamp_ms=100),110).valid
    ca.revoke(id.certificate.serial)
    assert gate.load_crl(ca.crl_update())
    revoked=gate.authenticate(id.create_message(timestamp_ms=150),155)
    assert revoked.override=="CRL_HIT"
    altered=ca.crl_update()
    altered["revoked_serials"]=[]
    assert not gate.load_crl(altered)
    assert not ca.verify_certificate(id.certificate,220)


def test_invalid_certificate_and_capacity():
    ca=CertificateAuthority();id=ca.issue("a")
    gate=CryptoGate(ca,Settings())
    msg=id.create_message(timestamp_ms=100)
    msg.cert_digest="00"*8
    assert gate.authenticate(msg,110).reason=="UNKNOWN_OR_INVALID_CERT"
    config=Settings(max_active_senders=1)
    gate=CryptoGate(ca,config)
    assert gate.authenticate(id.create_message(timestamp_ms=101),110).valid
    id2=ca.issue("b")
    assert not gate.authenticate(id2.create_message(timestamp_ms=101),110).valid


def test_authenticated_four_dh_session_and_rekey():
    ca=CertificateAuthority();v=ca.issue("v");r=ca.issue("r",is_rsu=True)
    sv,sr=mutual_handshake(v,r,ca,now_ms=20)
    assert sv.key==sr.key and len(sv.key)==32 and sv.transcript_hash==sr.transcript_hash
    old=sv.key
    sv.ratchet(21);sr.ratchet(21)
    assert sv.key==sr.key and sv.key!=old
    assert not sv.expired(21)
    with pytest.raises(ValueError):sv.ratchet(60021)
