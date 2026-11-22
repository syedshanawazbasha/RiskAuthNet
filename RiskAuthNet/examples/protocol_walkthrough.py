"""Demonstrate real certificate, replay, signed CRL and V2I session path."""
from riskauthnet.crypto.certificates import CertificateAuthority
from riskauthnet.crypto.session import mutual_handshake
from riskauthnet.config import Settings
from riskauthnet.models import Context
from riskauthnet.pipeline import Receiver

p=Settings()
ta=CertificateAuthority()
car=ta.issue("private-car-001",now_ms=0)
rsu=ta.issue("roadside-101",0,1000000,is_rsu=True)
v_session,r_session=mutual_handshake(car,rsu,ta,now_ms=0)
assert v_session.key==r_session.key
print("V2I session agreement:",len(v_session.key),"bytes; identities mutually authenticated")
receiver=Receiver(ta,p,identities={car.pseudonym:car})
first=car.create_message(timestamp_ms=100,seq=1,x=0,y=0,speed=10)
print("First reception:",receiver.process(first,110,Context()).to_dict())
print("Replay:",receiver.process(first,111,Context()).reason)
ta.revoke(car.certificate.serial)
receiver.refresh_crl()
second=car.create_message(timestamp_ms=200,seq=2,x=1,y=0,speed=10)
print("Revoked credential:",receiver.process(second,210,Context()).reason)
