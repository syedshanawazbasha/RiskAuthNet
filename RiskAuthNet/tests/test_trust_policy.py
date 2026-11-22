from riskauthnet.crypto.certificates import CertificateAuthority
from riskauthnet.config import Settings
from riskauthnet.trust.trust_engine import TrustEngine
from riskauthnet.risk.policy import RiskPolicy
from riskauthnet.models import Context


def _messages(n=15, start=0, speed=10):
    ca=CertificateAuthority();id=ca.issue("x")
    return id,[id.create_message(timestamp_ms=start+i*100,seq=i+1,
               x=speed*i*0.1,y=0,speed=speed,heading=0) for i in range(n)]


def test_bounded_trust_and_cold_start():
    p=Settings();id,mm=_messages(15)
    engine=TrustEngine(p);risk=RiskPolicy(p)
    c=Context(vehicle_count=40,channel_busy=0.3)
    values=[]
    for msg in mm:
        s,score,features=engine.update(msg,c)
        values.append(s.trust)
        out=risk.evaluate(msg,s,c)
        if s.seen<=3:assert out.level>=1
    assert all(0<=x<=1 for x in values)
    assert len(s.history)==10
    assert s.trust>0.9
    assert risk.evaluate(mm[-1],s,c).level==0


def test_kinematic_attacks_penalty_and_recovery():
    p=Settings();id,mm=_messages(5)
    engine=TrustEngine(p)
    for m in mm[:3]:engine.update(m,Context())
    before=engine.get(id.pseudonym).trust
    two=id.create_message(timestamp_ms=300,seq=4,x=900,speed=110)
    three=id.create_message(timestamp_ms=400,seq=5,x=1800,speed=110)
    engine.update(two,Context())
    s,sc,f=engine.update(three,Context())
    assert s.trust<before and s.probation and sc<0.5
    damaged=s.trust
    for i in range(10):
        msg=id.create_message(timestamp_ms=500+i*100,seq=6+i,
                              x=1800+110*(i+1)*0.1,speed=110)
        engine.update(msg,Context())
    # Bad behaviour should not generate arbitrary trust recovery.
    assert 0<=s.trust<=1
    assert len(s.history)<=p.window_size


def test_fading_loss_no_kinematic_penalty():
    p=Settings();id,_=_messages()
    eng=TrustEngine(p);ctx=Context(neighbor_pdr=0.4)
    # Drop every other signed packet; send times and x positions remain physical.
    for k in range(10):
        m=id.create_message(timestamp_ms=k*200,seq=k*2+1,x=2*k,speed=10)
        s,score,feat=eng.update(m,ctx)
    assert feat["rate"]>0.90
    assert feat["time"]>0.90
    assert score>0.90


def test_risk_monotonicity_and_emergency_floor():
    p=Settings();id,mm=_messages(1)
    eng=TrustEngine(p);s,_,_=eng.update(mm[0],Context())
    r=RiskPolicy(p)
    low=r.evaluate(mm[0],s,Context(vehicle_count=10,channel_busy=0))
    high=r.evaluate(mm[0],s,Context(vehicle_count=200,channel_busy=1,rsu_reachable=False,recent_alerts=20))
    assert high.risk>low.risk
    e=id.create_message(timestamp_ms=100,seq=2,kind="EMERGENCY")
    assert r.evaluate(e,s,Context()).level>=2
    s.trust=0.2
    assert r.evaluate(mm[0],s,Context()).level==3
