
from __future__ import annotations
from dataclasses import dataclass
import copy
import math
import random

from ..models import Message, Context
from ..config import Settings
from ..crypto.certificates import CertificateAuthority, Identity

SCENARIOS = {
 "s1":("urban",30,"none"),"s2":("urban",80,"spoof"),
 "s3":("urban",120,"replay"),"s4":("urban",120,"sybil"),
 "s5":("highway",40,"none"),"s6":("highway",70,"tamper"),
 "s7":("highway",100,"mixed"),"s8":("urban",200,"mixed")}
ATTACKS = ("none","spoof","replay","sybil","tamper","position","speed","flood","mixed")


@dataclass
class TraceEvent:
    message: Message
    arrival_ms: int
    malicious: bool
    attack: str
    context: Context


@dataclass
class Trace:
    events: list[TraceEvent]
    authority: CertificateAuthority
    identities: dict[str,Identity]
    seed: int
    environment: str


def generate_trace(*, config: Settings | None = None, seed: int = 42,
                   vehicles: int = 12, duration_seconds: float = 8.0,
                   environment: str = "urban", attack: str = "mixed",
                   attacker_fraction: float = 0.1,
                   channel_drop_probability: float | None = None) -> Trace:
    if vehicles < 1 or duration_seconds <= 0 or attack not in ATTACKS or environment not in ("urban","highway"):
        raise ValueError("invalid trace setup")
    if not 0 <= attacker_fraction <= 1:
        raise ValueError("attacker_fraction outside [0,1]")
    p=config or Settings()
    rng=random.Random(seed)
    ca=CertificateAuthority()
    if channel_drop_probability is None:
        channel_drop_probability = 0.1 if environment=="urban" else 0.04
    identities={}
    actors=[]
    attacker_set=set(rng.sample(range(vehicles),min(vehicles,round(vehicles*attacker_fraction)))) if attack!="none" else set()
    for i in range(vehicles):
        ident=ca.issue(f"vehicle-{i}",0,int(duration_seconds*1000)+p.pseudonym_lifetime_ms+1000)
        identities[ident.pseudonym]=ident
        speed=rng.uniform(5,16) if environment=="urban" else rng.uniform(22,32)
        actors.append([ident, speed, rng.uniform(-100,100), rng.uniform(-100,100),0.0, i])
    events=[]
    previous_message: dict[int,Message] = {}
    steps=math.ceil(duration_seconds*1000/p.beacon_interval_ms)
    for k in range(steps):
        ms=k*p.beacon_interval_ms
        for actor in actors:
            ident,speed,x0,y0,heading,i=actor
            if ms>0 and ms%p.pseudonym_lifetime_ms==0:
                ident=ca.issue(f"vehicle-{i}",ms,int(duration_seconds*1000)+p.pseudonym_lifetime_ms+1000)
                actor[0]=ident
                identities[ident.pseudonym]=ident
            if rng.random()<channel_drop_probability:
                # Lost beacon: sender's seq still advances so receiver sees a gap.
                ident.next_sequence += 1
                continue
            x=x0+speed*ms/1000.0
            y=y0
            typ="EMERGENCY" if rng.random()<0.005 else ("DENM" if rng.random()<0.015 else "BSM")
            event_code="emergency-brake" if typ=="EMERGENCY" else "congestion" if typ=="DENM" else ""
            malicious = (i in attacker_set and k>0 and rng.random()<0.48)
            chosen=attack if attack!="mixed" else rng.choice(["spoof","replay","sybil","tamper","position","speed","flood"])
            if chosen=="none":
                malicious=False
            if not malicious: chosen="none"
            if malicious and chosen=="speed":
                speed_report=110.0
            else:
                speed_report=speed
            if malicious and chosen=="position":
                x+=rng.choice([-1,1])*rng.uniform(100,300)
            if malicious and chosen=="sybil":
                # Multiple legitimately certified pseudonyms belonging to one vehicle.
                # TA-only mapping is retained; this attack is not cryptographic forgery.
                sybil_id=ca.issue(f"vehicle-{i}",ms,p.pseudonym_lifetime_ms)
                identities[sybil_id.pseudonym]=sybil_id
                send_id=sybil_id
                event_code="congestion"
                typ="DENM"
            else:
                send_id=ident
            m=send_id.create_message(timestamp_ms=ms,kind=typ,x=x,y=y,
                        speed=speed_report,heading=heading,event_code=event_code,
                        include_certificate=(send_id.next_sequence<=2 or k%20==0))
            if malicious and chosen=="spoof":
                m.signature_b64="AAAA"  # malformed signature
            elif malicious and chosen=="tamper":
                m.x += 200.0  # modification after signing -> invalid ECDSA
            elif malicious and chosen=="replay":
                if i in previous_message:
                    m=copy.deepcopy(previous_message[i])
                else:
                    malicious=False; chosen="none"
            elif malicious and chosen=="flood":
                # Signed burst: one additional packet within 2 ms.
                extra=send_id.create_message(timestamp_ms=ms+2,kind="BSM",x=x,y=y,
                                              speed=speed_report,heading=heading,
                                              include_certificate=True)
                ctx=Context(vehicle_count=vehicles,channel_busy=min(1,0.15+vehicles/450+0.2),
                            rsu_reachable=True,recent_alerts=5,
                            neighbor_pdr=1-channel_drop_probability,
                            neighbor_speeds=(speed,speed+1),corroborators=0)
                events.append(TraceEvent(extra,ms+12,True,"flood",ctx))
            if not malicious and k % 2 == 0:
                previous_message[i]=copy.deepcopy(m)
            arrival=ms+rng.randint(5,20)
            ctx=Context(vehicle_count=vehicles,
                        channel_busy=min(1.0,0.12+vehicles/450 + (0.16 if malicious else 0)),
                        rsu_reachable=(rng.random() > 0.035),
                        recent_alerts=(5 if malicious else 0),
                        neighbor_pdr=1-channel_drop_probability,
                        neighbor_speeds=(speed,speed+rng.uniform(-2,2)),
                        corroborators=(0 if malicious else 2))
            events.append(TraceEvent(m,arrival,malicious,chosen,ctx))
    events.sort(key=lambda e: (e.arrival_ms,e.message.pseudonym,e.message.seq))
    return Trace(events,ca,identities,seed,environment)
