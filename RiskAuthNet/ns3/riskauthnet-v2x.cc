
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include <fstream>
#include <sstream>
#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <cmath>
using namespace ns3;

struct MobilityRow { uint64_t ms; std::string id; double x,y,speed,heading; };
static std::ofstream output;
static std::vector<std::string> idNames;
static const uint32_t kPort = 4444;
static const uint64_t kStartOffsetMs = 100;

static void Receive(Ptr<Socket> socket) {
  Ptr<Packet> pkt;
  Address sender;
  while ((pkt = socket->RecvFrom(sender))) {
    if (pkt->GetSize() == 0 || pkt->GetSize()>2048) continue;
    std::vector<uint8_t> buf(pkt->GetSize());
    pkt->CopyData(buf.data(),pkt->GetSize());
    std::string payload(buf.begin(),buf.end());
    std::istringstream fields(payload);
    std::string nodeName,seqStr,timeStr;
    if (!std::getline(fields,nodeName,',') ||
        !std::getline(fields,seqStr,',') ||
        !std::getline(fields,timeStr,',')) continue;
    uint64_t recv = (uint64_t)Simulator::Now().GetMilliSeconds();
    output << nodeName << ',' << seqStr << ',' << timeStr << ','
           << (recv>kStartOffsetMs ? recv-kStartOffsetMs : 0) << ','
           << socket->GetNode()->GetId() << '\n';
  }
}

static void Send(Ptr<Socket> socket, const std::string& nodeName,
                 uint64_t seq, uint64_t sendMs, uint32_t pktSize) {
  std::string header=nodeName+","+std::to_string(seq)+","+std::to_string(sendMs);
  if (header.size()+1>pktSize) return;
  std::vector<uint8_t> data(pktSize,'*');
  std::copy(header.begin(),header.end(),data.begin());
  data[header.size()] = ',';
  Ptr<Packet> pkt=Create<Packet>(data.data(),pktSize);
  socket->Send(pkt);
}

int main(int argc,char** argv) {
  std::string mobilityCsv="mobility.csv",outputCsv="ns3-received.csv";
  uint32_t packetBytes=300;
  double txDbm=23.0;
  double nakagamiM=1.0;
  CommandLine cmd(__FILE__);
  cmd.AddValue("mobilityCsv","SUMO exported CSV (send_ms,vehicle_id,x,y,speed,heading)",mobilityCsv);
  cmd.AddValue("outputCsv","Output per-receiver successful RX CSV",outputCsv);
  cmd.AddValue("packetBytes","Size of UDP application payload, not IEEE1609.2 actual encoding",packetBytes);
  cmd.AddValue("txDbm","Transmitter power",txDbm);
  cmd.AddValue("nakagamiM","Urban=1, Highway=3",nakagamiM);
  cmd.Parse(argc,argv);
  if (packetBytes<64 || packetBytes>1300) { std::cerr << "Invalid packetBytes\n"; return 2; }
  std::ifstream file(mobilityCsv);
  if (!file) { std::cerr << "Cannot open " << mobilityCsv << '\n'; return 2; }
  std::string line;
  std::getline(file,line); // header
  std::vector<MobilityRow> rows;
  std::map<std::string,uint32_t> indexes;
  uint64_t lastMs=0;
  while(std::getline(file,line)) {
    std::istringstream s(line);
    std::string cells[6];
    bool ok=true;
    for(int k=0;k<6;++k) if(!std::getline(s,cells[k],',')) {ok=false;break;}
    if (!ok) continue;
    try {
      MobilityRow r{std::stoull(cells[0]),cells[1],std::stod(cells[2]),
                    std::stod(cells[3]),std::stod(cells[4]),std::stod(cells[5])};
      if(!indexes.count(r.id)) {
        indexes[r.id]=indexes.size();
        idNames.push_back(r.id);
      }
      lastMs=std::max(lastMs,r.ms);
      rows.push_back(r);
    } catch (const std::exception&) { continue; }
  }
  if(rows.empty()) {std::cerr << "No usable mobility points\n";return 2;}
  std::stable_sort(rows.begin(),rows.end(),[](const MobilityRow&a,const MobilityRow&b){return a.ms<b.ms;});
  NodeContainer nodes;
  nodes.Create(indexes.size());
  std::vector<Ptr<WaypointMobilityModel>> mobility(indexes.size());
  std::vector<uint64_t> prevMs(indexes.size(),0);
  std::vector<bool> first(indexes.size(),true);
  for(const auto& row:rows) {
    uint32_t id=indexes.at(row.id);
    auto model=mobility[id];
    if(!model) {
      model=CreateObject<WaypointMobilityModel>();
      mobility[id]=model;
      nodes.Get(id)->AggregateObject(model);
      model->AddWaypoint(Waypoint(Seconds(0),Vector(row.x,row.y,1.5)));
    }
    if((first[id] && row.ms==0) || (!first[id] && row.ms<=prevMs[id])){
      first[id]=false; continue;
    }
    model->AddWaypoint(Waypoint(MilliSeconds(row.ms),Vector(row.x,row.y,1.5)));
    first[id]=false;prevMs[id]=row.ms;
  }
  WifiHelper wifi;
  wifi.SetStandard(WIFI_STANDARD_80211p);
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
      "DataMode",StringValue("OfdmRate6MbpsBW10MHz"),
      "ControlMode",StringValue("OfdmRate6MbpsBW10MHz"));
  YansWifiChannelHelper channel;
  channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
  channel.AddPropagationLoss("ns3::LogDistancePropagationLossModel","Exponent",DoubleValue(3.0));
  channel.AddPropagationLoss("ns3::NakagamiPropagationLossModel",
                             "m0",DoubleValue(nakagamiM),
                             "m1",DoubleValue(nakagamiM),
                             "m2",DoubleValue(nakagamiM));
  YansWifiPhyHelper phy;
  phy.SetChannel(channel.Create());
  phy.Set("TxPowerStart",DoubleValue(txDbm));
  phy.Set("TxPowerEnd",DoubleValue(txDbm));
  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");
  NetDeviceContainer devs=wifi.Install(phy,mac,nodes);
  InternetStackHelper stack;
  stack.Install(nodes);
  Ipv4AddressHelper addresses;
  addresses.SetBase("10.1.0.0","255.255.0.0");
  addresses.Assign(devs);
  const TypeId protocol=TypeId::LookupByName("ns3::UdpSocketFactory");
  std::vector<Ptr<Socket>> tx(indexes.size());
  for(uint32_t i=0;i<indexes.size();++i) {
    Ptr<Socket> rx=Socket::CreateSocket(nodes.Get(i),protocol);
    rx->Bind(InetSocketAddress(Ipv4Address::GetAny(),kPort));
    rx->SetRecvCallback(MakeCallback(&Receive));
    tx[i]=Socket::CreateSocket(nodes.Get(i),protocol);
    tx[i]->SetAllowBroadcast(true);
    tx[i]->Connect(InetSocketAddress(Ipv4Address("10.1.255.255"),kPort));
  }
  std::vector<uint64_t> seq(indexes.size(),0);
  output.open(outputCsv);
  if(!output) { std::cerr << "Cannot write "<<outputCsv<<'\n';return 2; }
  output << "vehicle_id,seq,send_ms,receive_ms,receiver_node\n";
  for(const auto& row:rows) {
    uint32_t id=indexes.at(row.id);
    Simulator::Schedule(MilliSeconds(row.ms+kStartOffsetMs),&Send,tx[id],row.id,
                        ++seq[id],row.ms,packetBytes);
  }
  Simulator::Stop(MilliSeconds(lastMs+kStartOffsetMs+1000));
  Simulator::Run();Simulator::Destroy();output.close();
  return 0;
}
