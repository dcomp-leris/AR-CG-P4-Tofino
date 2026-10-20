#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/traffic-control-module.h"
#include "ns3/flow-monitor-module.h"

#include <fstream>
#include <iostream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("L4SMultiScenarioExperiment");

uint32_t g_l4sEcnMarks = 0;
uint32_t g_classicDrops = 0;
static uint8_t g_c3Tos = 0x00;

void TraceEcnMark (Ptr<const QueueDiscItem> item, const char* reason)
{
  g_l4sEcnMarks++;
}

void TraceDrop (Ptr<const QueueDiscItem> item)
{
  g_classicDrops++;
}

void SetC3SocketTos (Ptr<Socket> socket)
{
  socket->SetIpTos (g_c3Tos);
}

// Responsive UDP Client for Scenario 3
class ResponsiveUdpClient : public Application
{
public:
  ResponsiveUdpClient () : m_socket (0) {}
  virtual ~ResponsiveUdpClient () { m_socket = 0; }

  void Setup (Address addr, uint16_t port, DataRate maxRate, uint32_t packetSize)
  {
    m_peer = InetSocketAddress (Ipv4Address::ConvertFrom (addr), port);
    m_currentRate = maxRate;
    m_maxRate = maxRate;
    m_minRate = DataRate ("1.5Mbps");
    m_packetSize = packetSize;
  }

private:
  virtual void StartApplication (void)
  {
    m_socket = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId ());
    m_socket->Bind ();
    m_socket->Connect (m_peer);
    m_socket->SetIpTos (0x01); // ECT(1)
    m_socket->SetRecvCallback (MakeCallback (&ResponsiveUdpClient::ReceivePacket, this));
    m_running = true;
    SendPacket ();
  }

  virtual void StopApplication (void)
  {
    m_running = false;
    if (m_sendEvent.IsRunning ()) Simulator::Cancel (m_sendEvent);
    if (m_socket) m_socket->Close ();
  }

  void SendPacket (void)
  {
    Ptr<Packet> p = Create<Packet> (m_packetSize);
    m_socket->Send (p);

    if (m_running)
      {
        Time nextTime = Seconds (m_packetSize * 8.0 / m_currentRate.GetBitRate ());
        m_sendEvent = Simulator::Schedule (nextTime, &ResponsiveUdpClient::SendPacket, this);
      }
  }

  void ReceivePacket (Ptr<Socket> socket)
  {
    Ptr<Packet> packet;
    Address from;
    while ((packet = socket->RecvFrom (from)))
      {
        uint64_t newRate = std::max (m_minRate.GetBitRate (), static_cast<uint64_t> (m_currentRate.GetBitRate () * 0.85));
        m_currentRate = DataRate (newRate);
      }
  }

  Ptr<Socket> m_socket;
  Address m_peer;
  DataRate m_currentRate;
  DataRate m_maxRate;
  DataRate m_minRate;
  uint32_t m_packetSize;
  bool m_running{false};
  EventId m_sendEvent;
};

int main (int argc, char *argv[])
{
  uint32_t scenario = 5; // Default to Scenario 5 (Controlled L4S Video)
  CommandLine cmd (__FILE__);
  cmd.AddValue ("scenario", "Scenario: 1=Classic, 2=Uncontrolled ECT(1), 3=Responsive UDP, 4=Surge, 5=Controlled ECT(1) Video", scenario);
  cmd.Parse (argc, argv);

  // Set TOS based on selected scenario
  if (scenario == 1) g_c3Tos = 0x00;
  else g_c3Tos = 0x01; // ECT(1) for Scenarios 2, 3, 4, and 5

  NodeContainer clients;
  clients.Create (3);
  
  Ptr<Node> router = CreateObject<Node> ();
  Ptr<Node> server = CreateObject<Node> ();

  PointToPointHelper accessLink;
  accessLink.SetDeviceAttribute ("DataRate", StringValue ("100Mbps"));
  accessLink.SetChannelAttribute ("Delay", StringValue ("1ms"));

  PointToPointHelper bottleneckLink;
  bottleneckLink.SetDeviceAttribute ("DataRate", StringValue ("10Mbps"));
  bottleneckLink.SetChannelAttribute ("Delay", StringValue ("10ms"));

  NetDeviceContainer devC1R = accessLink.Install (clients.Get (0), router);
  NetDeviceContainer devC2R = accessLink.Install (clients.Get (1), router);
  NetDeviceContainer devC3R = accessLink.Install (clients.Get (2), router);
  NetDeviceContainer devRS = bottleneckLink.Install (router, server);

  Config::SetDefault ("ns3::TcpSocketBase::UseEcn", StringValue ("On"));

  InternetStackHelper stack;
  stack.Install (clients);
  stack.Install (router);
  stack.Install (server);

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0"); address.Assign (devC1R);
  address.SetBase ("10.1.2.0", "255.255.255.0"); address.Assign (devC2R);
  address.SetBase ("10.1.3.0", "255.255.255.0"); address.Assign (devC3R);
  address.SetBase ("10.1.4.0", "255.255.255.0"); Ipv4InterfaceContainer ipRS = address.Assign (devRS);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  // DualQ AQM Setup (FqPie with Flows = 1)
  TrafficControlHelper tch;
  tch.Uninstall (devRS.Get (0));

  tch.SetRootQueueDisc ("ns3::FqPieQueueDisc",
                        "UseEcn", BooleanValue (true),
                        "UseL4s", BooleanValue (true),
                        "Flows", UintegerValue (1),
                        "CeThreshold", TimeValue (MilliSeconds (1)),
                        "QueueDelayReference", TimeValue (MilliSeconds (15)));

  QueueDiscContainer qdiscs = tch.Install (devRS.Get (0));
  qdiscs.Get (0)->TraceConnectWithoutContext ("Mark", MakeCallback (&TraceEcnMark));
  qdiscs.Get (0)->TraceConnectWithoutContext ("Drop", MakeCallback (&TraceDrop));

  Ipv4Address serverIp = ipRS.GetAddress (1);
  uint16_t portC1 = 8001; uint16_t portC2 = 8002; uint16_t portC3 = 8003;

  // --- C1: Classic Background UDP (6 Mbps) ---
  PacketSinkHelper sinkC1 ("ns3::UdpSocketFactory", InetSocketAddress (serverIp, portC1));
  sinkC1.Install (server).Start (Seconds (0.0));
  OnOffHelper clientC1 ("ns3::UdpSocketFactory", InetSocketAddress (serverIp, portC1));
  clientC1.SetAttribute ("DataRate", DataRateValue (DataRate ("6Mbps")));
  clientC1.SetAttribute ("PacketSize", UintegerValue (1200));
  clientC1.Install (clients.Get (0)).Start (Seconds (0.5));

  // --- C2: Responsive L4S TCP Prague Flow (10 Mbps) ---
  PacketSinkHelper sinkC2 ("ns3::TcpSocketFactory", InetSocketAddress (serverIp, portC2));
  sinkC2.Install (server).Start (Seconds (0.0));
  OnOffHelper clientC2 ("ns3::TcpSocketFactory", InetSocketAddress (serverIp, portC2));
  clientC2.SetAttribute ("DataRate", DataRateValue (DataRate ("10Mbps")));
  clientC2.SetAttribute ("PacketSize", UintegerValue (1000));
  clientC2.Install (clients.Get (1)).Start (Seconds (1.0));

  // --- C3: Video Traffic Setup ---
  PacketSinkHelper sinkC3 ("ns3::UdpSocketFactory", InetSocketAddress (serverIp, portC3));
  sinkC3.Install (server).Start (Seconds (0.0));

  if (scenario == 3)
    {
      Ptr<ResponsiveUdpClient> videoClient = CreateObject<ResponsiveUdpClient> ();
      videoClient->Setup (serverIp, portC3, DataRate ("6Mbps"), 1200);
      clients.Get (2)->AddApplication (videoClient);
      videoClient->SetStartTime (Seconds (2.0));
      videoClient->SetStopTime (Seconds (9.5));
    }
  else
    {
      // Select rate based on Scenario: S5 is rate-capped to 3.5 Mbps
      DataRate videoRate = DataRate ("6Mbps");
      if (scenario == 4) videoRate = DataRate ("12Mbps");
      else if (scenario == 5) videoRate = DataRate ("3.5Mbps"); // Capped L4S Video

      OnOffHelper clientC3 ("ns3::UdpSocketFactory", InetSocketAddress (serverIp, portC3));
      clientC3.SetAttribute ("DataRate", DataRateValue (videoRate));
      clientC3.SetAttribute ("PacketSize", UintegerValue (1200));

      ApplicationContainer appC3 = clientC3.Install (clients.Get (2));
      appC3.Start (Seconds (2.0));

      Ptr<OnOffApplication> onoff = DynamicCast<OnOffApplication> (appC3.Get (0));
      onoff->TraceConnectWithoutContext ("CreatedSocket", MakeCallback (&SetC3SocketTos));
    }

  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll ();

  std::cout << "\n==========================================================\n";
  std::cout << "EXECUTING SCENARIO " << scenario << "\n";
  std::cout << "==========================================================\n";

  Simulator::Stop (Seconds (10.0));
  Simulator::Run ();

  monitor->CheckForLostPackets ();
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();

  for (auto iter = stats.begin (); iter != stats.end (); ++iter)
    {
      auto t = classifier->FindFlow (iter->first);
      if (t.destinationPort != portC1 && t.destinationPort != portC2 && t.destinationPort != portC3)
        continue;

      double duration = iter->second.timeLastRxPacket.GetSeconds () - iter->second.timeFirstTxPacket.GetSeconds ();
      double throughputMbps = (duration > 0) ? (iter->second.rxBytes * 8.0) / (duration * 1e6) : 0.0;
      double avgDelayMs = (iter->second.rxPackets > 0) ? (iter->second.delaySum.GetSeconds () / iter->second.rxPackets) * 1000.0 : 0.0;

      uint32_t txPackets = iter->second.txPackets;
      uint32_t lostPackets = iter->second.lostPackets;
      double lossPercent = (txPackets > 0) ? (static_cast<double>(lostPackets) / txPackets) * 100.0 : 0.0;

      std::string flowName = "";
      if (t.destinationPort == portC1) flowName = "C1: Classic Background";
      else if (t.destinationPort == portC2) flowName = "C2: L4S TCP Prague";
      else if (t.destinationPort == portC3) flowName = "C3: Video Stream";

      std::cout << flowName << ":\n";
      std::cout << "  Tx / Rx Packets : " << txPackets << " / " << iter->second.rxPackets << "\n";
      std::cout << "  Lost Packets    : " << lostPackets << " (" << lossPercent << "%)\n";
      std::cout << "  Throughput      : " << throughputMbps << " Mbps\n";
      std::cout << "  Mean Latency    : " << avgDelayMs << " ms\n";
      std::cout << "----------------------------------------------------------\n";
    }

  std::cout << "DUALQ AQM MARKS & DROPS:\n";
  std::cout << "  Total L4S CE Marks : " << g_l4sEcnMarks << "\n";
  std::cout << "  Total Classic Drops: " << g_classicDrops << "\n";
  std::cout << "==========================================================\n";

  Simulator::Destroy ();
  return 0;
}