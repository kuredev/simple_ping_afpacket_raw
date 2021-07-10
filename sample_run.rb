require_relative "./lib/simple_ping"

ping_client = SimplePing::Client.new(
                src_ip_addr: "172.31.34.23",
                src_if_name: "eth2",
                dst_ip_addr: "172.31.34.243",
                dst_mac_addr: "aa:aa:aa:aa:aa:aa"
              )
data = "a" * 30
pp ping_client.exec(dest_ip_addr: nil, data: data)
