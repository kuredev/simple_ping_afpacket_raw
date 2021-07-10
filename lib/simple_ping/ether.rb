# struct ether_header
# { 14Byte
#   u_int8_t  ether_dhost[ETH_ALEN]; 6Byte
#   u_int8_t  ether_shost[ETH_ALEN]; 6Byte
#   u_int16_t ether_type; 2Byte
# }
module SimplePing
  class EtherHeader
    include SimplePing::Util
    ETH_TYPE_NUMBER_ARP = 0x0800 # IPv4

    # ex:
    # if_name: "eth0"
    # dst_addr: "00:22:22:22:22:22"
    def initialize(if_name, dst_addr)
      @if_name = if_name
      @dst_addr = dst_addr
    end

    def to_pack
      ether_dhost = @dst_addr.split(":").map { |n| [n.to_i(16)].pack("C") }.join
      ether_shost = if_name_to_mac_adress(@if_name)
      ether_type = [ETH_TYPE_NUMBER_ARP].pack("S>")

      ether_dhost + ether_shost + ether_type
    end
  end
end
