module SimplePing
  class SockAddressLL
    # @param [String] if_name "eth0"
    def initialize(if_name)
      @if_name = if_name
    end

    # Used for Socket#bind
    # @return [String]
    def to_pack_from
      sll_family = [Socket::AF_PACKET].pack("S")
      sll_protocol = [0x0800].pack("S>") # htons(ETH_P_IP)
      sll_ifindex = [if_name_to_index(@if_name)].pack("i")
      sll_hatype = [1].pack("S") # ARPHRD_ETHER
      sll_pkttype = [1].pack("C") # PACKET_BROADCAST
      sll_halen = [6].pack("C") # ETH_ALEN
      sll_addr = if_name_to_mac_adress(@if_name) + [0].pack("C") * 2

      sll_family + sll_protocol + sll_ifindex + sll_hatype + \
        sll_pkttype + sll_halen + sll_addr
    end

    private

    # @param [String] if_name "eth0"
    # @return [Integer] 2
    def if_name_to_index(if_name)
      Socket.getifaddrs.find do |ifaddr|
        ifaddr.name == if_name
      end&.ifindex
    end

    # @param [String] if_name "eth0"
    # @return [String] "\n\x16S\xD0\xFC\x80"
    def if_name_to_mac_adress(if_name)
      sockaddr = Socket.getifaddrs
                        .select { |a| a.name == if_name.to_s }
                        .map(&:addr)
                        .find { |a| a.pfamily == Socket::PF_PACKET }
                        .to_sockaddr
      sockaddr[-6..-1]
    end
  end
end
