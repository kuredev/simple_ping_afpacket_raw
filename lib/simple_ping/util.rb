module SimplePing
  module Util
    private

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
