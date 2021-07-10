require "logger"
require "socket"
require "timeout"
require_relative "util"
require_relative "recv_message"
require_relative "icmp"
require_relative "ip"
require_relative "ether"
require_relative "sock_address_ll"

# Simple Ping (ICMP) client
# Root privilege required to run
# ex)
#   require_relative "./simple_ping/client"
#
#   client = SimplePing::Client.new(src_ip_addr: "192.168.1.100")
#   client.exec(dest_ip_addr: "192.168.1.101") # => true or false
module SimplePing
  ARPHRD_ETHER = 1
  ARPOP_REQUEST = 1
  ETH_ALEN = 6
  ETH_P_ARP = [0x0806].pack("S>").unpack1("S")
  ETH_P_IP = 0x0800
  ETH_TYPE_NUMBER_ARP = 0x0806
  PACKET_BROADCAST = 1
  PACKET_HOST = 0
  TIMEOUT_TIME = 3

  class Client
    # Wait time for ICMP Reply
    TIMEOUT_TIME = 10
    ETH_TYPE_NUMBER_ARP = 0x0800
    SOL_PACKET            = 0x0107 # bits/socket.h
    IFINDEX_SIZE          = 0x0004 # sizeof(ifreq.ifr_ifindex) on 64bit
    IFREQ_SIZE            = 0x0028 # sizeof(ifreq) on 64bit
    SIOCGIFINDEX          = 0x8933 # bits/ioctls.h
    PACKET_MR_PROMISC     = 0x0001 # netpacket/packet.h
    PACKET_MREQ_SIZE      = 0x0010 # sizeof(packet_mreq) on 64bit
    PACKET_ADD_MEMBERSHIP = 0x0001 # netpacket/packet.h

    # constructor
    #
    # @param src_ip_addr [String] IP address of the interface to send ping,  ex: "192.168.1.100"
    def initialize(src_ip_addr:, src_if_name:, dst_ip_addr:, dst_mac_addr:, log_level: Logger::INFO)
      @src_ip_addr = src_ip_addr
      @log_level = log_level
      @src_if_name = src_if_name
      @dst_ip_addr = dst_ip_addr
      @dst_mac_addr = dst_mac_addr
    end

    def bind_if(socket)
      sll = SimplePing::SockAddressLL.new(@src_if_name).to_pack_from
      socket.bind(sll)
    end

    # Execute ping(ICMP).
    # Basically, it returns Boolean depending on the result.
    # Exception may be thrown due to unexpected error etc.
    #
    # @param dest_ip_addr [String] IP address of destination to send ping, ex: "192.168.1.101"
    # @param data         [String] ICMP Datagram, ex: "abc"
    # @return             [Boolean]
    def exec(dest_ip_addr:, data: nil)
      # Transmission
      icmp = SimplePing::ICMP.new(type: SimplePing::ICMP::TYPE_ICMP_ECHO_REQUEST, data: data)
      ether_header = SimplePing::EtherHeader.new(@src_if_name, @dst_mac_addr).to_pack

      version = 4 # 4bit
      header_length = 5 # 4bit
      tos = 0 # 1Byte, diffserf も入ってる(6bit)
      total_length = 20 + 8 + data.size
      id = 15637 # 2Byte
      flags = 2 # 3bit
      fragment = 0 # 13bit
      time_to_live = 255 # 1Byte
      protocol = 1 # 1Byte, ICMP

      ip_header = SimplePing::IPHeader.new(
        version: version,
        header_length: header_length,
        tos: tos,
        total_length: total_length,
        id: id,
        flags: flags,
        fragment: fragment,
        time_to_live: time_to_live,
        protocol: protocol,
        src_addr: @src_ip_addr,
        dst_addr: @dst_ip_addr
      ).to_pack

      trans_data = ether_header + ip_header + icmp.to_trans_data # ★
      bind_if(socket)
      socket.send(trans_data, 0)
      # Receive
      begin
        Timeout.timeout(TIMEOUT_TIME) do
          mesg, _ = socket.recvfrom(1500)
          icmp_reply = SimplePing::RecvMessage.new(mesg).to_icmp

          if icmp.successful_reply?(icmp_reply)
            true
          elsif icmp_reply.is_type_destination_unreachable?
            logger.warn { "Destination Unreachable!!" }
            false
          elsif icmp_reply.is_type_redirect?
            logger.warn { "Redirect Required!!" }
            false
          end
        end
      rescue Timeout::Error => e
        logger.warn { "Timeout Occurred! #{e}" }
        false
      end
    end

    private

    # @return [Logger]
    def logger
      @logger ||= begin
        logger = Logger.new(STDOUT)
        logger.level = @log_level
        logger
      end
    end

    # Socket instance
    #
    # @return [Socket]
    def socket
      @socket ||= Socket.open(
        Socket::AF_PACKET,
        Socket::SOCK_RAW,     # RAW Socket
        0x0800 #Socket::ETH_P_IP  # ICMP, 何でもいいっぽい
      )
    end
  end
end
