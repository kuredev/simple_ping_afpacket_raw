# Class that stores the received message
# Implements a method to retrieve the ICMP header
class SimplePing::RecvMessage
  ether_header_size = 14
  ip_header_size = 20

  # constructor
  #
  # @param [String] mesg
  def initialize(mesg)
    mesg_length = mesg.length
    @icmp_mesg = mesg.byteslice(34, mesg_length - 34)
  end

  # Code
  #
  # @return [Integer]
  def code
    @icmp_mesg[1].bytes[0]
  end

  # ID
  #
  # @return [Integer]
  def id
    (@icmp_mesg[4].bytes[0] << 8) + @icmp_mesg[5].bytes[0]
  end

  # Data
  #
  # @return [String]
  def data
    @icmp_mesg[8, @icmp_mesg.length.to_i - 8]
  end

  # sequence numebr
  #
  # @return [Integer]
  def seq_number
    (@icmp_mesg[6].bytes[0] << 8) + @icmp_mesg[7].bytes[0]
  end

  # create icmp object
  #
  # @return [SimplePing::ICMP]
  def to_icmp
    icmp = SimplePing::ICMP.new(code: code, type: type)
    if icmp.is_type_echo?
      icmp.id = id
      icmp.seq_number = seq_number
      icmp.data = data
    end
    icmp
  end

  # Type
  #
  # @return [Integer]
  def type
    @icmp_mesg[0].bytes[0]
  end
end
