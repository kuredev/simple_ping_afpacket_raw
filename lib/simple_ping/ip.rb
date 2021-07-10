require "ipaddr"

module SimplePing
  class IPHeader
    def initialize(version:, header_length:, tos:, total_length:,
                   id:, flags:, fragment:, time_to_live:, protocol:,
                   src_addr:, dst_addr:)
      @version = version
      @header_length = header_length
      @tos = tos
      @total_length = total_length
      @id = id
      @flags = flags
      @fragment = fragment
      @time_to_live = time_to_live
      @protocol = protocol
      @src_addr = src_addr
      @dst_addr = dst_addr

      @checksum = checksum
    end

    def carry_up(num)
      carry_up_num = num.length - 16
      original_value = num[carry_up_num, 16]
      carry_up_value = num[0, carry_up_num]
      sum = original_value.to_i(2) + carry_up_value&.to_i(2)
      result = sum ^ 0xffff
      result
    end

    def checksum
      d16bit_version_headerl_tos_str = @version.to_s(2).rjust(4, "0") +
                                      @header_length.to_s(2).rjust(4, "0") +
                                      @tos.to_s(2).rjust(8, "0")
      d16bit_total_length = @total_length
      d16bit_id = @id # Integer
      d16bit_flag_fragment_str = @flags.to_s(2).rjust(3, "0") +
                            @fragment.to_s(2).rjust(13, "0")
      d16bit_ttl_protocol = @time_to_live.to_s(2).rjust(8, "0") +
                           @protocol.to_s(2).rjust(8, "0")
      d16bit_checksum = 0
      d16bit_src_addr_s1 = ::IPAddr.new(@src_addr).to_i.to_s(2).rjust(32, "0").byteslice(0, 16)
      d16bit_src_addr_s2 = ::IPAddr.new(@src_addr).to_i.to_s(2).rjust(32, "0").byteslice(16, 16)
      d16bit_dst_addr_s1 = ::IPAddr.new(@dst_addr).to_i.to_s(2).rjust(32, "0").byteslice(0, 16)
      d16bit_dst_addr_s2 = ::IPAddr.new(@dst_addr).to_i.to_s(2).rjust(32, "0").byteslice(16, 16)

      sum_16bit = d16bit_version_headerl_tos_str.to_i(2) +
                  d16bit_total_length +
                  d16bit_id +
                  d16bit_flag_fragment_str.to_i(2) +
                  d16bit_ttl_protocol.to_i(2) +
                  d16bit_src_addr_s1.to_i(2) +
                  d16bit_src_addr_s2.to_i(2) +
                  d16bit_dst_addr_s1.to_i(2) +
                  d16bit_dst_addr_s2.to_i(2)

      carry_up(sum_16bit.to_s(2).rjust(16, "0"))
    end

    def to_pack
      bynary_data =
        @version.to_s(2).rjust(4, "0") +
        @header_length.to_s(2).rjust(4, "0") +
        @tos.to_s(2).rjust(8, "0") +
        @total_length.to_s(2).rjust(16, "0") +
        @id.to_s(2).rjust(16, "0") +
        @flags.to_s(2).rjust(3, "0") +
        @fragment.to_s(2).rjust(13, "0") +
        @time_to_live.to_s(2).rjust(8, "0") +
        @protocol.to_s(2).rjust(8, "0") +
        @checksum.to_s(2).rjust(16, "0") +
        ::IPAddr.new(@src_addr).to_i.to_s(2).rjust(32, "0") +
        ::IPAddr.new(@dst_addr).to_i.to_s(2).rjust(32, "0")

      data_byte_arr = bynary_data.scan(/.{1,8}/)
      data_byte_arr.map! { |byte| byte.to_i(2).chr } # TO ASCII
      data_byte_arr.join
    end
  end

end
