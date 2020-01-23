module RackCAS
  class SAMLValidationResponse
    class AuthenticationFailure < StandardError; end
    class TicketInvalidError < AuthenticationFailure; end

    REQUEST_HEADERS = {
      'Accept' => '*/*',
      'Content-Type' => 'application/soap+xml; charset=utf-8'
    }

    def initialize(url, ticket)
      @url = URL.parse(url)
      @ticket = ticket
    end

    def user
      if success?
        xml_text_at('//Response/Assertion/AuthenticationStatement/Subject/NameIdentifier')
      else
        raise AuthenticationFailure, failure_message
      end
    end

    def extra_attributes
      attrs = {}

      raise AuthenticationFailure, failure_message unless success?

      attribute_statement = xml.at('//Response/Assertion/AttributeStatement')
      return unless attribute_statement

      attribute_statement.children.each do |node|
        key = node.at('@AttributeName')

        if key
          values = node.xpath('AttributeValue').map(&:text)

          values = values.first if values.size == 1

          attrs[key.text] = values
        end
      end

      attrs
    end

    protected

    def success?
      @success ||= xml_text_at('//Response/Status/StatusCode/@Value') =~ /saml1?p:Success/
    end

    def authentication_failure
      @authentication_failure ||= !@success
    end

    def failure_message
      if authentication_failure
        xml_text_at('//Response/Status/StatusMessage').strip
      end
    end

    def response
      require 'net/http'
      return @response unless @response.nil?

      http = Net::HTTP.new(@url.host, @url.inferred_port)

      if @url.scheme == 'https'
        http.use_ssl = true
        http.verify_mode = RackCAS.config.verify_ssl_cert? ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
      end

      now = Time.now

      data = %Q~<?xml version='1.0'?>
      <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
        <SOAP-ENV:Header/>
        <SOAP-ENV:Body>
          <samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="_#{ip_address}.#{now.to_i}" IssueInstant="#{now.strftime("%FT%TZ")}">
            <samlp:AssertionArtifact>#{@ticket}</samlp:AssertionArtifact>
          </samlp:Request>
        </SOAP-ENV:Body>
      </SOAP-ENV:Envelope>~

      begin
        @response = http.post(@url.request_uri, data, REQUEST_HEADERS)
      rescue Net::ReadTimeout
        @response = nil
        raise(AuthenticationFailure, "Net::ReadTimeout: ticket '#{@ticket}' not recognized")
      end

      @response
    end

    def xml
      return @xml unless @xml.nil?

      @xml = Nokogiri::XML(response.body).remove_namespaces!
    end

    def xml_text_at(path)
      element = xml.at(path)
      return unless element

      element.text
    end

    def ip_address
      require 'socket'

      return @ip_address unless @ip_address.nil?

      begin
        @ip_address = Socket.ip_address_list.detect{ |intf|
            intf.ipv4? and !intf.ipv4_loopback? and !intf.ipv4_multicast? and !intf.ipv4_private?
          }.ip_address
      rescue
        @ip_address = '127.0.0.1'
      end
    end
  end
end
