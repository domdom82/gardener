bit = require("bit")

function cidr_contains(cidr, ip)
  -- Split the CIDR into the base IP and the subnet mask length
  local baseIp, maskLength = cidr:match("^(%d+%.%d+%.%d+%.%d+)/(%d+)$")
  maskLength = tonumber(maskLength)

  if not baseIp or not maskLength or maskLength < 0 or maskLength > 32 then
      return false
  end

  -- Convert the base IP and the given IP to 32-bit numbers
  local baseIpNum = ip_to_number(baseIp)
  local ipNum = ip_to_number(ip)

  if not baseIpNum or not ipNum then
      return false
  end

  -- Calculate the subnet mask as a 32-bit number
  local mask = bit.bxor((2^(32 - maskLength) - 1), 0xFFFFFFFF)

  -- Check if the IP is in the range
  return bit.band(baseIpNum, mask) == bit.band(ipNum, mask)
end

function is_ipv4(address)
  if type(address) ~= "string" then
      return false
  end
  local octets = { address:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$") }
  if #octets ~= 4 then
      return false
  end
  for _, octet in ipairs(octets) do
      local num = tonumber(octet)
      -- Each octet must be a number between 0 and 255
      if not num or num < 0 or num > 255 then
          return false
      end
  end
  return true
end
function ip_to_number(ip)
  local octets = { ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$") }
  if #octets ~= 4 then
      return nil
  end
  local num = 0
  for i, octet in ipairs(octets) do
      local value = tonumber(octet)
      if not value or value < 0 or value > 255 then
          return nil
      end
      num = num * 256 + value
  end
  return num
end
function number_to_ip(num)
  local octet4 = math.floor(num / (256 ^ 3)) % 256
  local octet3 = math.floor(num / (256 ^ 2)) % 256
  local octet2 = math.floor(num / 256) % 256
  local octet1 = num % 256

  return string.format("%d.%d.%d.%d", octet4, octet3, octet2, octet1)
end
function netmap(ip, cidr)
  -- Split the CIDR into the base IP and the subnet mask length
  local baseIp, maskLength = cidr:match("^(%d+%.%d+%.%d+%.%d+)/(%d+)$")
  maskLength = tonumber(maskLength)

  if not baseIp or not maskLength or maskLength < 0 or maskLength > 32 then
      return nil, "Invalid CIDR range"
  end

  -- Convert the IP and the base IP to 32-bit numbers
  local ipNum = ip_to_number(ip)
  local baseIpNum = ip_to_number(baseIp)

  if not ipNum or not baseIpNum then
      return nil, "Invalid IP address"
  end

  -- Calculate the subnet mask as a 32-bit number
  local mask = bit.bxor((2^(32 - maskLength) - 1), 0xFFFFFFFF)

  -- Map the IP onto the CIDR range
  local mappedIpNum = bit.bor(bit.band(baseIpNum, mask), bit.band(ipNum, bit.bnot(mask)))
  return number_to_ip(mappedIpNum)
end

function envoy_on_request(request_handle)
  local shoot_pod_range = request_handle:metadata():get("shoot_pod_range")
  local shoot_service_range = request_handle:metadata():get("shoot_service_range")
  local shoot_node_range = request_handle:metadata():get("shoot_node_range")
  local shoot_pod_range_mapped = "244.0.0.0/8"
  local shoot_service_range_mapped = "243.0.0.0/8"
  local shoot_node_range_mapped = "242.0.0.0/8"

  -- Get the host from the CONNECT request
  local target = request_handle:headers():get(":authority")
  request_handle:logDebug("target is " .. target)
  if target then
    local ip, port = string.match(target, "([^:]+):?(%d*)")
    if ip then
      -- Check if ip is v4
      if is_ipv4(ip) then
        local new_target = target
        -- Find mapping range
        if cidr_contains(shoot_pod_range, ip) then
          new_target = netmap(ip, shoot_pod_range_mapped)
        elseif cidr_contains(shoot_service_range, ip) then
            new_target = netmap(ip, shoot_service_range_mapped)
        elseif cidr_contains(shoot_node_range, ip) then
            new_target = netmap(ip, shoot_node_range_mapped)
        end
        -- Add port again
        if port and port ~= "" then
          new_target = new_target .. ":" .. port
        end
        request_handle:logDebug("new target is " .. new_target)
        -- Set the rewritten target
        request_handle:headers():replace(":authority", new_target)
      end
    end
  end
end
