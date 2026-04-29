math.randomseed(os.time())

request = function()
  local roll = math.random(100)
  if roll <= 90 then
    return wrk.format("GET", "/small")
  end
  if roll <= 99 then
    return wrk.format("GET", "/medium")
  end
  return wrk.format("GET", "/big")
end
