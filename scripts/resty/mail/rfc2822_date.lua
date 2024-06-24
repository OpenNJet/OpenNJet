local MONTHS = {
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
}

local WDAYS = {
  "Sun",
  "Mon",
  "Tue",
  "Wed",
  "Thu",
  "Fri",
  "Sat",
}

-- Output a date and time in RFC 2822 compliant format.
--
-- This ensures the month and day of week are output in the compliant English
-- format (instead of relying on os.date, which can be affected by the current
-- system's locale).
return function(time)
  local data = os.date("*t", time)
  local month = MONTHS[data["month"]]
  local wday = WDAYS[data["wday"]]
  return os.date(wday .. ", %d " .. month .. " %Y %H:%M:%S %z", time)
end
