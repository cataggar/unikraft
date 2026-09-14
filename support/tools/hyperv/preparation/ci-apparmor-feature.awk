# AppArmor securityfs feature booleans use yes/no, not sysctl integers.
{
  if (++records != 1 || $0 != "yes") invalid = 1
}
END {
  exit(invalid || records != 1)
}
