# Only journalctl -k output from the bounded baseline time window is eligible.
/(^|[[:space:]])apparmor="DENIED"([[:space:]]|$)/ &&
/(^|[[:space:]])comm="uk-prep-ns-test"([[:space:]]|$)/ &&
/(^|[[:space:]])profile="unprivileged_userns"([[:space:]]|$)/ &&
/(^|[[:space:]])operation="capable"([[:space:]]|$)/ &&
/(^|[[:space:]])capability=21([[:space:]]|$)/ &&
/(^|[[:space:]])capname="sys_admin"([[:space:]]|$)/ {
    if (length($0) > 4096 || ++matched > 8) exit 1
    print
}
END {
    if (matched == 0) exit 1
}
