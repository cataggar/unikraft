#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -euo pipefail
umask 077
[[ $# == 2 && $1 == /* && $2 == /* && -x $2 ]] || {
	printf 'usage: FRESH_WORKTREE_FIXTURE_DIRECTORY NATIVE_VALIDATOR\n' >&2; exit 1;
}
base=$1 native=$2
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repository=$(cd -- "$here/../../.." && pwd -P)
[[ $base == "$repository/.d/"* && ${native##*/} == uk-hyperv-direct-validate ]] || exit 1
[[ $(head -c 4 "$native" | od -An -tx1 | tr -d ' \n') == 7f454c46 ]] || exit 1
[[ ! -e $base && ! -L $base ]] || exit 1
mkdir -m 0700 "$base"
fake="$here/direct-fixture-tool.sh"
harness="$here/../hyperv-direct-two-boot.sh"
jq=/usr/bin/jq
cases=0
"$jq" -e '
	.resources as $resources |
	($resources | map(select(.type == "Microsoft.Compute/virtualMachines")) | .[0].properties) as $vm |
	($resources | length) == 4 and
	all($resources[]; (.type | contains("publicIPAddresses") | not)) and
	($vm | has("osProfile") | not) and
	$vm.securityProfile.securityType == "Standard" and
	$vm.storageProfile.diskControllerType == "SCSI" and
	$vm.storageProfile.osDisk.createOption == "Attach" and
	$vm.storageProfile.osDisk.caching == "ReadOnly" and
	$vm.storageProfile.osDisk.deleteOption == "Detach" and
	($vm.storageProfile.dataDisks|length) == 1 and
	$vm.storageProfile.dataDisks[0].lun == 7 and
	$vm.storageProfile.dataDisks[0].caching == "None" and
	$vm.storageProfile.dataDisks[0].deleteOption == "Detach" and
	$vm.diagnosticsProfile.bootDiagnostics.enabled == true
' "$here/../../azure/hyperv-direct-two-boot.json" >/dev/null
fixture() {
	local scenario=$1 root="$base/$1"
	mkdir -m 0700 "$root" "$root/ledger"
	printf 'direct-two-boot-offline-only\n' > "$root/ISOLATED_OFFLINE_FIXTURE"
	printf '%s\n' "$scenario" > "$root/scenario"
	printf '{"exists":false,"boots":0,"power":"deallocated"}\n' > "$root/fake-cloud.json"
	: > "$root/calls"
	"$jq" -n --arg root "$root" --argjson expiry "$(($(date +%s) + 3600))" '
		def artifact($name;$size):{path:($root+"/"+$name),size:$size,sha256:("a"*64)};
		{schema:"uk.hyperv.direct-two-boot",version:1,
		 approval:{destructive_data_disk:true,direct_specialized_gen2:true,two_boots_only:true,
		   cleanup_owned_group:true,original_seed_reviewed:true,guarded_native_image_reviewed:true,expires_unix:$expiry},
		 attempt_id:"aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",subscription:"bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
		 location:"fixture",prefix:"fixture-direct",vm_size:"Standard_D2s_v5",
		 run_id:("1"*32),disk_id:("2"*32),controller:"SCSI",lun:7,sectors:8388608,sector_size:512,
		 serial_mode:"per_boot",runtime_seconds:60,cleanup_seconds:60,operation_seconds:10,poll_seconds:1,
		 os_vhd:artifact("os.vhd";1049088),seed_raw:artifact("seed.raw";4294967296),
		 seed_vhd:artifact("seed.vhd";4294967808),manifest:artifact("seed.json";1),config:artifact("config";1)}' \
		> "$root/scope.json"
	for boot in 1 2; do
		local state=0 action=BOOT1_WRITE writes=5 flushes=3
		if [[ $boot == 2 ]]; then state=2 action=BOOT2_READ writes=0 flushes=0; fi
		cat > "$root/boot$boot.log" <<EOF
UK_HYPERV_PLATFORM_READY
HYPERV_PERSISTENCE START PASS run=11111111111111111111111111111111 address=0:0:7 sectors=8388608 sector_size=512
HYPERV_PERSISTENCE SELECT PASS id=1 controller=1 state=$state
UK_HYPERV_PERSISTENCE_IDENTITY:1:2:11111111111111111111111111111111:22222222222222222222222222222222:33333333333333333333333333333333:0:0:7:8388608:512:16:1:3:0:44444444444444444444444444444444
HYPERV_PERSISTENCE $action PASS run=11111111111111111111111111111111
UK_HYPERV_PERSISTENCE_IO:1:$boot:11111111111111111111111111111111:$writes:$flushes:receipt-verified
UK_HYPERV_PERSISTENCE_BOOT${boot}_COMPLETE:11111111111111111111111111111111
HYPERV_PERSISTENCE FINAL PASS rc=0
main returned 0
EOF
	done
}
execute() {
	local root="$base/$1"
	UK_DIRECT_FIXTURE_ROOT="$root" UK_DIRECT_FIXTURE_VALIDATOR="$native" \
		"$harness" "$root/scope.json" "$root/attempt" "$root/ledger" "$fake" "$fake" "$fake" \
		> "$root/public.stdout" 2> "$root/public.stderr"
}
assert_no_secret() {
	local root="$base/$1"
	[[ ! -e $root/attempt/upload-os/sas.txt && ! -e $root/attempt/upload-data/sas.txt ]]
	! grep -R -l 'PRIVATE_FIXTURE_SAS' "$root/attempt" "$root/public.stdout" "$root/public.stderr" >/dev/null
}
for scenario in success lowercase-grant storage-azure-grant cumulative-serial incomplete-serial; do
	fixture "$scenario"
	if [[ $scenario == cumulative-serial ]]; then
		root="$base/$scenario"
		cat "$root/boot1.log" "$root/boot2.log" > "$root/combined.log"
		mv "$root/combined.log" "$root/boot2.log"
		"$jq" '.serial_mode="cumulative"' "$root/scope.json" > "$root/scope-next.json"
		mv "$root/scope-next.json" "$root/scope.json"
	fi
	execute "$scenario"
	root="$base/$scenario"
	"$jq" -e '.accepted == true and .reserved_boots == 2 and .primary_exit == 0 and .cleanup_exit == 0' "$root/attempt/outcome.json" >/dev/null
	first=$(sha256sum "$root/attempt/boot1.log"); first=${first%% *}
	admission=$(sha256sum "$root/attempt/boot2-admission.json"); admission=${admission%% *}
	"$jq" -s -e --arg first "$first" --arg admission "$admission" '
		.[0].boot == 1 and .[1].boot == 2 and
		.[0].serial_sha256 == $first and .[1].original_boot1_sha256 == $first and
		.[1].boot2_admission_sha256 == $admission and .[2].original_boot1_sha256 == $first and
		.[0].vm_uuid == .[1].vm_uuid and .[1].vm_uuid == .[2].vm_uuid and
		.[0].os_uuid == .[1].os_uuid and .[0].data_uuid == .[1].data_uuid and
		.[0].scope_sha256 == .[1].scope_sha256 and .[1].scope_sha256 == .[2].scope_sha256
	' "$root/attempt/boot1-capture.json" "$root/attempt/boot2-capture.json" \
		"$root/attempt/boot2-admission.json" >/dev/null
	for phase in boot1 boot2 retained final; do
		expected=Attached
		if [[ $phase == retained || $phase == final ]]; then expected=Reserved; fi
		"$jq" -s -e --arg expected "$expected" \
			'all(.[]; .diskState == $expected and .managedBy != null)' \
			"$root/attempt/$phase-os.json" "$root/attempt/$phase-data.json" >/dev/null
	done
	[[ $(grep -c '^vm start ' "$root/calls") == 1 ]]
	[[ $(grep -c '^deployment group ' "$root/calls") == 1 ]]
	[[ $(grep -c '^vm deallocate ' "$root/calls") == 2 ]]
	[[ $(grep -c '^transfer$' "$root/calls") == 2 ]]
	assert_no_secret "$scenario"
	if [[ $scenario == success ]]; then
		# A different attempt cannot consume the same persistent seed ledger.
		UK_DIRECT_FIXTURE_ROOT="$root" UK_DIRECT_FIXTURE_VALIDATOR="$native" \
			"$harness" "$root/scope.json" "$root/second-attempt" "$root/ledger" "$fake" "$fake" "$fake" \
			> "$root/second.stdout" 2> "$root/second.stderr" && exit 1
		"$jq" -e '.accepted == false and .reserved_boots == 0' "$root/second-attempt/outcome.json" >/dev/null
	fi
	before=$(wc -l < "$root/calls")
	! execute "$scenario"
	[[ $(wc -l < "$root/calls") == "$before" ]]
	cases=$((cases + 1))
done
for scenario in bad-input preexisting-group both-grants unknown-grant duplicate-grant numeric-exponent \
	upload-failure ambiguous-grant revoke-failure ambiguous-deploy ambiguous-deallocate \
	ambiguous-start identity-drift attachment-mismatch serial-failure boot2-writes \
	cleanup-unowned foreign-resource delete-failure boot1-mutated-before-start \
	boot1-mutated-after-start boot2-admission-mutated stale-boot1-log cumulative-prefix-drift \
	running-reserved retained-attached final-attached retained-unattached; do
	fixture "$scenario"
	if [[ $scenario == cumulative-prefix-drift ]]; then
		root="$base/$scenario"
		cat "$root/boot1.log" "$root/boot2.log" > "$root/combined.log"
		mv "$root/combined.log" "$root/boot2.log"
		"$jq" '.serial_mode="cumulative"' "$root/scope.json" > "$root/scope-next.json"
		mv "$root/scope-next.json" "$root/scope.json"
	fi
	! execute "$scenario"
	root="$base/$scenario"
	"$jq" -e '.accepted == false' "$root/attempt/outcome.json" >/dev/null
	starts=$(grep -c '^vm start ' "$root/calls" || :)
	(( starts <= 1 ))
	[[ $scenario != boot1-mutated-before-start || $starts == 0 ]]
	case $scenario in
		running-reserved|retained-attached|retained-unattached) [[ $starts == 0 ]] ;;
		final-attached) [[ $starts == 1 ]] ;;
	esac
	[[ $(grep -c '^deployment group ' "$root/calls" || :) -le 1 ]]
	case $scenario in
		cleanup-unowned|foreign-resource|identity-drift)
			! grep -q '^group delete ' "$root/calls"
			"$jq" -e '.cleanup_exit != 0' "$root/attempt/outcome.json" >/dev/null ;;
		preexisting-group) ! grep -q '^group create ' "$root/calls" ;;
		bad-input) [[ ! -s $root/calls ]] ;;
		delete-failure) "$jq" -e '.primary_exit == 0 and .cleanup_exit != 0' "$root/attempt/outcome.json" >/dev/null ;;
		*)
			"$jq" -e '.primary_exit != 0 and .owned_group_absent == true' "$root/attempt/outcome.json" >/dev/null ;;
	esac
	assert_no_secret "$scenario"
	cases=$((cases + 1))
done
for scenario in unapproved expired wrong-geometry; do
	fixture "$scenario"
	root="$base/$scenario"
	case $scenario in
		unapproved) filter='.approval.destructive_data_disk=false' ;;
		expired) filter='.approval.expires_unix=1' ;;
		wrong-geometry) filter='.sectors=4096' ;;
	esac
	"$jq" "$filter" "$root/scope.json" > "$root/scope-next.json"
	mv "$root/scope-next.json" "$root/scope.json"
	! execute "$scenario"
	[[ ! -s $root/calls && ! -d $root/ledger/attempt-aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa ]]
	cases=$((cases + 1))
done
printf 'PASS: %s isolated direct lifecycle fixtures (no real CLI, transfer, network, or disks).\n' "$cases"
