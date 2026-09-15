#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Deliberately isolated fake CLI / transfer / input-reader. It has no delegation
# to Azure, networking, production transfer, or disk devices.
set -euo pipefail
umask 077
root=${UK_DIRECT_FIXTURE_ROOT:?isolated fixture root required}
[[ $root == /* && -d $root && -f $root/ISOLATED_OFFLINE_FIXTURE && ! -L $root ]] || exit 90
[[ $(cat "$root/ISOLATED_OFFLINE_FIXTURE") == direct-two-boot-offline-only ]] || exit 90
jq=/usr/bin/jq
state="$root/fake-cloud.json"
scenario=$(cat "$root/scenario")
if [[ ${0##*/} == sha256sum ]]; then
	[[ $# == 2 && $1 == -- && $2 == "$root/"* ]] || exit 90
	/usr/bin/sha256sum "$@"
	reads=$("$jq" -r '.boot2_reads // 0' "$state")
	if [[ $scenario == cache-hash-error && $2 == "$root/attempt/boot2-candidate.log" ]] ||
		{ (( reads >= 2 )) && {
			[[ $scenario == cache-binding-hash-error && $2 == "$root/attempt/boot1.log" ]] ||
			[[ $scenario == cache-admission-hash-error && $2 == "$root/attempt/boot2-admission.json" ]];
		}; }; then
		printf 'fixture hash read failed\n' >&2
		exit 17
	fi
	exit
fi
native=${UK_DIRECT_FIXTURE_VALIDATOR:?native serial validator required}
[[ $native == /* && -x $native ]] || exit 90
[[ ${native##*/} == uk-hyperv-direct-validate ]] || exit 90
for arg in "$@"; do [[ $arg != *PRIVATE_FIXTURE_SAS* ]] || exit 91; done
case ${1:-} in
	scope|ledger|json)
		[[ $2 == "$root/"* ]] || exit 90
		"$native" "$@"
		exit ;;
	inputs)
		[[ $2 == "$root/"* ]] || exit 90
		"$jq" -e --arg root "$root/" \
			'[.os_vhd,.seed_raw,.seed_vhd,.config,.manifest] | all(.[]; .path|startswith($root))' "$2" >/dev/null
		[[ $scenario != bad-input ]]
		exit ;;
	serial)
		[[ $2 == "$root/"* && $3 == "$root/"* ]] || exit 90
		printf 'validator serial\n' >> "$root/calls"
		"$native" "$@"
		exit ;;
	transfer)
		[[ $# == 3 && $2 == "$root/attempt/upload-"* && $3 == job.json ]] || exit 90
		[[ $(stat -c %a "$2") == 700 && $(stat -c %a "$2/sas.txt") == 600 ]] || exit 91
		[[ $(cat "$2/sas.txt") == sv=fixture\&sig=PRIVATE_FIXTURE_SAS ]] || exit 91
		"$jq" -e --arg root "$root/" '.path|startswith($root)' "$2/request.json" >/dev/null
		printf '%s\n' transfer >> "$root/calls"
		[[ $scenario != upload-failure ]] || exit 12
		printf '%s\n' '{"succeeded":true}'
		exit ;;
esac
[[ ${AZURE_CORE_COLLECT_TELEMETRY:-} == 0 ]] || exit 91
cmd=$1 action=$2
shift 2
name= group= size=0
while (( $# )); do
	case $1 in
		--name) name=$2; shift 2 ;;
		--resource-group) group=$2; shift 2 ;;
		--upload-size-bytes) size=$2; shift 2 ;;
		--disk-size-gb) exit 92 ;;
		*) shift ;;
	esac
done
printf '%s %s %s\n' "$cmd" "$action" "$name" >> "$root/calls"
scope="$root/scope.json"
prefix=$("$jq" -r .prefix "$scope")
owner=$("$jq" -r .attempt_id "$scope")
sha=$("$jq" -r .os_vhd.sha256 "$scope")
sub=$("$jq" -r .subscription "$scope")
base="/subscriptions/$sub/resourceGroups/$prefix-rg"
vm_id="$base/providers/Microsoft.Compute/virtualMachines/$prefix-vm"
tags=$("$jq" -n --arg prefix "$prefix" --arg owner "$owner" --arg sha "$sha" \
	'{"managed-by":"unikraft-hyperv","uk-direct-run":$owner,"unikraft-run":$prefix,"image-sha256":$sha}')
mutate() {
	"$jq" "$@" "$state" > "$root/state-next.json"
	mv "$root/state-next.json" "$state"
}
disk() {
	local role=$1
	local uuid="original-$role" logical=4294967296 os=null gen=null
	[[ $role != os ]] || { logical=1048576; os='"Linux"'; gen='"V2"'; }
	if [[ $scenario == identity-drift && $role == data && $("$jq" -r .boots "$state") == 2 ]]; then uuid=replacement; fi
	if [[ $scenario == diagnostics-disk-identity-drift && $role == data &&
		$("$jq" -r '.cleanup // false' "$state") == true ]]; then uuid=replacement; fi
	"$jq" -n --argjson state "$(cat "$state")" --arg role "$role" --arg base "$base" \
		--arg prefix "$prefix" --argjson tags "$tags" --arg uuid "$uuid" --arg vm "$vm_id" \
		--argjson logical "$logical" --argjson os "$os" --argjson gen "$gen" --arg scenario "$scenario" '
		(if $state.boots == 0 then
		   if $state[$role].uploaded then "Unattached" else "ReadyToUpload" end
		 elif $state.power == "deallocated" then "Reserved" else "Attached" end) as $normal |
		(if $scenario == "running-reserved" and $role == "data" and $normal == "Attached" then "Reserved"
		 elif $scenario == "retained-attached" and $role == "data" and $state.boots == 1 and $normal == "Reserved" then "Attached"
		 elif $scenario == "final-attached" and $role == "os" and $state.boots == 2 and $normal == "Reserved" then "Attached"
		 elif $scenario == "retained-unattached" and $role == "data" and $state.boots == 1 and $normal == "Reserved" then "Unattached"
		 else $normal end) as $disk_state |
		{id:($base+"/providers/Microsoft.Compute/disks/"+$prefix+"-"+$role),name:($prefix+"-"+$role),
		 type:"Microsoft.Compute/disks",tags:$tags,uniqueId:$uuid,osType:$os,hyperVGeneration:$gen,
		 sku:{name:"StandardSSD_LRS"},logicalSectorSize:"512",diskSizeBytes:($logical|tostring),
		 diskState:$disk_state,
		 managedBy:(if $state.boots > 0 then $vm else null end),
		 creationData:{createOption:"Upload",uploadSizeBytes:
		  (if $scenario == "numeric-exponent" then "1e6" else ($logical+512|tostring) end)}}'
}
virtual_machine() {
	local os_id="$base/providers/Microsoft.Compute/disks/$prefix-os"
	local data_id="$base/providers/Microsoft.Compute/disks/$prefix-data"
	local uuid=original-vm vm_size=Standard_D2s_v5
	[[ $scenario != attachment-mismatch ]] || data_id="$base/providers/Microsoft.Compute/disks/replacement"
	[[ $scenario != diagnostics-unknown-vm ]] || vm_size=unapproved-size
	if [[ $scenario == diagnostics-vm-identity-drift &&
		$("$jq" -r '.cleanup // false' "$state") == true ]]; then uuid=replacement; fi
	"$jq" -n --arg vm "$vm_id" --arg prefix "$prefix" --arg base "$base" --argjson tags "$tags" \
		--arg os "$os_id" --arg data "$data_id" --arg uuid "$uuid" --arg size "$vm_size" '
		{id:$vm,name:($prefix+"-vm"),type:"Microsoft.Compute/virtualMachines",tags:$tags,vmId:$uuid,
		 securityProfile:{securityType:"Standard"},hardwareProfile:{vmSize:$size},
		 diagnosticsProfile:{bootDiagnostics:{enabled:true}},
		 networkProfile:{networkInterfaces:[{id:($base+"/providers/Microsoft.Network/networkInterfaces/"+$prefix+"-nic")}]},
		 storageProfile:{diskControllerType:"SCSI",osDisk:{createOption:"Attach",caching:"ReadOnly",
		   deleteOption:"Detach",managedDisk:{id:$os}},
		   dataDisks:[{lun:"7",createOption:"Attach",caching:"None",deleteOption:"Detach",managedDisk:{id:$data}}]}}'
}
case "$cmd $action" in
	"group exists")
		[[ $scenario != preexisting-group ]] || { printf 'true\n'; exit; }
		"$jq" .exists "$state" ;;
	"group create")
		mutate '.exists=true'
		"$jq" -n --arg id "$base" --argjson tags "$tags" '{id:$id,tags:$tags}' ;;
	"group show")
		date +%s > "$root/cleanup.seconds"
		mutate '.cleanup=true'
		[[ $("$jq" -r .exists "$state") == true ]] || exit 3
		[[ $scenario != cleanup-unowned && $scenario != diagnostics-unowned-group ]] || tags='{}'
		"$jq" -n --arg id "$base" --argjson tags "$tags" '{id:$id,tags:$tags}' ;;
	"group delete")
		date +%s > "$root/delete.seconds"
		[[ $scenario != delete-failure && $scenario != diagnostics-delete-failure &&
			$scenario != diagnostics-read-delete-failure ]] || exit 17
		mutate '.exists=false' ;;
	"disk create")
		role=${name##*-}
		mutate --arg role "$role" '.[$role]={created:true,uploaded:false}'
		printf '{}\n' ;;
	"disk show")
		disk "${name##*-}" ;;
	"disk grant-access")
		[[ $scenario != ambiguous-grant ]] || exit 18
		case $scenario in
			lowercase-grant) printf '{"accessSas":"https://fixture.blob.core.windows.net/upload?sv=fixture&sig=PRIVATE_FIXTURE_SAS"}\n' ;;
			storage-azure-grant) printf '{"accessSAS":"https://md-fixture.z99.blob.storage.azure.net/upload?sv=fixture&sig=PRIVATE_FIXTURE_SAS"}\n' ;;
			duplicate-grant) printf '{"accessSAS":"first","accessSAS":"second"}\n' ;;
			both-grants) printf '{"accessSAS":"secret","accessSas":"secret"}\n' ;;
			unknown-grant) printf '{"accessSAS":"secret","unexpected":true}\n' ;;
			*) printf '{"accessSAS":"https://fixture.blob.core.windows.net/upload?sv=fixture&sig=PRIVATE_FIXTURE_SAS"}\n' ;;
		esac ;;
	"disk revoke-access")
		[[ $scenario != revoke-failure ]] || { printf 'InvalidVhd\n' >&2; exit 19; }
		mutate --arg role "${name##*-}" '.[$role].uploaded=true' ;;
	"deployment group")
		mutate '.boots=1 | .power="running"'
		[[ $scenario != ambiguous-deploy ]] || exit 20
		printf '{}\n' ;;
	"vm show") virtual_machine ;;
	"vm get-instance-view")
		boot=$("$jq" -r .boots "$state")
		power=$("$jq" -r .power "$state")
		case "$scenario:$boot:$power" in
			stopped-boot1:1:running|stopped-boot2:2:running|stopped-both:*:running|stopped-bad-serial:1:running)
				power=stopped ;;
			unexpected-boot1-power:1:running|diagnostics-*:1:running) power=starting ;;
			unexpected-boot2-power:2:running) power=deallocating ;;
			retained-stopped:1:deallocated|final-stopped:2:deallocated) power=stopped ;;
		esac
		"$jq" -n --arg power "$power" --arg scenario "$scenario" '
			{instanceView:{statuses:[{code:"ProvisioningState/succeeded"},
			  {code:(if $scenario == "malformed-power" then null else "PowerState/"+$power end)}]}}' ;;
	"vm deallocate")
		mutate '.power="deallocated"'
		if [[ $scenario == boot1-mutated-before-start && $("$jq" -r .boots "$state") == 1 ]]; then
			printf 'benign-looking appended line\n' >> "$root/attempt/boot1.log"
		fi
		[[ $scenario != ambiguous-deallocate ]] || exit 21 ;;
	"vm start")
		[[ $("$jq" -r .boots "$state") == 1 ]] || exit 93
		[[ -f $root/attempt/boot2-admission.json ]]
		"$jq" -e --arg vm "$vm_id" \
			'.reserved_boots == 2 and .vm_id == $vm and (.original_boot1_sha256|length) == 64' \
			"$root/attempt/boot2-admission.json" >/dev/null
		date +%s > "$root/boot2-start.seconds"
		mutate '.boots=2 | .power="running" | .boot2_reads=0'
		if [[ $scenario == boot2-admission-mutated ]]; then
			printf ' \n' >> "$root/attempt/boot2-admission.json"
		fi
		[[ $scenario != ambiguous-start ]] || exit 22 ;;
	"vm boot-diagnostics")
		boot=$("$jq" -r .boots "$state")
		if [[ $("$jq" -r '.cleanup // false' "$state") == true ]]; then
			printf 'failure diagnostics\n' >> "$root/calls"
			date +%s > "$root/diagnostics.seconds"
			case $scenario in
				diagnostics-read-failure|diagnostics-read-delete-failure)
					printf 'fixture diagnostic read failure\n' >&2; exit 23 ;;
				diagnostics-decode-failure) printf '{"unexpected":"not a JSON string"}\n'; exit ;;
				diagnostics-timeout) sleep 35 ;;
			esac
			"$jq" -Rs . "$root/boot$boot.log"
			exit
		fi
		if [[ $boot == 2 ]]; then
			mutate '.boot2_reads += 1'
			reads=$("$jq" -r .boot2_reads "$state")
			case $scenario in
				boot1-mutated-after-start) printf 'benign-looking appended line\n' >> "$root/attempt/boot1.log" ;;
				stale-boot1-log) "$jq" -Rs . "$root/boot1.log"; exit ;;
				azure-cached-then-fresh)
					if (( reads == 1 )); then "$jq" -Rs . "$root/boot1.log"; exit; fi ;;
				azure-no-advance-then-fresh)
					case $reads in
						1) "$jq" -Rs . "$root/boot1-body.log"; exit ;;
						2) { cat "$root/boot1-body.log"; printf '\0'; } | "$jq" -Rs .; exit ;;
						3) "$jq" -Rs . "$root/boot1.log"; exit ;;
					esac ;;
				azure-padding-only)
					{ cat "$root/boot1-body.log"; printf '\0'; } | "$jq" -Rs .; exit ;;
				azure-prefix-changed)
					sed '1s/UK_HYPERV_PLATFORM_READY/UK_HYPERV_PLATFORM_DRIFT/' "$root/boot2.log" |
						"$jq" -Rs .; exit ;;
				azure-prefix-truncated)
					head -c -1 "$root/boot1-body.log" | "$jq" -Rs .; exit ;;
				azure-interior-nul-removed)
					tr -d '\000' < "$root/boot2.log" | "$jq" -Rs .; exit ;;
				azure-missing-prefix) "$jq" -Rs . "$root/boot2-body.log"; exit ;;
				azure-wrong-boot)
					cat "$root/boot1-body.log" "$root/boot1.log" | "$jq" -Rs .; exit ;;
				different-boot1-log|cumulative-different-boot1)
					sed 's/SELECT PASS id=1/SELECT PASS id=2/' "$root/boot1.log" | "$jq" -Rs .
					exit ;;
				cumulative-prefix-drift)
					sed '1s/UK_HYPERV_PLATFORM_READY/UK_HYPERV_PLATFORM_DRIFT/' "$root/boot2.log" |
						"$jq" -Rs .; exit ;;
			esac
			case $scenario in
				cached-then-fresh|cumulative-cached-then-fresh|cache-*)
					if (( reads == 1 )); then "$jq" -Rs . "$root/boot1.log"; exit; fi
					case $scenario in
						cache-boot1-mutated) printf 'changed during cache wait\n' >> "$root/attempt/boot1.log" ;;
						cache-capture-mutated) printf ' \n' >> "$root/attempt/boot1-capture.json" ;;
						cache-scope-mutated) printf ' \n' >> "$root/attempt/scope.json" ;;
						cache-admission-mutated) printf ' \n' >> "$root/attempt/boot2-admission.json" ;;
						cache-then-wrong-identity)
							sed 's/44444444444444444444444444444444/55555555555555555555555555555555/' "$root/boot2.log" |
								"$jq" -Rs .; exit ;;
						cache-then-failure) printf '"UK_HYPERV_ACCEPTANCE_FAIL:fixture\\n"\n'; exit ;;
					esac
					if [[ $scenario == cache-* ]]; then "$jq" -Rs . "$root/boot1.log"; exit; fi
					;;
			esac
		fi
		if [[ $boot == 1 && ( $scenario == azure-all-zero-boot1 || $scenario == azure-incomplete-boot1 ) ]]; then
			mutate '.serial_reads = ((.serial_reads // 0) + 1)'
			if [[ $("$jq" -r .serial_reads "$state") == 1 ]]; then
				if [[ $scenario == azure-all-zero-boot1 ]]; then printf '\0\0'
				else printf 'UK_HYPERV_PLATFORM_READY\n\0\0'; fi | "$jq" -Rs .
			else printf '"UK_HYPERV_ACCEPTANCE_FAIL:fixture\\n"\n'; fi
			exit
		fi
		if [[ $scenario == incomplete-serial && $("$jq" -r '.serial_reads // 0' "$state") == 0 ]]; then
			mutate '.serial_reads=1'
			printf '""\n'
			exit
		fi
		[[ $scenario != serial-failure && $scenario != stopped-bad-serial ]] ||
			{ printf '"UK_HYPERV_ACCEPTANCE_FAIL:fixture\\n"\n'; exit; }
		[[ $scenario != boot2-writes || $boot != 2 ]] || {
			sed 's/:2:11111111111111111111111111111111:0:0:/:2:11111111111111111111111111111111:1:0:/' "$root/boot2.log" |
				"$jq" -Rs .; exit;
		}
		"$jq" -Rs . "$root/boot$boot.log" ;;
	"resource list")
		{
			for role in os data; do
				[[ $("$jq" -r --arg role "$role" '.[$role].created // false' "$state") != true ]] || disk "$role"
			done
			[[ $("$jq" -r .boots "$state") == 0 ]] || virtual_machine
			[[ $scenario != foreign-resource && $scenario != diagnostics-foreign-resource ]] ||
				printf '{"id":"foreign","name":"foreign","type":"Microsoft.Compute/disks","tags":{}}\n'
		} | "$jq" -s . ;;
	*) exit 94 ;;
esac
