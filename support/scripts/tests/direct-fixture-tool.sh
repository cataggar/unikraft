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
	[[ $scenario != attachment-mismatch ]] || data_id="$base/providers/Microsoft.Compute/disks/replacement"
	"$jq" -n --arg vm "$vm_id" --arg prefix "$prefix" --arg base "$base" --argjson tags "$tags" \
		--arg os "$os_id" --arg data "$data_id" '
		{id:$vm,name:($prefix+"-vm"),type:"Microsoft.Compute/virtualMachines",tags:$tags,vmId:"original-vm",
		 securityProfile:{securityType:"Standard"},hardwareProfile:{vmSize:"Standard_D2s_v5"},
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
		[[ $("$jq" -r .exists "$state") == true ]] || exit 3
		[[ $scenario != cleanup-unowned ]] || tags='{}'
		"$jq" -n --arg id "$base" --argjson tags "$tags" '{id:$id,tags:$tags}' ;;
	"group delete")
		[[ $scenario != delete-failure ]] || exit 17
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
		"$jq" '{instanceView:{statuses:[{code:("PowerState/"+.power)}]}}' "$state" ;;
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
		mutate '.boots=2 | .power="running"'
		if [[ $scenario == boot2-admission-mutated ]]; then
			printf ' \n' >> "$root/attempt/boot2-admission.json"
		fi
		[[ $scenario != ambiguous-start ]] || exit 22 ;;
	"vm boot-diagnostics")
		boot=$("$jq" -r .boots "$state")
		if [[ $boot == 2 ]]; then
			case $scenario in
				boot1-mutated-after-start) printf 'benign-looking appended line\n' >> "$root/attempt/boot1.log" ;;
				stale-boot1-log) "$jq" -Rs . "$root/boot1.log"; exit ;;
				cumulative-prefix-drift)
					sed '1s/UK_HYPERV_PLATFORM_READY/UK_HYPERV_PLATFORM_DRIFT/' "$root/boot2.log" |
						"$jq" -Rs .; exit ;;
			esac
		fi
		if [[ $scenario == incomplete-serial && $("$jq" -r '.serial_reads // 0' "$state") == 0 ]]; then
			mutate '.serial_reads=1'
			printf '""\n'
			exit
		fi
		[[ $scenario != serial-failure ]] || { printf '"UK_HYPERV_ACCEPTANCE_FAIL:fixture\\n"\n'; exit; }
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
			[[ $scenario != foreign-resource ]] || printf '{"id":"foreign","name":"foreign","type":"Microsoft.Compute/disks","tags":{}}\n'
		} | "$jq" -s . ;;
	*) exit 94 ;;
esac
