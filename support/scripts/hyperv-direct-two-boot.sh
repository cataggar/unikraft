#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -euo pipefail
umask 077
export LC_ALL=C

die() { printf '%s\n' "direct two-boot refused: $1" >&2; exit 1; }
[[ $# == 6 ]] || die "usage: SCOPE_JSON FRESH_ATTEMPT_DIR SEED_LEDGER_DIR AZ_PATH UPLOADER_PATH VALIDATOR_PATH"
scope=$1 run=$2 ledger=$3 az=$4 uploader=$5 validator=$6
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
azure="$here/../azure"
jq=/usr/bin/jq
for tool in "$az" "$uploader" "$validator" "$jq"; do
	[[ $tool == /* && -f $tool && -x $tool ]] || die "explicit executable required"
done
for path in "$scope" "$run" "$ledger"; do
	[[ $path == /* && $path != *$'\n'* && $path != *$'\r'* ]] || die "absolute private paths required"
done
[[ ! -e $run && ! -L $run ]] || die "attempt already exists; resume is forbidden"
[[ -d $ledger && ! -L $ledger && $(stat -c %a "$ledger") == 700 && $(stat -c %u "$ledger") == "$(id -u)" ]] ||
	die "existing owner-private seed ledger required"
mkdir -m 0700 -- "$run"
exec 3>"$run/driver.stderr"
# Raw CLI/account/ARM/native diagnostics never reach the terminal.
exec 2>&3
"$validator" scope "$scope" > "$run/source-scope-check.stdout"
"$validator" ledger "$scope" "$ledger" > "$run/ledger-check.stdout"
cp -- "$scope" "$run/scope.json"
chmod 0600 "$run/scope.json"
scope="$run/scope.json"
"$validator" scope "$scope" > "$run/scope-check.stdout"
get() { "$jq" -er "$1" "$scope"; }
subscription=$(get .subscription)
owner=$(get .attempt_id)
prefix=$(get .prefix)
location=$(get .location)
vm_size=$(get .vm_size)
image_sha=$(get .os_vhd.sha256)
seed_sha=$(get .seed_vhd.sha256)
storage_run=$(get .run_id)
storage_disk=$(get .disk_id)
group="$prefix-rg"
vm="$prefix-vm"
group_id="/subscriptions/$subscription/resourceGroups/$group"
vm_id="$group_id/providers/Microsoft.Compute/virtualMachines/$vm"
os_id="$group_id/providers/Microsoft.Compute/disks/$prefix-os"
data_id="$group_id/providers/Microsoft.Compute/disks/$prefix-data"
nic_id="$group_id/providers/Microsoft.Network/networkInterfaces/$prefix-nic"
runtime=$(get .runtime_seconds)
cleanup_seconds=$(get .cleanup_seconds)
operation=$(get .operation_seconds)
poll_seconds=$(get .poll_seconds)
expires=$(get .approval.expires_unix)
[[ $(date +%s) -lt $expires ]] || die "approval expired"
deadline=$((SECONDS + runtime))
cleanup_lane=false
phase=local-admission
boots=0 group_intended=0 cleanup_exit=0 absent=false accepted=false
grant_os=0 grant_data=0
os_uuid= data_uuid= vm_uuid=
boot1_sha= boot1_capture_sha= admission_sha=
scope_sha=$(sha256sum -- "$scope")
scope_sha=${scope_sha%% *}
tags=("uk-direct-run=$owner" "unikraft-run=$prefix" "image-sha256=$image_sha" "managed-by=unikraft-hyperv")

event() {
	phase=$1
	"$jq" -cn --arg phase "$phase" --argjson boots "$boots" \
		'{phase:$phase,reserved_boots:$boots}' >> "$run/events.jsonl"
	sync -f "$run/events.jsonl"
}
bounded() {
	local limit=$((deadline - SECONDS))
	(( limit > 0 )) || return 124
	(( limit <= operation )) || limit=$operation
	timeout --kill-after=2s "${limit}s" "$@"
}
az_call() {
	local label=$1
	shift
	if [[ $cleanup_lane != true ]]; then
		[[ $(date +%s) -lt $expires ]] || return 125
	fi
	(
		ulimit -f 8192
		bounded env AZURE_CORE_COLLECT_TELEMETRY=0 "$az" "$@" \
			--subscription "$subscription" --only-show-errors --output json
	) > "$run/$label.json" 2> "$run/$label.stderr"
}
check() {
	local file=$1 filter=$2
	shift 2
	"$jq" -e -L "$azure" "$@" "include \"direct-two-boot\"; $filter" "$run/$file.json" >/dev/null
}
ownership() {
	check "$1" 'owned($id; $owner; $prefix; $sha)' \
		--arg id "$2" --arg owner "$owner" --arg prefix "$prefix" --arg sha "$image_sha"
}
group_absent() {
	az_call "$1" group exists --name "$group" && check "$1" '. == false'
}
inventory_owned() {
	check "$1" '
		type == "array" and all(.[];
			(.type | ascii_downcase) as $type |
			.name as $name |
			(($type == "microsoft.compute/disks" and ($name == ($prefix+"-os") or $name == ($prefix+"-data"))) or
			 ($type == "microsoft.compute/virtualmachines" and $name == ($prefix+"-vm")) or
			 ($type == "microsoft.network/networkinterfaces" and $name == ($prefix+"-nic")) or
			 ($type == "microsoft.network/networksecuritygroups" and $name == ($prefix+"-nsg")) or
			 ($type == "microsoft.network/virtualnetworks" and $name == ($prefix+"-vnet"))) and
			(.id | ascii_downcase) == (($group + "/providers/" + .type + "/" + .name) | ascii_downcase) and
			.tags["uk-direct-run"] == $owner and .tags["unikraft-run"] == $prefix and
			.tags["image-sha256"] == $sha and .tags["managed-by"] == "unikraft-hyperv")' \
		--arg group "$group_id" --arg owner "$owner" --arg prefix "$prefix" --arg sha "$image_sha"
}
cleanup_identities() {
	local role expected uuid
	for role in os data; do
		if [[ $role == os ]]; then expected=$os_id; uuid=$os_uuid
		else expected=$data_id; uuid=$data_uuid; fi
		if [[ -n $uuid ]]; then
			az_call "cleanup-$role-identity" disk show --resource-group "$group" --name "$prefix-$role" || return
			ownership "cleanup-$role-identity" "$expected" || return
			check "cleanup-$role-identity" '
				.uniqueId == $uuid and (.managedBy == null or .managedBy == $vm)' \
				--arg uuid "$uuid" --arg vm "$vm_id" || return
		fi
	done
	if [[ -n $vm_uuid ]]; then
		az_call cleanup-vm-identity vm show --resource-group "$group" --name "$vm" || return
		ownership cleanup-vm-identity "$vm_id" || return
		check cleanup-vm-identity '.vmId == $uuid' --arg uuid "$vm_uuid" || return
	fi
}
cleanup() {
	local primary=$? prior_phase=$phase
	trap - EXIT HUP INT TERM
	set +e
	deadline=$((SECONDS + cleanup_seconds))
	cleanup_lane=true
	event cleanup-intent || cleanup_exit=1
	if (( group_intended )); then
		if az_call cleanup-group group show --name "$group" && ownership cleanup-group "$group_id"; then
			# A failed revoke (including InvalidVhd on an empty upload) is a
			# cleanup failure, but must not prevent safe group deletion.
			for role in os data; do
				local granted=0 expected= current_uuid=
				if [[ $role == os ]]; then granted=$grant_os; expected=$os_id; current_uuid=$os_uuid
				else granted=$grant_data; expected=$data_id; current_uuid=$data_uuid; fi
				if (( granted )); then
					if az_call "cleanup-$role-observed" disk show --resource-group "$group" --name "$prefix-$role" &&
						ownership "cleanup-$role-observed" "$expected" &&
						check "cleanup-$role-observed" '.uniqueId == $uuid' --arg uuid "$current_uuid"; then
						az_call "cleanup-$role-revoke" disk revoke-access --resource-group "$group" --name "$prefix-$role" ||
							cleanup_exit=1
					else cleanup_exit=1; fi
				fi
			done
			if az_call cleanup-inventory resource list --resource-group "$group" &&
				inventory_owned cleanup-inventory && cleanup_identities; then
				event cleanup-delete-intent || cleanup_exit=1
				az_call cleanup-delete group delete --name "$group" --yes || cleanup_exit=1
				# Even a lost delete response needs an independent absence read.
				if group_absent cleanup-absent; then absent=true; else cleanup_exit=1; fi
			else cleanup_exit=1; fi
		elif group_absent cleanup-absent; then absent=true
		else cleanup_exit=1; fi
	fi
	# Never retain usable SAS or raw grant/error responses after termination.
	rm -f -- "$run"/upload-{os,data}/sas.txt "$run"/grant-{os,data}.{json,stderr} || cleanup_exit=1
	sync -f "$run" || cleanup_exit=1
	if [[ -e $run/upload-os/sas.txt || -e $run/upload-data/sas.txt ||
		-e $run/grant-os.json || -e $run/grant-data.json ||
		-e $run/grant-os.stderr || -e $run/grant-data.stderr ]]; then cleanup_exit=1; fi
	if ! bounded "$validator" inputs "$scope" > "$run/final-input-check.stdout" 2> "$run/final-input-check.stderr"; then
		cleanup_exit=1
	fi
	"$jq" -n --arg phase "$prior_phase" --argjson primary "$primary" --argjson cleanup "$cleanup_exit" \
		--argjson boots "$boots" --argjson absent "$absent" --argjson accepted "$accepted" --argjson created "$group_intended" \
		'{phase:$phase,primary_exit:$primary,cleanup_exit:$cleanup,reserved_boots:$boots,
		  persistence_evidence_complete:$accepted,owned_group_absent:$absent,
		  group_creation_attempted:($created == 1),
		  accepted:($primary == 0 and $cleanup == 0 and $accepted and $absent)}' > "$run/outcome.json"
	local recording=$?
	sync -f "$run/outcome.json" || recording=1
	if (( primary != 0 )); then exit "$primary"; fi
	(( cleanup_exit == 0 && recording == 0 )) || exit 1
	printf '%s\n' "Direct two-boot persistence evidence passed; owned group independently absent."
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

event local-admission
bounded "$validator" inputs "$scope" > "$run/input-check.stdout" 2> "$run/input-check.stderr"
# Both the semantic seed identity and exact VHD digest are consume-once names.
# mkdir is atomic; every earlier claim survives failure, SIGKILL, and cleanup.
mkdir -m 0700 -- "$ledger/attempt-$owner"
mkdir -m 0700 -- "$ledger/$storage_run-$storage_disk"
mkdir -m 0700 -- "$ledger/sha256-$seed_sha"
cp -- "$scope" "$ledger/$storage_run-$storage_disk/consumed.json"
sync -f "$ledger/$storage_run-$storage_disk/consumed.json"
sync -f "$ledger"
event seed-consumed
group_absent group-before || die "group preexists or absence is uncertain"
event group-create-intent
group_intended=1
az_call group-created group create --name "$group" --location "$location" --tags "${tags[@]}"
ownership group-created "$group_id"

upload() {
	local role=$1 field=$2 expected=$3
	local path size sha uuid
	path=$(get ".$field.path") size=$(get ".$field.size") sha=$(get ".$field.sha256")
	mkdir -m 0700 "$run/upload-$role"
	event "$role-create-intent"
	local extra=()
	[[ $role != os ]] || extra=(--os-type Linux --hyper-v-generation V2)
	az_call "$role-created" disk create --resource-group "$group" --name "$prefix-$role" --location "$location" \
		--upload-type Upload --upload-size-bytes "$size" --sku StandardSSD_LRS "${extra[@]}" --tags "${tags[@]}"
	az_call "$role-before-upload" disk show --resource-group "$group" --name "$prefix-$role"
	ownership "$role-before-upload" "$expected"
	check "$role-before-upload" '
		.diskState == "ReadyToUpload" and .creationData.createOption == "Upload" and
		(.creationData.uploadSizeBytes|uint) == $size and .sku.name == "StandardSSD_LRS" and
		(.logicalSectorSize == null or (.logicalSectorSize|uint) == 512) and
		(.uniqueId|type == "string" and length > 0) and
		(if $role == "os" then .osType == "Linux" and .hyperVGeneration == "V2" else .osType == null end)' \
		--argjson size "$size" --arg role "$role"
	uuid=$("$jq" -er .uniqueId "$run/$role-before-upload.json")
	if [[ $role == os ]]; then os_uuid=$uuid; grant_os=1; else data_uuid=$uuid; grant_data=1; fi
	event "$role-grant-intent"
	az_call "grant-$role" disk grant-access --resource-group "$group" --name "$prefix-$role" \
		--access-level Write --duration-in-seconds 1800
	bounded "$validator" json "$scope" "$run/grant-$role.json" \
		> "$run/$role-grant-check.stdout" 2> "$run/$role-grant-check.stderr"
	# The query and the JSON grant stay in private files, never shell variables,
	# argv, or environment. Only the native uploader reads sas.txt.
	"$jq" -erj -L "$azure" 'include "direct-two-boot"; grant | split("?")[1]' \
		"$run/grant-$role.json" > "$run/upload-$role/sas.txt"
	"$jq" -e -L "$azure" --arg path "$path" --arg sha "$sha" --argjson size "$size" \
		'include "direct-two-boot"; grant | split("?")[0] |
		{schema:"unikraft.hyperv.managed-disk-page-worker",schema_version:1,
		 endpoint:.,path:$path,size:$size,sha256:$sha}' \
		"$run/grant-$role.json" > "$run/upload-$role/request.json"
	local transfer_limit=$((deadline - SECONDS))
	(( transfer_limit <= operation )) || transfer_limit=$operation
	# Leave the native supervisor its own five-second cleanup before the
	# independent outer deadline; never kill it at its execution deadline.
	(( transfer_limit >= 8 )) || die "insufficient native transfer budget"
	"$jq" -n --argjson timeout "$((transfer_limit * 1000 - 7000))" \
		'{contract:"uk.hyperv.transfer-job",schema_version:1,kind:"pages",request:"request.json",
		  sas:"sas.txt",timeout_ms:$timeout,cleanup_ms:5000}' > "$run/upload-$role/job.json"
	event "$role-native-upload-intent"
	bounded "$uploader" transfer "$run/upload-$role" job.json \
		> "$run/$role-transfer.json" 2> "$run/$role-transfer.stderr"
	event "$role-revoke-intent"
	az_call "$role-revoked" disk revoke-access --resource-group "$group" --name "$prefix-$role"
	az_call "$role-after-upload" disk show --resource-group "$group" --name "$prefix-$role"
	ownership "$role-after-upload" "$expected"
	check "$role-after-upload" '
		.uniqueId == $uuid and .diskState == "Unattached" and .managedBy == null and
		(.diskSizeBytes|uint) == $logical' --arg uuid "$uuid" --argjson logical "$((size - 512))"
	if [[ $role == os ]]; then grant_os=0; else grant_data=0; fi
	rm -f -- "$run/upload-$role/sas.txt" "$run/grant-$role.json" "$run/grant-$role.stderr"
}
upload os os_vhd "$os_id"
upload data seed_vhd "$data_id"

observe() {
	local label=$1 power=$2 disk_state
	case $power in
		running) disk_state=Attached ;;
		deallocated) disk_state=Reserved ;;
		*) die "unsupported observation power state" ;;
	esac
	az_call "$label-vm" vm show --resource-group "$group" --name "$vm"
	ownership "$label-vm" "$vm_id"
	check "$label-vm" '
		.osProfile == null and .securityProfile.securityType == "Standard" and
		.hardwareProfile.vmSize == $size and
		.diagnosticsProfile.bootDiagnostics.enabled == true and
		.diagnosticsProfile.bootDiagnostics.storageUri == null and
		.storageProfile.diskControllerType == "SCSI" and
		.storageProfile.osDisk.createOption == "Attach" and .storageProfile.osDisk.caching == "ReadOnly" and
		.storageProfile.osDisk.deleteOption == "Detach" and .storageProfile.osDisk.managedDisk.id == $os and
		(.storageProfile.dataDisks|length) == 1 and
		(.storageProfile.dataDisks[0] |
		  (.lun|uint) == 7 and .createOption == "Attach" and .caching == "None" and
		  .deleteOption == "Detach" and .managedDisk.id == $data) and
		(.networkProfile.networkInterfaces|length) == 1 and .networkProfile.networkInterfaces[0].id == $nic and
		(.vmId|type == "string" and length > 0) and ($uuid == "" or .vmId == $uuid)' \
		--arg size "$vm_size" --arg os "$os_id" --arg data "$data_id" --arg nic "$nic_id" --arg uuid "$vm_uuid"
	vm_uuid=$("$jq" -er .vmId "$run/$label-vm.json")
	for role in os data; do
		local expected uuid bytes
		if [[ $role == os ]]; then expected=$os_id; uuid=$os_uuid; bytes=$(get .os_vhd.size)
		else expected=$data_id; uuid=$data_uuid; bytes=$(get .seed_vhd.size); fi
		az_call "$label-$role" disk show --resource-group "$group" --name "$prefix-$role"
		ownership "$label-$role" "$expected"
		check "$label-$role" '
			.uniqueId == $uuid and .managedBy == $vm and .diskState == $state and
			(.diskSizeBytes|uint) == $bytes' --arg uuid "$uuid" --arg vm "$vm_id" \
			--arg state "$disk_state" --argjson bytes "$((bytes - 512))"
	done
	az_call "$label-power" vm get-instance-view --resource-group "$group" --name "$vm"
	check "$label-power" 'power == $expected' --arg expected "PowerState/$power"
}
digest() {
	bounded sha256sum -- "$1" | cut -d ' ' -f 1
}
verify_boot1() {
	[[ -n $boot1_sha && -n $boot1_capture_sha &&
		$(digest "$run/boot1.log") == "$boot1_sha" &&
		$(digest "$run/boot1-capture.json") == "$boot1_capture_sha" &&
		$(digest "$scope") == "$scope_sha" ]] || die "original Boot1 evidence or scope changed"
}
capture_record() {
	local boot=$1 count=$2 serial_sha raw_sha observed mode
	serial_sha=$(digest "$run/boot$boot.log")
	raw_sha=$(digest "$run/boot$boot-serial-$count.json")
	observed=$(digest "$run/boot$boot-vm.json")
	mode=$(get .serial_mode)
	if [[ $boot == 2 ]]; then
		verify_boot1
		[[ -n $admission_sha && $(digest "$run/boot2-admission.json") == "$admission_sha" ]] ||
			die "Boot2 admission changed"
	else boot1_sha=$serial_sha; fi
	(
		set -C
		"$jq" -n --argjson boot "$boot" --argjson poll "$count" --arg mode "$mode" \
			--arg sha "$serial_sha" --arg raw "$raw_sha" --arg scope "$scope_sha" \
			--arg vm "$vm_id" --arg uuid "$vm_uuid" --arg os "$os_id" --arg os_uuid "$os_uuid" \
			--arg data "$data_id" --arg data_uuid "$data_uuid" --arg first "$boot1_sha" --arg admission "$admission_sha" \
			--arg observed "$observed" \
			'{schema:"uk.hyperv.direct-serial-capture",version:1,boot:$boot,poll:$poll,serial_mode:$mode,
			  serial_sha256:$sha,cli_wrapper_sha256:$raw,scope_sha256:$scope,vm_id:$vm,vm_uuid:$uuid,
			  os_id:$os,os_uuid:$os_uuid,data_id:$data,data_uuid:$data_uuid,vm_observation_sha256:$observed,
			  original_boot1_sha256:$first,boot2_admission_sha256:$admission}' > "$run/boot$boot-capture.json"
	)
	sync -f "$run/boot$boot-capture.json"
	if [[ $boot == 1 ]]; then
		boot1_sha=$serial_sha
		boot1_capture_sha=$(digest "$run/boot1-capture.json")
	fi
}
admit_boot2() {
	local vm_read os_read data_read power
	verify_boot1
	vm_read=$(digest "$run/retained-vm.json")
	os_read=$(digest "$run/retained-os.json")
	data_read=$(digest "$run/retained-data.json")
	power=$(digest "$run/retained-power.json")
	(
		set -C
		"$jq" -n --arg scope "$scope_sha" --arg first "$boot1_sha" --arg capture "$boot1_capture_sha" \
			--arg vm "$vm_id" --arg uuid "$vm_uuid" --arg os "$os_id" --arg os_uuid "$os_uuid" \
			--arg data "$data_id" --arg data_uuid "$data_uuid" \
			--arg vm_read "$vm_read" --arg os_read "$os_read" --arg data_read "$data_read" --arg power "$power" \
			'{schema:"uk.hyperv.direct-boot2-admission",version:1,reserved_boots:2,
			  scope_sha256:$scope,original_boot1_sha256:$first,boot1_capture_sha256:$capture,
			  vm_id:$vm,vm_uuid:$uuid,os_id:$os,os_uuid:$os_uuid,data_id:$data,data_uuid:$data_uuid,
			  retained_vm_sha256:$vm_read,retained_os_sha256:$os_read,retained_data_sha256:$data_read,
			  deallocated_power_sha256:$power}' > "$run/boot2-admission.json"
	)
	sync -f "$run/boot2-admission.json"
	admission_sha=$(digest "$run/boot2-admission.json")
}
serial() {
	local boot=$1 count=0 result
	while (( SECONDS < deadline && count < 60 )); do
		count=$((count + 1))
		if az_call "boot$boot-serial-$count" vm boot-diagnostics get-boot-log --resource-group "$group" --name "$vm"; then
			[[ $(stat -c %s "$run/boot$boot-serial-$count.json") -le 8388608 ]] || die "serial wrapper too large"
			"$jq" -erj 'if type == "string" then . else error("serial wrapper") end' \
				"$run/boot$boot-serial-$count.json" > "$run/boot$boot-candidate.log"
			result=0
			if [[ $boot == 1 ]]; then
				bounded "$validator" serial "$scope" "$run/boot1-candidate.log" \
					> "$run/serial-check.stdout" 2> "$run/serial-check.stderr" || result=$?
			else
				verify_boot1
				bounded "$validator" serial "$scope" "$run/boot1.log" "$run/boot2-candidate.log" \
					> "$run/serial-check.stdout" 2> "$run/serial-check.stderr" || result=$?
			fi
			if (( result == 0 )); then
				mv -- "$run/boot$boot-candidate.log" "$run/boot$boot.log"
				sync -f "$run/boot$boot.log"
				capture_record "$boot" "$count"
				return
			fi
			(( result == 2 )) || die "guest serial rejected"
		fi
		bounded sleep "$poll_seconds"
	done
	return 1
}

"$jq" -n --arg prefix "$prefix" --arg location "$location" --arg owner "$owner" --arg sha "$image_sha" \
	--arg os "$os_id" --arg data "$data_id" --arg size "$vm_size" \
	'{parameters:{namePrefix:{value:$prefix},location:{value:$location},ownerRun:{value:$owner},
	  imageSha256:{value:$sha},osDiskId:{value:$os},dataDiskId:{value:$data},vmSize:{value:$size}}}' \
	> "$run/deployment-parameters.json"
boots=1
event boot1-deploy-intent
az_call deployment deployment group create --resource-group "$group" --name "$prefix" \
	--template-file "$azure/hyperv-direct-two-boot.json" --parameters "@$run/deployment-parameters.json"
observe boot1 running
serial 1
event boot1-evidence-complete
event deallocate-intent
az_call deallocated vm deallocate --resource-group "$group" --name "$vm"
observe retained deallocated
bounded "$validator" inputs "$scope" > "$run/retained-input-check.stdout" 2> "$run/retained-input-check.stderr"
[[ $(date +%s) -lt $expires ]] || die "approval expired before Boot2"
boots=2
admit_boot2
event boot2-start-intent
# There is exactly one start call. An ambiguous response exits into cleanup.
az_call started vm start --resource-group "$group" --name "$vm"
observe boot2 running
serial 2
event boot2-evidence-complete
event final-deallocate-intent
az_call final-deallocated vm deallocate --resource-group "$group" --name "$vm"
observe final deallocated
verify_boot1
accepted=true
event persistence-evidence-complete
