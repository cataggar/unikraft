.schema == "hyperv_preparation_namespace_ci_baseline_v1" and
.authority == "synthetic_only" and .process_cleanup_complete == true and
.helper_exit == 125 and .namespace_succeeded == false and
(.namespace_error == "namespace_unavailable" or
 .namespace_error == "mount_namespace_unavailable" or
 .namespace_error == "user_mapping_unavailable")
