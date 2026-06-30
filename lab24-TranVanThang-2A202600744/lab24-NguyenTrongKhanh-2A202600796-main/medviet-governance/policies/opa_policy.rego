package medviet.data_access

import future.keywords.if
import future.keywords.in

default allow := false
default deny := false

# Restricted data may never be exported outside Vietnamese infrastructure.
deny if {
    input.action == "export"
    input.data_classification == "restricted"
    input.destination_country != "VN"
}

# Keep this explicit prohibition for auditability even though default-deny also
# prevents the request.
deny if {
    input.user.role == "ml_engineer"
    input.resource == "production_data"
    input.action == "delete"
}

# Admin can perform any operation which is not explicitly denied above.
allow if {
    not deny
    input.user.role == "admin"
}

# ML Engineers can read/write only model-training resources.
allow if {
    not deny
    input.user.role == "ml_engineer"
    input.resource in {"training_data", "model_artifacts"}
    input.action in {"read", "write"}
}

allow if {
    not deny
    input.user.role == "ml_engineer"
    input.resource == "aggregated_metrics"
    input.action == "read"
}

# Data Analysts can read aggregate metrics and write reports only.
allow if {
    not deny
    input.user.role == "data_analyst"
    input.resource == "aggregated_metrics"
    input.action == "read"
}

allow if {
    not deny
    input.user.role == "data_analyst"
    input.resource == "reports"
    input.action == "write"
}

# Interns are isolated to the sandbox.
allow if {
    not deny
    input.user.role == "intern"
    input.resource == "sandbox_data"
    input.action in {"read", "write"}
}
