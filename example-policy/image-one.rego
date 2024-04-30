# METADATA
# title: Verify Image
# description: Verify Image is allowed to be used and in the right format
# schemas:
#   - input: schema["dockerfile"]
# custom:
#   id: ID001
#   severity: MEDIUM
#   input:
#     selector: 
#     - type: dockerfile

package custom.dockerfile.ID001

import future.keywords.in

allowed_images :=  {
    ["node:21-alpine3.19", "as", "build-deps"],
    ["nginx:1.24"]
}

deny[msg] {
    input.Stages[m].Commands[l].Cmd == "from"
    val := input.Stages[m].Commands[l].Value
    not val in allowed_images
    msg := sprintf("The container image '%s' used in the Dockerfile is not allowed", val)
}