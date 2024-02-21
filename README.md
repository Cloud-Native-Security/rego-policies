# Argo Workflows Rego

## Resources
Argo Quickstart https://argo-workflows.readthedocs.io/en/latest/quick-start/
Structure of a Workflow: https://argo-workflows.readthedocs.io/en/latest/walk-through/the-structure-of-workflow-specs/ 

## Misconfiguration Scanning Argo Workflows

```
cd argo-workflows

trivy config --policy ./policies --namespaces custom ./example-workflow.yaml
```