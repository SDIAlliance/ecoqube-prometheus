# SDIA ECOQUBE

## Architecture

The ECOQUBE infrastructure consists of several components for each environment:

* AWS VPC, Subnets, etc.
* EKS Kubernetes Cluster
* ASG for Kubernetes worker nodes
* EFS & S3

The environment is hosted in AWS Region eu-central-1 (Frankfurt)

## Deployment

All AWS resources and Kubernetes services are deployed using Github Actions.

* `terraform` is used to deploy all AWS resources
* `kubectl` is used to deploy all Kubernetes system services
* `helm` is used to deploy Thanos and Grafana

## Data Persistence

Thanos uses an S3 bucket for long term durable data storage. 
Kubernetes persistent volume claims are stored on EFS.

## Configuration & Operation

### Github Actions

Github Actions are defined in `.github/workflows/aws_deployment.yaml`.

Scripts used to configure Kubernetes, Thanos & Grafana are stored in `scripts/`

#### Github & AWS Integration

Github uses federated OIDC auth to assume an IAM role in the SDIA AWS Account to deploy the AWS resources and to access the Terraform state S3 bucket & DynamoDB table.

The necessary IAM roles, S3 bucket and DynamoDB table are created through Cloudformation. The template can be found in `cf/`.

Updates to the Cloudformation stack can be performed using the AWS cli, for example:
`aws cloudformation deploy --template ecoqube-github-integration.yaml --stack-name ecoqube-github-integration --capabilities CAPABILITY_NAMED_IAM --region eu-central-1`

### Terraform

Terraform variables are defined in `tf/config/<ENV>.tfvars`.

### Kubernetes

Kubernetes templates can be found in `k8s/`.

All YAML files with suffix `_envsubst` are processed with the `envsubst` utility to substitute environment variables set at build time!

### Thanos & Grafana (Helm)

Thanos and Grafana are installed using the Bitnami Helm charts:

https://github.com/bitnami/charts/tree/master/bitnami/thanos

https://github.com/bitnami/charts/tree/master/bitnami/grafana

Helm config files for Thanos and Grafana can be found in `ecoqube/`

All YAML files with suffix `_envsubst` are processed with the `envsubst` utility to substitute environment variables set at build time!

To configure the Thanos data source in Grafana check the procedure as described here: https://docs.bitnami.com/tutorials/create-multi-cluster-monitoring-dashboard-thanos-grafana-prometheus/

The password for the Grafana `admin` user should be defined as a SecureString SSM Parameter named: `/ecoqube/<ENV>/env/grafana_admin_password`

The whitelist can be configured through the option `alb.ingress.kubernetes.io/inbound-cidrs` in the Helm config files

### Ingress

External ingress is configured using the `AWS Load Balancer Controller` in Kubernetes: https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.2/guide/ingress/annotations/

The settings can be found in the Helm configuration files for Thanos and Grafana mentioned above

### Kubernetes Cluster Access

The `kubectl` config required to access the cluster can be configured by the `scripts/kr.sh` script.

Run script the assume EKS management role (the leading `.` is part of the command!):
`. ./kr.sh set <dev|prd>`

Check access to cluster:
`kubectl get nodes`
