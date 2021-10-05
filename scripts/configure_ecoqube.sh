#!/bin/bash

PUBLIC_SUBNET_1A=$(aws ssm get-parameters --region eu-central-1 --name /${PROJECT}/${TARGET_ENV}/env/public_subnet_1a --query Parameters[0].Value --output text)
PUBLIC_SUBNET_1B=$(aws ssm get-parameters --region eu-central-1 --name /${PROJECT}/${TARGET_ENV}/env/public_subnet_1b --query Parameters[0].Value --output text)
GRAFANA_ADMIN_PASSWORD=$(aws ssm get-parameters --region eu-central-1 --name /${PROJECT}/${TARGET_ENV}/env/grafana_admin_password --query Parameters[0].Value --output text --with-decryption)
GRAFANA_ACM_CERT_ARN=$(aws ssm get-parameters --region eu-central-1 --name /${PROJECT}/${TARGET_ENV}/env/grafana_acm_cert_arn --query Parameters[0].Value --output text)
THANOS_ACM_CERT_ARN=$(aws ssm get-parameters --region eu-central-1 --name /${PROJECT}/${TARGET_ENV}/env/thanos_acm_cert_arn --query Parameters[0].Value --output text)
GRAFANA_HOSTNAME=$(grep grafana_hostname tf/config/$TARGET_ENV.tfvars | awk -F '"' '{print $2}')
THANOS_HOSTNAME=$(grep thanos_hostname tf/config/$TARGET_ENV.tfvars | awk -F '"' '{print $2}')

export PUBLIC_SUBNET_1A=$PUBLIC_SUBNET_1A
export PUBLIC_SUBNET_1B=$PUBLIC_SUBNET_1B
export GRAFANA_ADMIN_PASSWORD=$GRAFANA_ADMIN_PASSWORD
export GRAFANA_ACM_CERT_ARN=$GRAFANA_ACM_CERT_ARN
export THANOS_ACM_CERT_ARN=$THANOS_ACM_CERT_ARN
export GRAFANA_HOSTNAME=$GRAFANA_HOSTNAME
export THANOS_HOSTNAME=$THANOS_HOSTNAME

for template in `ls ecoqube/*.yaml_envsubst | cut -d"." -f1`; do
  echo -e "Creating config file from template $template.yaml_envsubst"
  envsubst < "$template.yaml_envsubst" > "$template.yaml"
  echo -e "Created config file $template.yaml\n"
done

kubectl apply -f ecoqube/ecoqube.yaml
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update
helm upgrade --install ecoqube-thanos bitnami/thanos -f ecoqube/bitnami-thanos-helm-config.yaml -n ecoqube-${TARGET_ENV}
helm upgrade --install ecoqube-grafana bitnami/grafana -f ecoqube/bitnami-grafana-helm-config.yaml -n ecoqube-${TARGET_ENV}