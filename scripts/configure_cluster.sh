#!/bin/bash

EFS_ID=$(aws ssm get-parameters --region eu-central-1 --name /${PROJECT}/${TARGET_ENV}/env/efs_id --query Parameters[0].Value --output text)
export EFS_ID=$EFS_ID

if [[ $KUBERNETES_VERSION == 1.20 ]]
then
  export CLUSTER_AUTOSCALER_VERSION=v1.20.0
elif [[ $KUBERNETES_VERSION == 1.21 ]]
then
  export CLUSTER_AUTOSCALER_VERSION=v1.21.0
else
  echo "Error: no versions defined for Kubernetes $KUBERNETES_VERSION"
  exit 1
fi

echo "Kubernetes version: $KUBERNETES_VERSION"

aws eks update-kubeconfig --name ecoqube-${TARGET_ENV}-cluster

for template in `ls k8s/*.yaml_envsubst | cut -d"." -f1`; do
  echo -e "Creating config file from template $template.yaml_envsubst"
  envsubst < "$template.yaml_envsubst" > "$template.yaml"
  echo -e "Created config file $template.yaml\n"
done

for config in `ls k8s/*.yaml`; do
  echo -e "Applying config file $config to cluster ecoqube-${TARGET_ENV}-cluster"
  kubectl apply -f $config
  echo -e "Applied config file $config\n"
done

echo -e "Worker nodes:"
kubectl get nodes
echo -e "Current pods:"
kubectl get pods -A