project                           = "ecoqube"
env                               = "dev"
kubernetes_version                = "1.23"
enable_eks_addons                 = true  # Should be set to false when initially creating the cluster
aws_eks_addon_version_kube_proxy  = "v1.23.16-eksbuild.2"
aws_eks_addon_version_coredns     = "v1.8.7-eksbuild.7"
aws_eks_addon_version_vpc_cni     = "v1.15.1-eksbuild.1"
grafana_hostname                  = "dev-grafana.eco-qube.eu"
grafana_whitelist                 = "45.138.228.108/32, 10.0.0.0/8, 83.78.135.237/32, 90.158.160.105/32, 86.93.7.144/32, 89.12.11.97/32, 84.107.17.81/32, 0.0.0.0/0"
thanos_hostname                   = "dev-thanos.eco-qube.eu"
thanos_whitelist                  = "45.138.228.108/32, 10.0.0.0/8, 83.78.135.237/32, 90.158.160.105/32, 86.93.7.144/32, 84.107.17.81/32, 185.116.0.0/16, 146.19.177.0/24, 46.4.38.227/32, 65.109.33.153/32"
