project                           = "ecoqube"
env                               = "prd"
kubernetes_version                = "1.21"
enable_eks_addons                 = true  # Should be set to false when initially creating the cluster
aws_eks_addon_version_kube_proxy  = "v1.21.2-eksbuild.2"
aws_eks_addon_version_coredns     = "v1.8.4-eksbuild.1"
aws_eks_addon_version_vpc_cni     = "v1.9.1-eksbuild.1"
grafana_hostname                  = "grafana.eco-qube.eu"
grafana_whitelist                 = "45.138.228.108/32, 10.0.0.0/8, 83.78.135.237/32, 90.158.160.105/32, 86.93.7.144/32, 89.12.11.97/32, 84.107.17.81/32"
thanos_hostname                   = "thanos.eco-qube.eu"
thanos_whitelist                  = "45.138.228.108/32, 10.0.0.0/8, 83.78.135.237/32, 90.158.160.105/32, 86.93.7.144/32, 84.107.17.81/32"
