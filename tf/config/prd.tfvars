project                           = "ecoqube"
env                               = "prd"
kubernetes_version                = "1.21"
enable_eks_addons                 = false  # Should be set to false when initially creating the cluster
aws_eks_addon_version_kube_proxy  = "v1.21.2-eksbuild.2"
aws_eks_addon_version_coredns     = "v1.8.4-eksbuild.1"
aws_eks_addon_version_vpc_cni     = "v1.9.1-eksbuild.1"
