# Scope
#######
variable "project" {
  type = string
}

variable "env" {
  type = string
}

variable "kubernetes_version" {
  type = string
}

variable "image_id" {
  type = string
}

variable "enable_eks_addons" {
  type    = bool
  default = true
}

variable "aws_eks_addon_version_kube_proxy" {
  type = string
}

variable "aws_eks_addon_version_coredns" {
  type = string
}

variable "aws_eks_addon_version_vpc_cni" {
  type = string
}

variable "grafana_hostname" {
  type = string
}

variable "thanos_hostname" {
  type = string
}
