packer {
  required_version = "= 1.16.0"

  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = "= 1.8.1"
    }
  }
}

variable "region" {
  type = string
  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$", var.region))
    error_message = "Region must be an explicit AWS region."
  }
}

variable "target_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.target_account_id))
    error_message = "Target account ID must be the STS-verified build account."
  }
}

variable "source_ami_id" {
  type = string
  validation {
    condition     = can(regex("^ami-[0-9a-f]{17}$", var.source_ami_id))
    error_message = "Source AMI ID must be an explicit long-form AMI ID."
  }
}

variable "source_ami_owner" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.source_ami_owner))
    error_message = "Source AMI owner must be an explicit AWS account ID."
  }
}

variable "vpc_id" {
  type = string
  validation {
    condition     = can(regex("^vpc-[0-9a-f]{17}$", var.vpc_id))
    error_message = "VPC ID must be explicit."
  }
}

variable "subnet_id" {
  type = string
  validation {
    condition     = can(regex("^subnet-[0-9a-f]{17}$", var.subnet_id))
    error_message = "Subnet ID must be explicit."
  }
}

variable "security_group_id" {
  type = string
  validation {
    condition     = can(regex("^sg-[0-9a-f]{17}$", var.security_group_id))
    error_message = "Security Group ID must be explicit."
  }
}

variable "packer_source_security_group_id" {
  type = string
  validation {
    condition     = can(regex("^sg-[0-9a-f]{17}$", var.packer_source_security_group_id))
    error_message = "Packer source Security Group ID must be the read-back SSH source SG."
  }
}

variable "kms_key_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws[a-zA-Z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}$", var.kms_key_arn))
    error_message = "KMS key ARN must name an explicit KMS key."
  }
}

variable "instance_type" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]*[0-9][a-z0-9.]*$", var.instance_type))
    error_message = "Instance type must be explicit."
  }
}

variable "ssh_username" {
  type = string
  validation {
    condition     = can(regex("^[a-z_][a-z0-9_-]{0,31}$", var.ssh_username))
    error_message = "SSH username must match the pinned source AMI."
  }
}

variable "root_device_name" {
  type = string
  validation {
    condition     = can(regex("^/dev/[a-z0-9]+$", var.root_device_name))
    error_message = "Root device name must match the pinned source AMI."
  }
}

variable "rootfs_tar_path" {
  type = string
  validation {
    condition     = can(regex("^/", var.rootfs_tar_path))
    error_message = "Rootfs tar path must be absolute."
  }
}

variable "rootfs_sha256" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.rootfs_sha256))
    error_message = "Rootfs SHA-256 must be a lowercase digest."
  }
}

variable "ami_digest" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.ami_digest))
    error_message = "AMI digest must be the semantic release digest embedded in installation.json."
  }
}

variable "nftables_nevra" {
  type = string
  validation {
    condition     = can(regex("^nftables-[0-9][A-Za-z0-9._+~:]*-[A-Za-z0-9][A-Za-z0-9._+~]*\\.x86_64$", var.nftables_nevra))
    error_message = "Nftables NEVRA must be an exact x86_64 package identifier."
  }
}

data "amazon-ami" "base" {
  region      = var.region
  owners      = [var.source_ami_owner]
  most_recent = false
  filters = {
    "image-id"            = var.source_ami_id
    "architecture"        = "x86_64"
    "root-device-type"    = "ebs"
    "state"               = "available"
    "virtualization-type" = "hvm"
  }
}

source "amazon-ebs" "cloud_worker" {
  region                      = var.region
  source_ami                  = data.amazon-ami.base.id
  instance_type               = var.instance_type
  ssh_username                = var.ssh_username
  ssh_interface               = "private_ip"
  ssh_clear_authorized_keys   = true
  associate_public_ip_address = false
  vpc_id                      = var.vpc_id
  subnet_id                   = var.subnet_id
  security_group_id           = var.security_group_id
  shutdown_behavior           = "terminate"

  ami_name         = "dirextalk-pi-worker-${substr(var.ami_digest, 0, 12)}-{{timestamp}}"
  ami_description  = "Dirextalk ephemeral-pi-task AMI ${var.ami_digest} rootfs ${var.rootfs_sha256}"
  imds_support     = "v2.0"
  ena_support      = true
  force_deregister = false

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  launch_block_device_mappings {
    device_name           = var.root_device_name
    delete_on_termination = true
    encrypted             = true
    kms_key_id            = var.kms_key_arn
    volume_type           = "gp3"
    volume_size           = 16
    iops                  = 3000
    throughput            = 125
  }

  run_tags = {
    "Name"                    = "dirextalk-cloud-worker-ami-build"
    "DirextalkRecipe"         = "ephemeral-pi-task"
    "DirextalkTargetAccount"  = var.target_account_id
    "DirextalkAMIDigest"      = var.ami_digest
    "DirextalkRootfsSHA256"   = var.rootfs_sha256
    "DirextalkSourceAMI"      = var.source_ami_id
    "DirextalkSourceOwner"    = var.source_ami_owner
    "DirextalkPackerSourceSG" = var.packer_source_security_group_id
  }
  run_volume_tags = {
    "DirextalkRecipe"        = "ephemeral-pi-task"
    "DirextalkTargetAccount" = var.target_account_id
    "DirextalkAMIDigest"     = var.ami_digest
    "DirextalkRootfsSHA256"  = var.rootfs_sha256
  }
  tags = {
    "Name"                   = "dirextalk-ephemeral-pi-task"
    "DirextalkRecipe"        = "ephemeral-pi-task"
    "DirextalkTargetAccount" = var.target_account_id
    "DirextalkAMIDigest"     = var.ami_digest
    "DirextalkRootfsSHA256"  = var.rootfs_sha256
    "DirextalkSourceAMI"     = var.source_ami_id
    "DirextalkSourceOwner"   = var.source_ami_owner
  }
  snapshot_tags = {
    "DirextalkRecipe"        = "ephemeral-pi-task"
    "DirextalkTargetAccount" = var.target_account_id
    "DirextalkAMIDigest"     = var.ami_digest
    "DirextalkRootfsSHA256"  = var.rootfs_sha256
  }
}

build {
  name    = "dirextalk-cloud-worker"
  sources = ["source.amazon-ebs.cloud_worker"]

  provisioner "file" {
    source      = var.rootfs_tar_path
    destination = "/tmp/dirextalk-cloud-worker-rootfs.tar"
  }

  provisioner "file" {
    source      = "deploy/cloud-worker/rootfs-files.allowlist"
    destination = "/tmp/dirextalk-cloud-worker-rootfs-files.allowlist.incoming"
  }

  provisioner "file" {
    source      = "deploy/cloud-worker/install-rootfs.sh"
    destination = "/tmp/dirextalk-cloud-worker-install-rootfs.incoming"
  }

  provisioner "shell" {
    environment_vars = [
      "DIREXTALK_ROOTFS_SHA256=${var.rootfs_sha256}",
      "DIREXTALK_AMI_DIGEST=${var.ami_digest}",
      "DIREXTALK_NFTABLES_NEVRA=${var.nftables_nevra}",
    ]
    inline = [
      "sudo install -o root -g root -m 0444 /tmp/dirextalk-cloud-worker-rootfs-files.allowlist.incoming /tmp/dirextalk-cloud-worker-rootfs-files.allowlist",
      "sudo install -o root -g root -m 0555 /tmp/dirextalk-cloud-worker-install-rootfs.incoming /tmp/dirextalk-cloud-worker-install-rootfs",
      "sudo /tmp/dirextalk-cloud-worker-install-rootfs --target-root / --payload-tar /tmp/dirextalk-cloud-worker-rootfs.tar --payload-sha256 \"$DIREXTALK_ROOTFS_SHA256\" --allowlist /tmp/dirextalk-cloud-worker-rootfs-files.allowlist --nftables-nevra \"$DIREXTALK_NFTABLES_NEVRA\"",
      "sudo /usr/local/sbin/dirextalk-cloud-worker-qualify --phase offline --target-root / --ami-digest \"$DIREXTALK_AMI_DIGEST\" --rootfs-sha256 \"$DIREXTALK_ROOTFS_SHA256\" --nftables-nevra \"$DIREXTALK_NFTABLES_NEVRA\"",
      "sudo rm -f /tmp/dirextalk-cloud-worker-rootfs.tar /tmp/dirextalk-cloud-worker-rootfs-files.allowlist /tmp/dirextalk-cloud-worker-rootfs-files.allowlist.incoming /tmp/dirextalk-cloud-worker-install-rootfs /tmp/dirextalk-cloud-worker-install-rootfs.incoming",
    ]
  }
}
