output "repository_url" {
  value = "${coalesce("${module.ecr.repository_url}", "** unset **")}"
}

output "name" {
  value = "${module.ecr.name}"
}

output "registry_id" {
  value = "${module.ecr.registry_id}"
}
