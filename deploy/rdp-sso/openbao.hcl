storage "raft" {
  path    = "/openbao/file"
  node_id = "rdp-sso"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr = "http://openbao:8200"
cluster_addr = "https://openbao:8201"
disable_mlock = true
