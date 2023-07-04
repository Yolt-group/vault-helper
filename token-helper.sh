#!/bin/bash

function token_path {
  case "$VAULT_ADDR" in
  https://vault.yolt.io)
    echo $HOME/.vault-helper/vault.yolt.io/token
    ;;
  *)
    echo $HOME/.vault-token
  esac
}

function get {
  cat $(token_path)
  exit 0
}

function store {
  echo $1 > $(token_path)
}

function erase {
  rm -f $(token_path)
}

case "$1" in
get)
  get
  ;;
store)
  store $2
  ;;
erase)
  erase
  ;;
*)
  echo $"Usage: $0 {get|store|erase}"
  exit 1
esac

