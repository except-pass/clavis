package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var manualCmd = &cobra.Command{
	Use:   "manual",
	Short: "Print comprehensive documentation",
	Long:  "Print the full Clavis manual with mental model, commands, and workflow patterns.",
	Run:   runManual,
}

func init() {
	rootCmd.AddCommand(manualCmd)
}

func runManual(cmd *cobra.Command, args []string) {
	fmt.Print(manualText)
}

const manualText = `CLAVIS MANUAL
=============

Clavis is an encrypted secrets manager that stores secrets as tagged key-value
bundles in a single age-encrypted vault file.

MENTAL MODEL
------------

A SECRET is a named bundle of key-value pairs with metadata:

    Name:   "prod/myapp/mysql"
    Tags:   env:prod, service:myapp, type:database
    Values: host=..., port=3306, username=..., password=...

Secrets are organized by TAGS, not folders. Tags have categories:

    env:      prod, dev, staging, local, ...
    service:  your service names (myapp, api, worker, ...)
    type:     database, credential, api-key, ssh-key, certificate, ...

Names use slash-separated paths: "prod/myapp/mysql", "github/token"
Keys within a secret use dot notation: "prod/myapp/mysql.password"

STORAGE
-------

All secrets live in a single encrypted file:

    ~/.secrets/vault.age      # encrypted vault (safe to backup/commit)
    ~/.secrets/identity.txt   # age private key (NEVER share/commit)

COMMANDS
--------

CRUD Operations:

    clavis add <name> key=value ...         Add new secret
    clavis add <name> key=value --tag env:prod --tag service:x
    clavis get <name>                       Get all values (env format)
    clavis get <name>.key                   Get single value
    clavis get <name> --format=json         Get as JSON
    clavis set <name> key=value             Update/add keys to existing secret
    clavis rm <name>                        Remove entire secret
    clavis rm <name>.key                    Remove single key from secret

Tagging:

    clavis tag <name> category:value        Add tag
    clavis untag <name> category            Remove tag

Discovery:

    clavis list                             All secret names
    clavis list env:prod                    Filter by tag
    clavis list env:prod type:database      Multiple filters (AND)
    clavis list --tags                      Show tags alongside names
    clavis list --verbose                   Show names, tags, and keys
    clavis tags                             All tags grouped by category
    clavis tags env                         Values for one category
    clavis show <name>                      Full details of one secret
    clavis search <pattern>                 Search names, tags, and values
    clavis search <pattern> --reveal        Show matching value context

Output Formats:

    clavis get <name>                       env format (default): export FOO='val'
    clavis get <name> --format=json         JSON object
    clavis get <name> --format=yaml         YAML
    clavis get <name> --format=docker       Docker env: FOO=val (no export/quotes)
    clavis get <name> --format=files -o dir Write one file per key

WORKFLOW PATTERNS
-----------------

1. DISCOVER WHAT'S AVAILABLE

    # What tag categories exist?
    clavis tags

    # What environments?
    clavis tags env

    # What services?
    clavis tags service

    # What prod databases exist?
    clavis list env:prod type:database

2. GET CREDENTIALS FOR A SERVICE

    # See what keys a secret has
    clavis show prod/myapp/mysql

    # Get connection string pieces
    clavis get prod/myapp/mysql.host
    clavis get prod/myapp/mysql.password

    # Export all as env vars
    eval $(clavis get prod/myapp/mysql)

    # Use in a script
    HOST=$(clavis get prod/myapp/mysql.host)
    PASS=$(clavis get prod/myapp/mysql.password)

3. ADD NEW CREDENTIALS

    # Database with full connection info
    clavis add prod/myapp/mysql \
        host=db.example.com \
        port=3306 \
        database=mydb \
        username=admin \
        password=secret \
        --tag env:prod \
        --tag service:myapp \
        --tag type:database

    # API key (simple)
    clavis add stripe/token \
        token=sk_live_abc123 \
        --tag service:stripe \
        --tag type:api-key

    # SSH key (multiline value)
    clavis add ssh/deploy \
        "private_key=$(cat ~/.ssh/deploy_key)" \
        --tag type:ssh-key

4. UPDATE EXISTING CREDENTIALS

    # Add new key to existing secret
    clavis set prod/myapp/mysql readonly_user=reporter

    # Change existing key
    clavis set prod/myapp/mysql password=newpass

5. FIND SECRETS BY TAG

    # All secrets for a service
    clavis list service:myapp

    # All SSH keys
    clavis list type:ssh-key

    # All prod certificates
    clavis list env:prod type:certificate

    # All databases in dev
    clavis list env:dev type:database

6. SEARCH ACROSS EVERYTHING

    # Search names, tags, and values
    clavis search db.example.com         # finds by tag or value
    clavis search prod                   # finds env:prod tags
    clavis search amazonaws              # finds AWS endpoints in values
    clavis search --reveal admin         # show context around match

    # Tag matches show: name [category:value]
    # Value matches show: name.key

7. USE IN CI/DOCKER

    # Write env file for docker
    clavis get prod/myapp --format=docker > .env
    docker run --env-file .env myimage

    # Write secrets as files (for k8s-style mounts)
    clavis get prod/myapp --format=files -o /run/secrets/

8. EXTRACT CERTS/KEYS TO FILES

    clavis get myservice/cert.certificate > /tmp/cert.pem
    clavis get myservice/cert.private_key > /tmp/key.pem
    clavis get myservice/cert.root_ca > /tmp/ca.pem
    chmod 600 /tmp/*.pem

AGENT TIPS
----------

When working with Clavis programmatically:

1. Use "clavis search <pattern>" to find secrets by name, tag, or value
2. Use "clavis tags" to discover what tag categories exist
3. Use "clavis list <tag> --tags" to see matching secrets with their tags
4. Use "clavis get <name> --format=json" for structured output
5. Use "clavis get <name>.key" for single values (no parsing needed)
6. Tag queries use AND logic: "clavis list env:prod type:database"
7. Names use / for hierarchy, . for key access within a secret

COMMON TAG PATTERNS
-------------------

    env:prod, env:dev, env:staging, env:uat, env:local
    type:database, type:credential, type:api-key, type:ssh-key, type:certificate
    service:<name>   # aws, github, mysql, influx, etc.

`
