OpenShift console client integration with Akamai
==============================

```
# Install project
$ git clone git@github.com:pyToshka/openshift-console-client.git
$ cd openshift-console-client
$ glide up -v

# Compile openshift console client
$ make WHAT=cmd/oc GOFLAGS=-v

# Set cookie as environment variable
$ ./_output/local/bin/darwin/amd64/oc login https://os.example.com --token=<token>
This is experimental application.
```
