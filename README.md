# Golang SSH Test Rig

This is inspired by the httptest package and provides a simple rig to test SSH
libraries. It starts a local server, that can be configured to a certain extent.

A word of warning: This is more of an experiment, than something I'd use in
production. At least not without some proper review and some major refinements.

And a note on closing sessions: usually that is done by the server after the
command exited. This in turn means, that a client, gracefully closing the
session will receive an `io.EOF` error.
