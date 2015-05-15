/*
 *
 * Copyright 2015, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef GRPC_INTERNAL_CORE_SECURITY_SECURITY_CONTEXT_H
#define GRPC_INTERNAL_CORE_SECURITY_SECURITY_CONTEXT_H

#include "src/core/security/credentials.h"

/* --- grpc_auth_context ---

   High level authentication context object. Can optionally be chained. */

/* Property names are always NULL terminated. */

struct grpc_auth_property_iterator {
  const grpc_auth_context *ctx;
  size_t index;
  char *name;
};

struct grpc_auth_context {
  struct grpc_auth_context *chained;
  grpc_auth_property *properties;
  size_t property_count;
  gpr_refcount refcount;
  const char *peer_identity_property_name;
};

/* Refcounting. */
grpc_auth_context *grpc_auth_context_ref(
    grpc_auth_context *ctx);
void grpc_auth_context_unref(grpc_auth_context *ctx);

/* Called when the metadata processing is done. If the processing failed,
   success is set to 0. */
typedef void (*grpc_process_auth_metadata_done_cb)(
    void *user_data, int success, grpc_auth_context *result);

/* Pluggable metadata processing function. */
typedef void (*grpc_process_auth_metadata_func)(
    grpc_auth_context *transport_ctx,
    const grpc_metadata_array *metadata,
    grpc_process_auth_metadata_done_cb cb, void *user_data);

/* Registration function for metadata processing.
   Should be called before the server is started. */
void grpc_server_auth_context_register_process_metadata_func(
    grpc_process_auth_metadata_func func);

/* --- grpc_client_security_context ---

   Internal client-side security context. */

typedef struct {
  grpc_credentials *creds;
} grpc_client_security_context;

grpc_client_security_context *grpc_client_security_context_create(void);
void grpc_client_security_context_destroy(void *ctx);

/* --- grpc_server_security_context ---

   Internal server-side security context. (TODO: jboeuf) */

#endif  /* GRPC_INTERNAL_CORE_SECURITY_SECURITY_CONTEXT_H */

