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

#include <string.h>

#include "src/core/security/security_context.h"
#include "src/core/surface/call.h"
#include "src/core/support/string.h"

#include <grpc/grpc_security.h>
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>

/* --- grpc_call --- */

grpc_call_error grpc_call_set_credentials(grpc_call *call,
                                          grpc_credentials *creds) {
  grpc_client_security_context *ctx = NULL;
  if (!grpc_call_is_client(call)) {
    gpr_log(GPR_ERROR, "Method is client-side only.");
    return GRPC_CALL_ERROR_NOT_ON_SERVER;
  }
  if (creds != NULL && !grpc_credentials_has_request_metadata_only(creds)) {
    gpr_log(GPR_ERROR, "Incompatible credentials to set on a call.");
    return GRPC_CALL_ERROR;
  }
  ctx = (grpc_client_security_context *)grpc_call_context_get(
      call, GRPC_CONTEXT_SECURITY);
  if (ctx == NULL) {
    ctx = grpc_client_security_context_create();
    ctx->creds = grpc_credentials_ref(creds);
    grpc_call_context_set(call, GRPC_CONTEXT_SECURITY, ctx,
                          grpc_client_security_context_destroy);
  } else {
    grpc_credentials_unref(ctx->creds);
    ctx->creds = grpc_credentials_ref(creds);
  }
  return GRPC_CALL_OK;
}

/* --- grpc_client_security_context --- */

grpc_client_security_context *grpc_client_security_context_create(void) {
  grpc_client_security_context *ctx =
      gpr_malloc(sizeof(grpc_client_security_context));
  memset(ctx, 0, sizeof(grpc_client_security_context));
  return ctx;
}

void grpc_client_security_context_destroy(void *ctx) {
  grpc_client_security_context *c = (grpc_client_security_context *)ctx;
  grpc_credentials_unref(c->creds);
  gpr_free(ctx);
}

/* --- grpc_auth_context --- */

grpc_auth_context *grpc_auth_context_ref(grpc_auth_context *ctx) {
  if (ctx == NULL) return NULL;
  gpr_ref(&ctx->refcount);
  return ctx;
}

void grpc_auth_context_unref(grpc_auth_context *ctx) {
  if (ctx == NULL) return;
  if (gpr_unref(&ctx->refcount)) {
    size_t i;
    grpc_auth_context_unref(ctx->chained);
    for (i = 0; i < ctx->property_count; i++) {
      grpc_auth_property *prop = &ctx->properties[i];
      gpr_free(prop->name);
      gpr_free(prop->value);
    }
  }
}

const char *gprc_auth_context_peer_identity_property_name(
    const grpc_auth_context *ctx) {
  return ctx->peer_identity_property_name;
}

grpc_auth_property_iterator *grpc_auth_context_property_iterator(
    const grpc_auth_context *ctx) {
  grpc_auth_property_iterator *it;
  if (ctx == NULL) return NULL;
  it = gpr_malloc(sizeof(grpc_auth_property_iterator));
  memset(it, 0, sizeof(grpc_auth_property_iterator));
  it->ctx = ctx;
  return it;
}

const grpc_auth_property *grpc_auth_property_iterator_next(
    grpc_auth_property_iterator *it) {
  if (it == NULL) return NULL;
  while (it->index == it->ctx->property_count) {
    if (it->ctx->chained == NULL) return NULL;
    it->ctx = it->ctx->chained;
    it->index = 0;
  }
  if (it->name == NULL) {
    return &it->ctx->properties[it->index++];
  } else {
    while (it->index < it->ctx->property_count) {
      const grpc_auth_property *prop = &it->ctx->properties[it->index++];
      GPR_ASSERT(prop->name != NULL);
      if (strcmp(it->name, prop->name) == 0) {
        return prop;
      }
    }
    /* We could not find the name, try another round. */
    return grpc_auth_property_iterator_next(it);
  }
}

grpc_auth_property_iterator *grpc_auth_context_find_properties_by_name(
    const grpc_auth_context *ctx, const char *name) {
  grpc_auth_property_iterator *it;
  if (ctx == NULL || name == NULL) return NULL;
  it = grpc_auth_context_property_iterator(ctx);
  it->name = gpr_strdup(name);
  return it;
}

grpc_auth_property_iterator *grpc_auth_context_peer_identity(
    const grpc_auth_context *ctx) {
  if (ctx == NULL || ctx->peer_identity_property_name == NULL) return NULL;
  return grpc_auth_context_find_properties_by_name(
      ctx, ctx->peer_identity_property_name);
}

void grpc_auth_property_iterator_destroy(grpc_auth_property_iterator *it) {
  if (it == NULL) return;
  if (it->name != NULL) gpr_free(it->name);
  gpr_free(it);
}
