#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later

# Run with "ninja kres-gen" to re-generate kres-gen.lua
set -o pipefail -o errexit -o nounset

cd "$(dirname ${0})"
CDEFS="../../scripts/gen-cdefs.sh"
LIBKRES="${MESON_BUILD_ROOT}/lib/libkres.so"
KRESD="${MESON_BUILD_ROOT}/daemon/kresd"
if [ ! -e "$LIBKRES" ]; then
	# We probably use static libkres.
	LIBKRES="$KRESD"
fi

for REQFILE in "$CDEFS" "$LIBKRES" "$KRESD"
do
	test '!' -s "$REQFILE" -a -r "$REQFILE" \
		&& echo "Required file $REQFILE cannot be read, did you build binaries and shared libraries?" \
		&& exit 1
done

# Write to kres-gen.lua instead of stdout
mv kres-gen.lua{,.bak} ||:
exec 5<&1-  # move stdout into FD 5
exec 1<>kres-gen.lua  # replace stdout with file

restore() {
    exec 1>&-  # close stdout redirected into kres-gen.lua
    exec 1<&5-  # restore original stdout
    mv -v kres-gen.lua{,.fail} ||:
    mv -v kres-gen.lua{.bak,} ||:
    (>&2 echo "Failed to re-generate kres-gen.lua! Missing debugsymbols? Missing shared library?")
}
trap restore ERR INT TERM

### Dev's guide
#
# C declarations for lua are (mostly) generated to simplify maintenance.
# (Avoid typos, accidental mismatches, etc.)
#
# To regenerate the C definitions for lua:
# - you need to have debugging symbols for knot-dns and knot-resolver;
#   you get those by compiling with -g; for knot-dns it might be enough
#   to just install it with debugging symbols included (in your distro way)
# - run ninja kres-gen
# - the knot-dns libraries are found via pkg-config
# - you also need gdb on $PATH

printf -- "-- SPDX-License-Identifier: GPL-3.0-or-later\n\n"
printf -- "local ffi = require('ffi')\n"
printf -- "--[[ This file is generated by ./kres-gen.sh ]] ffi.cdef[[\n"

## Various types (mainly), from libknot and libkres

printf "
typedef struct knot_dump_style knot_dump_style_t;
extern const knot_dump_style_t KNOT_DUMP_STYLE_DEFAULT;
struct kr_cdb_api {};
struct lru {};
"

${CDEFS} ${LIBKRES} types <<-EOF
	knot_section_t
	knot_rrinfo_t
	knot_dname_t
	knot_rdata_t
	knot_rdataset_t
EOF

# The generator doesn't work well with typedefs of functions.
printf "
typedef struct knot_mm {
	void *ctx, *alloc, *free;
} knot_mm_t;

typedef void *(*map_alloc_f)(void *, size_t);
typedef void (*map_free_f)(void *baton, void *ptr);
typedef void (*trace_log_f) (const struct kr_request *, const char *);
typedef void (*trace_callback_f)(struct kr_request *);
typedef uint8_t * (*alloc_wire_f)(struct kr_request *req, uint16_t *maxlen);
typedef bool (*addr_info_f)(struct sockaddr*);
"

genResType() {
	echo "$1" | ${CDEFS} ${LIBKRES} types
}

# No simple way to fixup this rename in ./kres.lua AFAIK.
genResType "knot_rrset_t" | sed 's/\<owner\>/_owner/; s/\<ttl\>/_ttl/'

printf "
struct kr_module;
typedef char *(kr_prop_cb)(void *, struct kr_module *, const char *);
"

${CDEFS} ${LIBKRES} types <<-EOF
	#knot_pkt_t contains indirect recursion
	typedef knot_pkt_t
	knot_edns_options_t
	knot_pktsection_t
	knot_compr_t
	struct knot_pkt
	# lib/generic/
	map_t
	#trie_t inside is private to libknot
	typedef trie_t
	# libkres
	struct kr_qflags
	ranked_rr_array_entry_t
	ranked_rr_array_t
	kr_http_header_array_entry_t
	kr_http_header_array_t
	inaddr_array_t
	struct kr_zonecut
	kr_qarray_t
	struct kr_rplan
	struct kr_request_qsource_flags
	struct kr_request
	enum kr_rank
	typedef kr_cdb_pt
	struct kr_cdb_stats
	typedef uv_timer_t
	struct kr_cache
	# lib/layer.h
	kr_layer_t
	kr_layer_api_t
	# lib/module.h
	struct kr_prop
	struct kr_module
	struct kr_server_selection
EOF

# static variables; these lines might not be simple to generate
printf "
kr_layer_t kr_layer_t_static;
_Bool kr_dbg_assumption_abort;
_Bool kr_dbg_assumption_fork;
"

printf "
typedef int32_t (*kr_stale_cb)(int32_t ttl, const knot_dname_t *owner, uint16_t type,
				const struct kr_query *qry);

void kr_rrset_init(knot_rrset_t *rrset, knot_dname_t *owner,
			uint16_t type, uint16_t rclass, uint32_t ttl);
"

## Some definitions would need too many deps, so shorten them.

genResType "struct kr_query"

genResType "struct kr_context" | sed '/module_array_t/,$ d'
printf "\tchar _stub[];\n};\n"


echo "struct kr_transport" | ${CDEFS} ${KRESD} types | sed '/union /,$ d'
printf "\t/* beware: hidden stub, to avoid hardcoding sockaddr lengths */\n};\n"

## libknot API
${CDEFS} libknot functions <<-EOF
# Utils
	knot_strerror
# Domain names
	knot_dname_copy
	knot_dname_from_str
	knot_dname_in_bailiwick
	knot_dname_is_equal
	knot_dname_labels
	knot_dname_size
	knot_dname_to_lower
	knot_dname_to_str
# Resource records
	knot_rdataset_at
	knot_rdataset_merge
	knot_rrset_add_rdata
	knot_rrset_free
	knot_rrset_txt_dump
	knot_rrset_txt_dump_data
	knot_rrset_size
# Packet
	knot_pkt_begin
	knot_pkt_put_question
	knot_pkt_put_rotate
	knot_pkt_new
	knot_pkt_free
	knot_pkt_parse
EOF

## libkres API
${CDEFS} ${LIBKRES} functions <<-EOF
# Resolution request
	kr_request_ensure_answer
	kr_resolve_plan
	kr_resolve_pool
# Resolution plan
	kr_rplan_push
	kr_rplan_pop
	kr_rplan_resolved
	kr_rplan_last
# Forwarding
	kr_forward_add_target
# Utils
	kr_log_req
	kr_log_q
	kr_make_query
	kr_pkt_make_auth_header
	kr_pkt_put
	kr_pkt_recycle
	kr_pkt_clear_payload
	kr_pkt_has_dnssec
	kr_pkt_qclass
	kr_pkt_qtype
	kr_pkt_text
	kr_rnd_buffered
	kr_rrsig_sig_inception
	kr_rrsig_sig_expiration
	kr_rrsig_type_covered
	kr_inaddr
	kr_inaddr_family
	kr_inaddr_len
	kr_inaddr_str
	kr_sockaddr_cmp
	kr_sockaddr_len
	kr_inaddr_port
	kr_straddr_family
	kr_straddr_subnet
	kr_bitcmp
	kr_family_len
	kr_straddr_socket
	kr_straddr_split
	kr_rank_test
	kr_ranked_rrarray_add
	kr_ranked_rrarray_finalize
	kr_qflags_set
	kr_qflags_clear
	kr_zonecut_add
	kr_zonecut_is_empty
	kr_zonecut_set
	kr_now
	kr_strptime_diff
	kr_file_mtime
	kr_fssize
	kr_dirent_name
	lru_free_items_impl
	lru_create_impl
	lru_get_impl
	mm_realloc
# Trust anchors
	kr_ta_get
	kr_ta_add
	kr_ta_del
	kr_ta_clear
# DNSSEC
	kr_dnssec_key_ksk
	kr_dnssec_key_revoked
	kr_dnssec_key_tag
	kr_dnssec_key_match
# Cache
	kr_cache_closest_apex
	kr_cache_insert_rr
	kr_cache_remove
	kr_cache_remove_subtree
	kr_cache_commit
	# FIXME: perhaps rename this exported symbol
	packet_ttl
EOF


## kresd itself: worker stuff

${CDEFS} ${KRESD} types <<-EOF
	endpoint_flags_t
	# struct args is a bit complex
	addr_array_t
	flagged_fd_t
	flagged_fd_array_t
	config_array_t
	struct args
EOF
echo "struct args *the_args;"

echo "struct endpoint"    | ${CDEFS} ${KRESD} types | sed 's/uv_handle_t \*/void */'
echo "struct request_ctx" | ${CDEFS} ${KRESD} types | sed '/struct {/,$ d'
printf "\t/* beware: hidden stub, to avoid hardcoding sockaddr lengths */\n};\n"

echo "struct qr_task" | ${CDEFS} ${KRESD} types | sed '/pktbuf/,$ d'
printf "\t/* beware: hidden stub, to avoid qr_tasklist_t */\n};\n"


${CDEFS} ${KRESD} functions <<-EOF
	worker_resolve_exec
	worker_resolve_mk_pkt
	worker_resolve_start
EOF

echo "struct engine" | ${CDEFS} ${KRESD} types | sed '/struct network/,$ d'
printf "\tchar _stub[];\n};\n"

echo "struct worker_ctx" | ${CDEFS} ${KRESD} types | sed '/uv_loop_t/,$ d'
printf "\tchar _stub[];\n};\n"

echo "struct worker_ctx *the_worker;"


## libzscanner API for ./zonefile.lua
${CDEFS} libzscanner types <<-EOF
	zs_win_t
	zs_apl_t
	zs_loc_t
	zs_state_t
	#zs_scanner_t contains recursion
	typedef zs_scanner_t
	zs_scanner_t
EOF
${CDEFS} libzscanner functions <<-EOF
	zs_deinit
	zs_init
	zs_parse_record
	zs_set_input_file
	zs_set_input_string
	zs_strerror
EOF

printf "]]\n"

rm kres-gen.lua.bak ||:
(>&2 echo "Successfully re-generated ${PWD}/kres-gen.lua")

exit 0
