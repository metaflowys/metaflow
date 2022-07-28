static __inline void *get_the_first_parameter(struct pt_regs *ctx)
{
	void *ptr;
	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		ptr = (void *)ctx->rax;
	} else {
		bpf_probe_read(&ptr, sizeof(ptr), (void *)(ctx->rsp + 8));
	}
	return ptr;
}

static __inline bool is_grpc_syscallConn_interface(void *ptr)
{
	struct go_interface i;
	bpf_probe_read_user(&i, sizeof(i), ptr);

	struct ebpf_proc_info *info = get_current_proc_info();
	return info ? i.type == info->credentials_syscallConn_itab : false;
}

static __inline int get_fd_from_http2serverConn_ctx(struct pt_regs *ctx)
{
	void *ptr = get_the_first_parameter(ctx);
	ptr += get_uprobe_offset(OFFSET_IDX_CONN_HTTP2_SERVER_CONN);
	return get_fd_from_tcp_or_tls_conn_interface(ptr);
}

static __inline int get_fd_from_http2ClientConn(void *ptr)
{
	ptr += get_uprobe_offset(OFFSET_IDX_TCONN_HTTP2_CLIENT_CONN);
	return get_fd_from_tcp_or_tls_conn_interface(ptr);
}

static __inline int get_fd_from_http2ClientConn_ctx(struct pt_regs *ctx)
{
	void *ptr = get_the_first_parameter(ctx);
	return get_fd_from_http2ClientConn(ptr);
}

static __inline int get_fd_from_grpc_http2Client_ctx(struct pt_regs *ctx)
{
	void *ptr = get_the_first_parameter(ctx);
	ptr += get_uprobe_offset(OFFSET_IDX_CONN_GRPC_HTTP2_CLIENT);
	if (is_grpc_syscallConn_interface(ptr)) {
		struct go_interface i;
		bpf_probe_read_user(&i, sizeof(i), ptr);
		bpf_probe_read_user(&i, sizeof(i), i.ptr);
		ptr = i.ptr;
	}
	return get_fd_from_tcp_or_tls_conn_interface(ptr);
}

static __inline int get_fd_from_grpc_http2Server_ctx(struct pt_regs *ctx)
{
	void *ptr = get_the_first_parameter(ctx);
	ptr += get_uprobe_offset(OFFSET_IDX_CONN_GRPC_HTTP2_SERVER);
	if (is_grpc_syscallConn_interface(ptr)) {
		struct go_interface i;
		bpf_probe_read_user(&i, sizeof(i), ptr);
		bpf_probe_read_user(&i, sizeof(i), i.ptr);
		ptr = i.ptr;
	}
	return get_fd_from_tcp_or_tls_conn_interface(ptr);
}

static __inline int get_side_from_grpc_loopyWriter(struct pt_regs *ctx)
{
	void *ptr = get_the_first_parameter(ctx);

	ptr += get_uprobe_offset(OFFSET_IDX_SIDE_GRPC_TRANSPORT_LOOPY_WRITER);
	int side = 0;
	bpf_probe_read_user(&side, sizeof(side), ptr);
	return side;
}

static __inline int get_fd_from_grpc_loopyWriter(struct pt_regs *ctx)
{
	void *ptr = get_the_first_parameter(ctx);

	ptr += get_uprobe_offset(OFFSET_IDX_FRAMER_GRPC_TRANSPORT_LOOPY_WRITER);
	bpf_probe_read_user(&ptr, sizeof(ptr), ptr);
	ptr += get_uprobe_offset(OFFSET_IDX_WRITER_GRPC_TRANSPORT_FRAMER);
	bpf_probe_read_user(&ptr, sizeof(ptr), ptr);
	ptr += get_uprobe_offset(OFFSET_IDX_CONN_GRPC_TRANSPORT_BUFWRITER);

	if (is_grpc_syscallConn_interface(ptr)) {
		struct go_interface i;
		bpf_probe_read_user(&i, sizeof(i), ptr);
		bpf_probe_read_user(&i, sizeof(i), i.ptr);
		ptr = i.ptr;
	}
	return get_fd_from_tcp_or_tls_conn_interface(ptr);
}

struct go_http2_header_field {
	struct go_string name;
	struct go_string value;
	bool sensitive;
};

static __inline int handle_http2_header_field(void *ptr, int idx)
{
	struct go_http2_header_field *tmp = ptr;
	struct go_http2_header_field field;
	bpf_probe_read_user(&field, sizeof(field), tmp + idx);

	// 通过字符串的 len 确定了这些就是动态表的数组,且 field 就是动态表中的一项
	// 后面需要把这些东西根据长度读出来放到一个大的 buffer 里传上去
	bpf_debug("field name len=[%d], value len=[%d]\n", field.name.len,
		  field.value.len);
	return 0;
}

// golang.org/x/net/http2/hpack.dynamicTable
static __inline int update_dynamic_table(void *ptr)
{
	struct go_slice ents;
	bpf_probe_read_user(&ents, sizeof(ents), ptr);
	bpf_debug("ents len=[%d], cap=[%d]\n", ents.len, ents.cap);

	static const int field_max = 100;
	static const int debug_show_max = 3;
	int field_idx = 0;

#pragma unroll
	for (field_idx = 0; field_idx < field_max; ++field_idx) {
		if (field_idx >= debug_show_max)
			break;
		if (field_idx < ents.len)
			handle_http2_header_field(ents.ptr, field_idx);
	}

	ptr += get_uprobe_offset(
		OFFSET_IDX_EVICT_COUNT_HPACK_HEADER_FIELD_TABLE);
	__u64 evictCount;
	bpf_probe_read_user(&evictCount, sizeof(evictCount), ptr);
	bpf_debug("evictCount=[%d]\n", evictCount);
	return 0;
}

static __inline void *
get_http2ClientConn_from_http2clientConnReadLoop_ctx(struct pt_regs *ctx)
{
	void *ptr = get_the_first_parameter(ctx);
	ptr += get_uprobe_offset(OFFSET_IDX_CC_HTTP2_CLIENT_CONN_READ_LOOP);
	bpf_probe_read(&ptr, sizeof(ptr), ptr);
	return ptr;
}

static __inline int get_fd_from_http2clientConnReadLoop_ctx(struct pt_regs *ctx)
{
	void *ptr = get_http2ClientConn_from_http2clientConnReadLoop_ctx(ctx);
	return get_fd_from_http2ClientConn(ptr);
}

static void *get_http2ClientConn_request_table(void *ptr)
{
	ptr += get_uprobe_offset(OFFSET_IDX_HENC_HTTP2_CLIENT_CONN);
	bpf_probe_read_user(&ptr, sizeof(ptr), ptr);
	return ptr;
}

static void *get_http2ClientConn_response_table(void *ptr)
{
	ptr += get_uprobe_offset(OFFSET_IDX_FR_HTTP2_CLIENT_CONN);
	bpf_probe_read_user(&ptr, sizeof(ptr), ptr);
	ptr += get_uprobe_offset(OFFSET_IDX_READ_META_HEADERS_HTTP2_FRAMER);
	bpf_probe_read_user(&ptr, sizeof(ptr), ptr);
	return ptr;
}

static void *get_http2serverConn_request_table(void *ptr)
{
	ptr += get_uprobe_offset(OFFSET_IDX_FRAMER_HTTP2_CLIENT_CONN);
	bpf_probe_read_user(&ptr, sizeof(ptr), ptr);
	ptr += get_uprobe_offset(OFFSET_IDX_READ_META_HEADERS_HTTP2_FRAMER);
	bpf_probe_read_user(&ptr, sizeof(ptr), ptr);
	return ptr;
}

static void *get_http2serverConn_response_table(void *ptr)
{
	ptr += get_uprobe_offset(OFFSET_IDX_HPACK_ENCODER_HTTP2_CLIENT_CONN);
	bpf_probe_read_user(&ptr, sizeof(ptr), ptr);
	return ptr;
}

static __inline void *
get_request_table_from_http2serverConn_ctx(struct pt_regs *ctx)
{
	void *ptr = get_the_first_parameter(ctx);
	return get_http2serverConn_request_table(ptr);
}

static __inline void *
get_response_table_from_http2serverConn_ctx(struct pt_regs *ctx)
{
	void *ptr = get_the_first_parameter(ctx);
	return get_http2serverConn_response_table(ptr);
}

static __inline void *
get_request_table_from_http2ClientConn_ctx(struct pt_regs *ctx)
{
	void *ptr = get_the_first_parameter(ctx);
	return get_http2ClientConn_request_table(ptr);
}

static __inline void *
get_response_table_from_http2clientConnReadLoop_ctx(struct pt_regs *ctx)
{
	void *ptr = get_http2ClientConn_from_http2clientConnReadLoop_ctx(ctx);
	return get_http2ClientConn_response_table(ptr);
}

// 日志上来看,调用多次 writeHeader 后调用一次 writeHeaders 进行发送
// 可能可以把这两个联系起来完成功能
SEC("uprobe/go_http2ClientConn_writeHeader")
int uprobe_go_http2ClientConn_writeHeader(struct pt_regs *ctx)
{
	// 看样子不需要这个hook点,临时屏蔽掉
	return 0;
	int fd = get_fd_from_http2ClientConn_ctx(ctx);
	int tcp_seq = get_tcp_write_seq_from_fd(fd);
	bpf_debug("===== 0 ===== fd=[%d] tcp_seq=[%u]\n", fd, tcp_seq);

	// TODO: Implement hook function
	return 0;
}

SEC("uprobe/go_http2ClientConn_writeHeaders")
int uprobe_go_http2ClientConn_writeHeaders(struct pt_regs *ctx)
{
	int fd = get_fd_from_http2ClientConn_ctx(ctx);
	int tcp_seq = get_tcp_write_seq_from_fd(fd);
	bpf_debug("===== 1 ===== fd=[%d] tcp_seq=[%u]\n", fd, tcp_seq);

	// 在这里把动态表打印出来
	void *ptr = get_request_table_from_http2ClientConn_ctx(ctx);
	update_dynamic_table(ptr);
	// TODO: Implement hook function
	return 0;
}

// func (sc *http2serverConn) processHeaders(f *http2MetaHeadersFrame) error
SEC("uprobe/go_http2serverConn_processHeaders")
int uprobe_go_http2serverConn_processHeaders(struct pt_regs *ctx)
{
	int fd = get_fd_from_http2serverConn_ctx(ctx);
	int tcp_seq = get_tcp_read_seq_from_fd(fd);
	bpf_debug("===== 2 ===== fd=[%d] tcp_seq=[%u]\n", fd, tcp_seq);
	void *ptr = get_request_table_from_http2serverConn_ctx(ctx);
	update_dynamic_table(ptr);
	// TODO: Implement hook function
	return 0;
}

// func (sc *http2serverConn) writeHeaders(st *http2stream, headerData *http2writeResHeaders) error
SEC("uprobe/go_http2serverConn_writeHeaders")
int uprobe_go_http2serverConn_writeHeaders(struct pt_regs *ctx)
{
	int fd = get_fd_from_http2serverConn_ctx(ctx);
	int tcp_seq = get_tcp_write_seq_from_fd(fd);
	bpf_debug("===== 3 ===== fd=[%d] tcp_seq=[%u]\n", fd, tcp_seq);
	void *ptr = get_response_table_from_http2serverConn_ctx(ctx);
	update_dynamic_table(ptr);
	// TODO: Implement hook function
	return 0;
}

SEC("uprobe/go_http2clientConnReadLoop_handleResponse")
int uprobe_go_http2clientConnReadLoop_handleResponse(struct pt_regs *ctx)
{
	int fd = get_fd_from_http2clientConnReadLoop_ctx(ctx);
	int tcp_seq = get_tcp_read_seq_from_fd(fd);
	bpf_debug("===== 4 ===== fd=[%d] tcp_seq=[%u]\n", fd, tcp_seq);

	void *ptr = get_response_table_from_http2clientConnReadLoop_ctx(ctx);
	update_dynamic_table(ptr);
	// TODO: Implement hook function
	return 0;
}

SEC("uprobe/go_http2Server_operateHeaders")
int uprobe_go_http2Server_operateHeaders(struct pt_regs *ctx)
{
	int fd = get_fd_from_grpc_http2Server_ctx(ctx);
	int tcp_seq = get_tcp_read_seq_from_fd(fd);
	bpf_debug("===== 6 ===== fd=[%d] tcp_seq=[%u]\n", fd, tcp_seq);

	// TODO: Implement hook function
	return 0;
}

SEC("uprobe/go_loopyWriter_writeHeader")
int uprobe_go_loopyWriter_writeHeader(struct pt_regs *ctx)
{
	int fd = get_fd_from_grpc_loopyWriter(ctx);
	int tcp_seq = get_tcp_write_seq_from_fd(fd);
	int side = get_side_from_grpc_loopyWriter(ctx);
	if (side == 0) {
		bpf_debug("===== 5 ===== fd=[%d] tcp_seq=[%u]\n", fd, tcp_seq);
	} else {
		bpf_debug("===== 7 ===== fd=[%d] tcp_seq=[%u]\n", fd, tcp_seq);
	}

	// TODO: Implement hook function
	return 0;
}

SEC("uprobe/go_http2Client_operateHeaders")
int uprobe_go_http2Client_operateHeaders(struct pt_regs *ctx)
{
	int fd = get_fd_from_grpc_http2Client_ctx(ctx);
	int tcp_seq = get_tcp_read_seq_from_fd(fd);
	bpf_debug("===== 8 ===== fd=[%d] tcp_seq=[%u]\n", fd, tcp_seq);

	// TODO: Implement hook function
	return 0;
}
