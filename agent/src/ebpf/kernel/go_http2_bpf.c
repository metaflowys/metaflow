static __inline bool is_grpc_syscallConn_interface(void *ptr)
{
	struct go_interface i;
	bpf_probe_read_user(&i, sizeof(i), ptr);

	struct ebpf_proc_info *info = get_current_proc_info();
	return info ? i.type == info->credentials_syscallConn_itab : false;
}

static __inline int get_conn_http2_server_conn_offset(void)
{
	return get_uprobe_offset(OFFSET_IDX_CONN_HTTP2_SERVER_CONN);
}

static __inline int get_tconn_http2_client_conn_offset(void)
{
	return get_uprobe_offset(OFFSET_IDX_TCONN_HTTP2_CLIENT_CONN);
}

static __inline int get_cc_http2_client_conn_read_loop_offset(void)
{
	return get_uprobe_offset(OFFSET_IDX_CC_HTTP2_CLIENT_CONN_READ_LOOP);
}

static __inline int get_conn_grpc_http2_client_offset(void)
{
	return get_uprobe_offset(OFFSET_IDX_CONN_GRPC_HTTP2_CLIENT);
}

static __inline int get_conn_grpc_http2_server_offset(void)
{
	return get_uprobe_offset(OFFSET_IDX_CONN_GRPC_HTTP2_SERVER);
}

static __inline int get_framer_grpc_transport_loopy_writer_offset(void)
{
	return get_uprobe_offset(OFFSET_IDX_FRAMER_GRPC_TRANSPORT_LOOPY_WRITER);
}

static __inline int get_side_grpc_transport_loopy_writer_offset(void)
{
	return get_uprobe_offset(OFFSET_IDX_SIDE_GRPC_TRANSPORT_LOOPY_WRITER);
}

static __inline int get_writer_grpc_transport_framer_offset(void)
{
	return get_uprobe_offset(OFFSET_IDX_WRITER_GRPC_TRANSPORT_FRAMER);
}

static __inline int get_conn_grpc_transport_bufwriter_offset(void)
{
	return get_uprobe_offset(OFFSET_IDX_CONN_GRPC_TRANSPORT_BUFWRITER);
}

static __inline int get_fd_from_http2serverConn_ctx(struct pt_regs *ctx)
{
	void *ptr;
	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		ptr = (void *)ctx->rax;
	} else {
		bpf_probe_read(&ptr, sizeof(ptr), (void *)(ctx->rsp + 8));
	}
	ptr += get_conn_http2_server_conn_offset();
	return get_fd_from_tcp_or_tls_conn_interface(ptr);
}

static __inline int get_fd_from_http2ClientConn(void *ptr)
{
	ptr += get_tconn_http2_client_conn_offset();
	return get_fd_from_tcp_or_tls_conn_interface(ptr);
}

static __inline int get_fd_from_http2ClientConn_ctx(struct pt_regs *ctx)
{
	void *ptr;
	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		ptr = (void *)ctx->rax;
	} else {
		bpf_probe_read(&ptr, sizeof(ptr), (void *)(ctx->rsp + 8));
	}
	return get_fd_from_http2ClientConn(ptr);
}

static __inline int get_fd_from_grpc_http2Client_ctx(struct pt_regs *ctx)
{
	void *ptr;
	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		ptr = (void *)ctx->rax;
	} else {
		bpf_probe_read(&ptr, sizeof(ptr), (void *)(ctx->rsp + 8));
	}
	ptr += get_conn_grpc_http2_client_offset();
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
	void *ptr;
	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		ptr = (void *)ctx->rax;
	} else {
		bpf_probe_read(&ptr, sizeof(ptr), (void *)(ctx->rsp + 8));
	}
	ptr += get_conn_grpc_http2_server_offset();
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
	void *ptr;
	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		ptr = (void *)ctx->rax;
	} else {
		bpf_probe_read(&ptr, sizeof(ptr), (void *)(ctx->rsp + 8));
	}

	ptr += get_side_grpc_transport_loopy_writer_offset();
	int side = 0;
	bpf_probe_read_user(&side, sizeof(side), ptr);
	return side;
}

static __inline int get_fd_from_grpc_loopyWriter(struct pt_regs *ctx)
{
	void *ptr;
	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		ptr = (void *)ctx->rax;
	} else {
		bpf_probe_read(&ptr, sizeof(ptr), (void *)(ctx->rsp + 8));
	}

	ptr += get_framer_grpc_transport_loopy_writer_offset();
	bpf_probe_read_user(&ptr, sizeof(ptr), ptr);
	ptr += get_writer_grpc_transport_framer_offset();
	bpf_probe_read_user(&ptr, sizeof(ptr), ptr);
	ptr += get_conn_grpc_transport_bufwriter_offset();

	if (is_grpc_syscallConn_interface(ptr)) {
		struct go_interface i;
		bpf_probe_read_user(&i, sizeof(i), ptr);
		bpf_probe_read_user(&i, sizeof(i), i.ptr);
		ptr = i.ptr;
	}
	return get_fd_from_tcp_or_tls_conn_interface(ptr);
}

// type http2clientConnReadLoop struct {
//	_  http2incomparable
//	cc *http2ClientConn
//}
static __inline int get_fd_from_http2clientConnReadLoop_ctx(struct pt_regs *ctx)
{
	void *ptr;
	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		ptr = (void *)ctx->rax;
	} else {
		bpf_probe_read(&ptr, sizeof(ptr), (void *)(ctx->rsp + 8));
	}
	ptr += get_cc_http2_client_conn_read_loop_offset();
	bpf_probe_read(&ptr, sizeof(ptr), ptr);
	return get_fd_from_http2ClientConn(ptr);
}

// func (sc *http2serverConn) writeHeaders(st *http2stream, headerData *http2writeResHeaders) error
SEC("uprobe/go_http2serverConn_writeHeaders")
int uprobe_go_http2serverConn_writeHeaders(struct pt_regs *ctx)
{
	int fd = get_fd_from_http2serverConn_ctx(ctx);
	int tcp_seq = get_tcp_write_seq_from_fd(fd);
	bpf_debug("3. http2serverConn writeHeaders fd=[%d] tcp_seq=[%u]\n", fd,
		  tcp_seq);

	// TODO: Implement hook function
	return 0;
}

// func (sc *http2serverConn) processHeaders(f *http2MetaHeadersFrame) error
SEC("uprobe/go_http2serverConn_processHeaders")
int uprobe_go_http2serverConn_processHeaders(struct pt_regs *ctx)
{
	int fd = get_fd_from_http2serverConn_ctx(ctx);
	int tcp_seq = get_tcp_read_seq_from_fd(fd);
	bpf_debug("2. http2serverConn processHeaders fd=[%d] tcp_seq=[%u]\n",
		  fd, tcp_seq);

	// TODO: Implement hook function
	return 0;
}

SEC("uprobe/go_http2clientConnReadLoop_handleResponse")
int uprobe_go_http2clientConnReadLoop_handleResponse(struct pt_regs *ctx)
{
	int fd = get_fd_from_http2clientConnReadLoop_ctx(ctx);
	int tcp_seq = get_tcp_read_seq_from_fd(fd);
	bpf_debug(
		"4. http2clientConnReadLoop handleResponse fd=[%d] tcp_seq=[%u]\n",
		fd, tcp_seq);

	// TODO: Implement hook function
	return 0;
}

SEC("uprobe/go_http2ClientConn_writeHeaders")
int uprobe_go_http2ClientConn_writeHeaders(struct pt_regs *ctx)
{
	int fd = get_fd_from_http2ClientConn_ctx(ctx);
	int tcp_seq = get_tcp_write_seq_from_fd(fd);
	bpf_debug("1. http2ClientConn writeHeaders fd=[%d] tcp_seq=[%u]\n", fd,
		  tcp_seq);

	// TODO: Implement hook function
	return 0;
}

// 日志上来看,调用多次 writeHeader 后调用一次 writeHeaders 进行发送
// 可能可以把这两个联系起来完成功能
SEC("uprobe/go_http2ClientConn_writeHeader")
int uprobe_go_http2ClientConn_writeHeader(struct pt_regs *ctx)
{
	int fd = get_fd_from_http2ClientConn_ctx(ctx);
	int tcp_seq = get_tcp_write_seq_from_fd(fd);
	bpf_debug("0. http2ClientConn writeHeader fd=[%d] tcp_seq=[%u]\n", fd,
		  tcp_seq);

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
		bpf_debug("5. grpc client write fd=[%d] tcp_seq=[%u]\n", fd,
			  tcp_seq);
	} else {
		bpf_debug("7. grpc server write fd=[%d] tcp_seq=[%u]\n", fd,
			  tcp_seq);
	}

	// TODO: Implement hook function
	return 0;
}

SEC("uprobe/go_http2Client_operateHeaders")
int uprobe_go_http2Client_operateHeaders(struct pt_regs *ctx)
{
	int fd = get_fd_from_grpc_http2Client_ctx(ctx);
	int tcp_seq = get_tcp_read_seq_from_fd(fd);
	bpf_debug("8. grpc client read fd=[%d] tcp_seq=[%u]\n", fd, tcp_seq);

	// TODO: Implement hook function
	return 0;
}

SEC("uprobe/go_http2Server_operateHeaders")
int uprobe_go_http2Server_operateHeaders(struct pt_regs *ctx)
{
	int fd = get_fd_from_grpc_http2Server_ctx(ctx);
	int tcp_seq = get_tcp_read_seq_from_fd(fd);
	bpf_debug("6. grpc server read fd=[%d] tcp_seq=[%u]\n", fd, tcp_seq);

	// TODO: Implement hook function
	return 0;
}