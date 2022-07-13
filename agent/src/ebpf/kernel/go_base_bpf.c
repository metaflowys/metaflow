#define HASH_ENTRIES_MAX 40960

/*
 * The binary executable file offset of the GO process
 * key: pid
 * value: struct ebpf_proc_info
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct ebpf_proc_info);
	__uint(max_entries, HASH_ENTRIES_MAX);
} proc_info_map SEC(".maps");

/*
 * Goroutines Map
 * key: {tgid, pid}
 * value: goroutine ID
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __s64);
	__uint(max_entries, MAX_SYSTEM_THREADS);
} goroutines_map SEC(".maps");

static __inline struct ebpf_proc_info *get_current_proc_info()
{
	__u64 id;
	pid_t pid;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	return info;
}

static __inline int get_uprobe_offset(int offset_idx)
{
	struct ebpf_proc_info *info = get_current_proc_info();
	if (info) {
		return info->offsets[offset_idx];
	}

	return -1;
}

static __inline __u32 get_go_version(void)
{
	__u64 id;
	pid_t pid;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	struct ebpf_proc_info *info;
	info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (info) {
		return info->version;
	}

	return 0;
}

static __inline int get_runtime_g_goid_offset(void)
{
	return get_uprobe_offset(OFFSET_IDX_GOID_RUNTIME_G);
}

static __inline int get_crypto_tls_conn_conn_offset(void)
{
	return get_uprobe_offset(OFFSET_IDX_CONN_TLS_CONN);
}

static __inline int get_net_poll_fd_sysfd(void)
{
	return get_uprobe_offset(OFFSET_IDX_SYSFD_POLL_FD);
}

static __inline __s64 get_current_goroutine(void)
{
	__u64 current_thread = bpf_get_current_pid_tgid();
	__s64 *goid_ptr = bpf_map_lookup_elem(&goroutines_map, &current_thread);
	if (goid_ptr) {
		return *goid_ptr;
	}

	return 0;
}

static __inline bool is_tcp_conn_interface(void *conn)
{
	struct go_interface i;
	bpf_probe_read_user(&i, sizeof(i), conn);

	struct ebpf_proc_info *info = get_current_proc_info();
	return info ? i.type == info->net_TCPConn_itab : false;
}

static __inline int get_fd_from_tcp_conn_interface(void *conn)
{
	if (!is_tcp_conn_interface(conn)) {
		return -1;
	}

	int offset_fd_sysfd = get_net_poll_fd_sysfd();
	if (offset_fd_sysfd < 0)
		return -1;

	struct go_interface i = {};
	void *ptr;
	int fd;

	bpf_probe_read_user(&i, sizeof(i), conn);
	bpf_probe_read_user(&ptr, sizeof(ptr), i.ptr);
	bpf_probe_read_user(&fd, sizeof(fd), ptr + offset_fd_sysfd);
	return fd;
}

static __inline int get_fd_from_tls_conn_struct(void *conn)
{
	int offset_conn_conn = get_crypto_tls_conn_conn_offset();
	if (offset_conn_conn < 0)
		return -1;

	return get_fd_from_tcp_conn_interface(conn + offset_conn_conn);
}

static __inline bool is_tls_conn_interface(void *conn)
{
	struct go_interface i;
	bpf_probe_read_user(&i, sizeof(i), conn);

	struct ebpf_proc_info *info = get_current_proc_info();
	return info ? i.type == info->crypto_tls_Conn_itab : false;
}

static __inline int get_fd_from_tls_conn_interface(void *conn)
{
	if (!is_tls_conn_interface(conn)) {
		return -1;
	}
	struct go_interface i = {};

	bpf_probe_read_user(&i, sizeof(i), conn);
	return get_fd_from_tls_conn_struct(i.ptr);
}

static __inline int get_fd_from_tcp_or_tls_conn_interface(void *conn)
{
	int fd;
	fd = get_fd_from_tls_conn_interface(conn);
	if (fd > 0) {
		// TODO: 标记 http2 使用了 tls 加密
		return fd;
	}
	fd = get_fd_from_tcp_conn_interface(conn);
	if (fd > 0) {
		// TODO: 标记 http2 没有通过 tls 加密
		return fd;
	}
	return -1;
}

SEC("uprobe/runtime.casgstatus")
int runtime_casgstatus(struct pt_regs *ctx)
{
	int offset_g_goid = get_runtime_g_goid_offset();
	if (offset_g_goid < 0) {
		return 0;
	}

	__s32 newval;
	void *g_ptr;

	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		g_ptr = (void *)(ctx->rax);
		newval = (__s32)(ctx->rcx);
	} else {
		bpf_probe_read(&g_ptr, sizeof(g_ptr), (void *)(ctx->rsp + 8));
		bpf_probe_read(&newval, sizeof(newval),
			       (void *)(ctx->rsp + 20));
	}

	if (newval != 2) {
		return 0;
	}

	__s64 goid = 0;
	bpf_probe_read(&goid, sizeof(goid), g_ptr + offset_g_goid);
	__u64 current_thread = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&goroutines_map, &current_thread, &goid, BPF_ANY);

	return 0;
}

// /sys/kernel/debug/tracing/events/sched/sched_process_exit/format
SEC("tracepoint/sched/sched_process_exit")
int bpf_func_sched_process_exit(struct sched_comm_exit_ctx *ctx)
{
	pid_t pid, tid;
	__u64 id;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (__u32)id;

	// If is a process, clear proc_info_map element and submit event.
	if (pid == tid) {
		bpf_map_delete_elem(&proc_info_map, &pid);
		struct event_data data;
		data.pid = pid;
		data.event_type = EVENT_TYPE_PROC_EXIT;
		int ret = bpf_perf_event_output(ctx, &NAME(socket_data),
						BPF_F_CURRENT_CPU, &data,
						sizeof(data));

		if (ret) {
			bpf_debug(
				"bpf_func_sched_process_exit event outputfaild: %d\n",
				ret);
		}
	}

	bpf_map_delete_elem(&goroutines_map, &id);
	return 0;
}

// /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
SEC("tracepoint/sched/sched_process_exec")
int bpf_func_sched_process_exec(struct sched_comm_exec_ctx *ctx)
{
	struct event_data data;
	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	pid_t tid = (__u32)id;

	if (pid == tid) {
		data.event_type = EVENT_TYPE_PROC_EXEC;
		data.pid = pid;
		int ret = bpf_perf_event_output(ctx, &NAME(socket_data),
						BPF_F_CURRENT_CPU, &data,
						sizeof(data));

		if (ret) {
			bpf_debug(
				"bpf_func_sys_exit_execve event output() faild: %d\n",
				ret);
		}
	}

	return 0;
}
