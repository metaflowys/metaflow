use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str,
    time::Duration,
};

use prost::Message;

use super::{
    enums::{IpProtocol, TapType},
    flow::L7Protocol,
    tap_port::TapPort,
};

use crate::proto::flow_log;
use crate::utils::net::MacAddr;

#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum L7ResponseStatus {
    Ok,
    Error,
    NotExist,
    ServerError,
    ClientError,
}

impl Default for L7ResponseStatus {
    fn default() -> Self {
        L7ResponseStatus::Ok
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum LogMessageType {
    Request,
    Response,
    Session,
    Other,
    Max,
}

impl Default for LogMessageType {
    fn default() -> Self {
        LogMessageType::Other
    }
}

#[derive(Debug, Default)]
pub struct AppProtoHead {
    pub proto: L7Protocol,
    pub msg_type: LogMessageType, // HTTP，DNS: request/response
    pub status: L7ResponseStatus, // 状态描述：0：正常，1：已废弃使用(先前用于表示异常)，2：不存在，3：服务端异常，4：客户端异常
    pub code: u16,                // HTTP状态码: 1xx-5xx, DNS状态码: 0-7
    pub rrt: u64,                 // HTTP，DNS时延: response-request
}

impl From<AppProtoHead> for flow_log::AppProtoHead {
    fn from(f: AppProtoHead) -> Self {
        flow_log::AppProtoHead {
            proto: f.proto as u32,
            msg_type: f.msg_type as u32,
            status: f.status as u32,
            code: f.code as u32,
            rrt: f.rrt,
        }
    }
}

#[derive(Debug)]
pub struct AppProtoLogsBaseInfo {
    start_time: Duration,
    end_time: Duration,
    flow_id: u64,
    tap_port: TapPort,
    vtap_id: u16,
    tap_type: TapType,
    is_ipv6: bool,
    tap_side: u8,
    pub head: AppProtoHead,

    /* L2 */
    mac_src: MacAddr,
    mac_dst: MacAddr,
    /* L3 ipv4 or ipv6 */
    ip_src: IpAddr,
    ip_dst: IpAddr,
    /* L3EpcID */
    l3_epc_id_src: i32,
    l3_epc_id_dst: i32,
    /* L4 */
    port_src: u16,
    port_dst: u16,
    /* First L7 TCP Seq */
    req_tcp_seq: u32,
    resp_tcp_seq: u32,

    protocol: IpProtocol,
    is_vip_interface_src: bool,
    is_vip_interface_dst: bool,
}

impl From<AppProtoLogsBaseInfo> for flow_log::AppProtoLogsBaseInfo {
    fn from(f: AppProtoLogsBaseInfo) -> Self {
        let (ip4_src, ip4_dst, ip6_src, ip6_dst) = match (f.ip_src, f.ip_dst) {
            (IpAddr::V4(ip4), IpAddr::V4(ip4_1)) => {
                (ip4, ip4_1, Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED)
            }
            (IpAddr::V6(ip6), IpAddr::V6(ip6_1)) => {
                (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, ip6, ip6_1)
            }
            _ => panic!("ip_src,ip_dst type mismatch"),
        };
        flow_log::AppProtoLogsBaseInfo {
            start_time: f.start_time.as_nanos() as u64,
            end_time: f.end_time.as_nanos() as u64,
            flow_id: f.flow_id,
            tap_port: f.tap_port.0,
            vtap_id: f.vtap_id as u32,
            tap_type: u16::from(f.tap_type) as u32,
            is_ipv6: f.is_ipv6 as u32,
            tap_side: f.tap_side as u32,
            head: Some(f.head.into()),
            mac_src: f.mac_src.into(),
            mac_dst: f.mac_dst.into(),
            ip_src: u32::from_le_bytes(ip4_src.octets()),
            ip_dst: u32::from_le_bytes(ip4_dst.octets()),
            ip6_src: ip6_src.octets().to_vec(),
            ip6_dst: ip6_dst.octets().to_vec(),
            l3_epc_id_src: f.l3_epc_id_src,
            l3_epc_id_dst: f.l3_epc_id_dst,
            port_src: f.port_src as u32,
            port_dst: f.port_dst as u32,
            protocol: f.protocol as u32,
            is_vip_interface_src: f.is_vip_interface_src as u32,
            is_vip_interface_dst: f.is_vip_interface_dst as u32,
            req_tcp_seq: f.req_tcp_seq,
            resp_tcp_seq: f.resp_tcp_seq,
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct DnsInfo {
    pub trans_id: u16,
    pub query_type: u8,
    pub query_name: String,
    // 根据查询类型的不同而不同，如：
    // A: ipv4/ipv6地址
    // NS: name server
    // SOA: primary name server
    pub answers: String,
}

impl From<DnsInfo> for flow_log::DnsInfo {
    fn from(f: DnsInfo) -> Self {
        flow_log::DnsInfo {
            trans_id: f.trans_id as u32,
            query_type: f.query_type as u32,
            query_name: f.query_name,
            answers: f.answers,
        }
    }
}

#[derive(Debug, Default)]
pub struct MysqlInfo {
    // Server Greeting
    pub protocol_version: u8,
    pub server_version: String,
    pub server_thread_id: u32,
    // request
    pub command: u8,
    pub context: String,
    // response
    pub response_code: u8,
    pub error_code: u16,
    pub affected_rows: u64,
    pub error_message: String,
}

impl From<MysqlInfo> for flow_log::MysqlInfo {
    fn from(f: MysqlInfo) -> Self {
        flow_log::MysqlInfo {
            protocol_version: f.protocol_version as u32,
            server_version: f.server_version,
            server_thread_id: f.server_thread_id,
            command: f.command as u32,
            context: f.context,
            response_code: f.response_code as u32,
            affected_rows: f.affected_rows,
            error_code: f.error_code as u32,
            error_message: f.error_message,
        }
    }
}

#[derive(Debug, Default)]
pub struct RedisInfo {
    pub request: Vec<u8>,      // 命令字段包括参数例如："set key value"
    pub request_type: Vec<u8>, // 命令类型不包括参数例如：命令为"set key value"，命令类型为："set"
    pub response: Vec<u8>,     // 整数回复 + 批量回复 + 多条批量回复
    pub status: Vec<u8>,       // '+'
    pub error: Vec<u8>,        // '-'
}

impl fmt::Display for RedisInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RedisInfo {{ request: {:?}, ",
            str::from_utf8(&self.request).unwrap_or_default()
        )?;
        write!(
            f,
            "request_type: {:?}, ",
            str::from_utf8(&self.request_type).unwrap_or_default()
        )?;
        write!(
            f,
            "response: {:?}, ",
            str::from_utf8(&self.response).unwrap_or_default()
        )?;
        write!(
            f,
            "status: {:?}, ",
            str::from_utf8(&self.status).unwrap_or_default()
        )?;
        write!(
            f,
            "error: {:?} }}",
            str::from_utf8(&self.error).unwrap_or_default()
        )
    }
}

impl From<RedisInfo> for flow_log::RedisInfo {
    fn from(f: RedisInfo) -> Self {
        flow_log::RedisInfo {
            request: f.request,
            request_type: f.request_type,
            response: f.response,
            status: f.status,
            error: f.error,
        }
    }
}

#[derive(Debug, Default)]
pub struct KafkaInfo {
    pub correlation_id: u32,

    // request
    pub req_msg_size: i32,
    pub api_version: u16,
    pub api_key: u16,
    pub client_id: String,

    // reponse
    pub resp_msg_size: i32,
}

impl From<KafkaInfo> for flow_log::KafkaInfo {
    fn from(f: KafkaInfo) -> Self {
        flow_log::KafkaInfo {
            correlation_id: f.correlation_id,
            req_msg_size: f.req_msg_size,
            api_version: f.api_version as u32,
            api_key: f.api_key as u32,
            client_id: f.client_id,
            resp_msg_size: f.resp_msg_size,
        }
    }
}

#[derive(Debug, Default)]
pub struct DubboInfo {
    // header
    pub serial_id: u8,
    pub data_type: u8,
    pub request_id: i64,

    // req
    pub req_msg_size: i32,
    pub dubbo_version: String,
    pub service_name: String,
    pub service_version: String,
    pub method_name: String,

    // resp
    pub resp_msg_size: i32,
}

impl From<DubboInfo> for flow_log::DubboInfo {
    fn from(f: DubboInfo) -> Self {
        flow_log::DubboInfo {
            serial_id: f.serial_id as u32,
            r#type: f.data_type as u32,
            id: f.request_id as u32,
            req_body_len: f.req_msg_size,
            version: f.dubbo_version,
            service_name: f.service_name,
            service_version: f.service_version,
            method_name: f.method_name,
            resp_body_len: f.resp_msg_size,
        }
    }
}

#[derive(Debug, Default)]
pub struct HttpInfo {
    pub stream_id: u32,
    pub version: String,
    pub trace_id: String,
    pub span_id: String,

    pub method: String,
    pub path: String,
    pub host: String,
    pub client_ip: String,

    pub req_content_length: Option<u64>,
    pub resp_content_length: Option<u64>,
}

impl From<HttpInfo> for flow_log::HttpInfo {
    fn from(f: HttpInfo) -> Self {
        flow_log::HttpInfo {
            stream_id: f.stream_id,
            version: f.version,
            method: f.method,
            path: f.path,
            host: f.host,
            client_ip: f.client_ip,
            trace_id: f.trace_id,
            span_id: f.span_id,
            req_content_length: match f.req_content_length {
                Some(length) => length as i64,
                _ => -1,
            },
            resp_content_length: match f.resp_content_length {
                Some(length) => length as i64,
                _ => -1,
            },
        }
    }
}

pub enum AppProtoLogsInfo {
    Dns(DnsInfo),
    Mysql(MysqlInfo),
    Redis(RedisInfo),
    Kafka(KafkaInfo),
    Dubbo(DubboInfo),
    Http(HttpInfo),
}

impl fmt::Display for AppProtoLogsInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(l) => write!(f, "{:?}", l),
            Self::Mysql(l) => write!(f, "{:?}", l),
            Self::Redis(l) => write!(f, "{:?}", l),
            Self::Dubbo(l) => write!(f, "{:?}", l),
            Self::Kafka(l) => write!(f, "{:?}", l),
            Self::Http(l) => write!(f, "{:?}", l),
        }
    }
}

pub struct AppProtoLogsData {
    pub base_info: AppProtoLogsBaseInfo,
    pub special_info: AppProtoLogsInfo,
}

impl AppProtoLogsData {
    pub fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let mut pb_proto_logs_data = flow_log::AppProtoLogsData {
            base: Some(self.base_info.into()),
            http: None,
            dns: None,
            mysql: None,
            redis: None,
            dubbo: None,
            kafka: None,
        };
        match self.special_info {
            AppProtoLogsInfo::Dns(t) => pb_proto_logs_data.dns = Some(t.into()),
            AppProtoLogsInfo::Mysql(t) => pb_proto_logs_data.mysql = Some(t.into()),
            AppProtoLogsInfo::Redis(t) => pb_proto_logs_data.redis = Some(t.into()),
            AppProtoLogsInfo::Kafka(t) => pb_proto_logs_data.kafka = Some(t.into()),
            AppProtoLogsInfo::Dubbo(t) => pb_proto_logs_data.dubbo = Some(t.into()),
            AppProtoLogsInfo::Http(t) => pb_proto_logs_data.http = Some(t.into()),
        };

        pb_proto_logs_data
            .encode(buf)
            .map(|_| pb_proto_logs_data.encoded_len())
    }
}

impl fmt::Display for AppProtoLogsData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.base_info)?;
        write!(f, "{}", self.special_info)
    }
}

impl fmt::Display for AppProtoLogsBaseInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "start_time: {:?} end_time: {:?} flow_id: {} vtap_id: {} tap_type: {} tap_port: {} proto: {:?} msg_type: {:?} code: {} \
            status: {:?} rrt: {} tap_side {} is_vip_interface_src {:?} is_vip_interface_dst {:?} mac_src: {} mac_dst: {} \
            ip_src: {} ip_dst: {} proto: {:?} port_src: {} port_dst: {} l3_epc_id_src: {} l3_epc_id_dst: {} req_tcp_seq: {} resp_tcp_seq: {}",
            self.start_time, self.end_time, self.flow_id, self.vtap_id, self.tap_type, self.tap_port, self.head.proto, self.head.msg_type, self.head.code,
            self.head.status, self.head.rrt, self.tap_side, self.is_vip_interface_src, self.is_vip_interface_dst, self.mac_src, self.mac_dst,
            self.ip_src, self.ip_dst, self.protocol, self.port_src, self.port_dst, self.l3_epc_id_src, self.l3_epc_id_dst, self.req_tcp_seq, self.resp_tcp_seq
        )
    }
}
