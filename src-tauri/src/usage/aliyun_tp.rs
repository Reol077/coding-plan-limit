//! 阿里云百炼 / 千问AI平台 Token Plan 订阅用量：控制面 OpenAPI（ACS3-HMAC-SHA256 签名）。
//! 接口 GetSubscriptionStats（x-acs-version 2026-02-10），无业务参数，返回订阅周期内
//! 各档位席位的 Credits 总量 / 本周期剩余量。
//! 注意：Claude Code 侧接入（token-plan.*.maas.* 的 /apps/anthropic）用的是 sk-sp-
//! 专属推理 Key，本查询必须另配阿里云账号 AccessKey（建议 RAM 子账号最小授权）。

use hmac::{Hmac, Mac};
use reqwest::header::HeaderMap;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::http::{client, f64_of, parse_time_any};
use super::types::Quota;

type HmacSha256 = Hmac<Sha256>;

const ACTION: &str = "GetSubscriptionStats";
const API_VERSION: &str = "2026-02-10";
const PATH: &str = "/tokenplan/subscription/stats";
/// 空 body 的 SHA256（签名与 x-acs-content-sha256 头共用此固定值）
const EMPTY_BODY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SIGNED_HEADERS: &str =
    "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version";

/// 区域 → 控制面域名（cn = 中国大陆站，intl = 国际站新加坡）
fn host_of(region: &str) -> &'static str {
    if region == "intl" {
        "modelstudio.ap-southeast-1.aliyuncs.com"
    } else {
        "modelstudio.cn-beijing.aliyuncs.com"
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// ACS3-HMAC-SHA256 签名（阿里云 RPC 新版协议，与 AWS V4 同构但单步 HMAC、无派生链）：
/// canonical headers 按头名字母序逐个 `小写名:值\n`（末尾带换行），query 恒为空。
fn sign_headers(ak: &str, sk: &str, host: &str, x_date: &str, nonce: &str) -> HeaderMap {
    let canonical_headers = format!(
        "host:{host}\nx-acs-action:{ACTION}\nx-acs-content-sha256:{EMPTY_BODY_SHA256}\nx-acs-date:{x_date}\nx-acs-signature-nonce:{nonce}\nx-acs-version:{API_VERSION}\n"
    );
    let canonical_request =
        format!("GET\n{PATH}\n\n{canonical_headers}\n{SIGNED_HEADERS}\n{EMPTY_BODY_SHA256}");
    let string_to_sign =
        format!("ACS3-HMAC-SHA256\n{}", sha256_hex(canonical_request.as_bytes()));
    let signature = hex_lower(&hmac_sha256(sk.as_bytes(), string_to_sign.as_bytes()));
    let authorization = format!(
        "ACS3-HMAC-SHA256 Credential={ak},SignedHeaders={SIGNED_HEADERS},Signature={signature}"
    );

    let mut headers = HeaderMap::new();
    headers.insert("Authorization", authorization.parse().expect("header 值"));
    headers.insert("x-acs-action", ACTION.parse().expect("header 值"));
    headers.insert("x-acs-version", API_VERSION.parse().expect("header 值"));
    headers.insert("x-acs-date", x_date.parse().expect("header 值"));
    headers.insert("x-acs-signature-nonce", nonce.parse().expect("header 值"));
    headers.insert(
        "x-acs-content-sha256",
        EMPTY_BODY_SHA256.parse().expect("header 值"),
    );
    headers
}

/// 极简 XML 取值（仅用于解析阿里云网关的错误报文）
fn xml_tag(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = start + text[start..].find(&close)?;
    Some(text[start..end].to_string())
}

fn brief(text: &str) -> String {
    text.chars().take(160).collect()
}

pub async fn query(
    region: &str,
    base_url: Option<&str>,
    ak: &str,
    sk: &str,
) -> Result<Quota, String> {
    // base_url 仅接受主机名（可带协议前缀），路径固定；留空按区域取默认站
    let host = base_url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|raw| {
            raw.trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .to_string()
        })
        .unwrap_or_else(|| host_of(region).to_string());
    let url = format!("https://{host}{PATH}");

    let now = time::OffsetDateTime::now_utc();
    let x_date = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let nonce = uuid::Uuid::new_v4().to_string();
    let headers = sign_headers(ak, sk, &host, &x_date, &nonce);

    let resp = client()
        .get(&url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| format!("网络请求失败: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("读取响应失败: {e}"))?;

    // 阿里云网关对签名/参数类错误可能直接回 XML（如 MissingDate），业务错误回 JSON 信封
    if text.trim_start().starts_with('<') {
        let code = xml_tag(&text, "Code").unwrap_or_else(|| status.as_u16().to_string());
        let msg = xml_tag(&text, "Message").unwrap_or_default();
        return Err(format!("{ACTION} 失败 ({code}): {msg}"));
    }
    let body: Value = serde_json::from_str(&text)
        .map_err(|_| format!("HTTP {}: 响应非 JSON: {}", status.as_u16(), brief(&text)))?;
    if body.get("Success").and_then(|v| v.as_bool()) == Some(false) {
        let code = body.get("Code").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let msg = body.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        return Err(format!("{ACTION} 失败 ({code}): {msg}"));
    }
    if !status.is_success() {
        return Err(format!("{ACTION} 失败: HTTP {}: {}", status.as_u16(), brief(&text)));
    }

    let data = body.get("Data").ok_or_else(|| format!("响应缺少 Data: {}", brief(&text)))?;
    let items = data
        .get("Items")
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
        .ok_or_else(|| format!("接口未返回席位数据（未订阅 Token Plan？）: {}", brief(&data.to_string())))?;

    // 多档位席位（standard/pro/max）求和；重置时刻取各档位与本订阅周期的最早值
    let mut total = 0.0f64;
    let mut remaining = 0.0f64;
    let mut refresh_at = parse_time_any(data.get("SubscriptionEndTime"));
    for item in items {
        total += f64_of(item, "SeatCredits").unwrap_or(0.0);
        remaining += f64_of(item, "SeatRemainingCredits").unwrap_or(0.0);
        if let Some(r) = parse_time_any(item.get("SeatRefreshTime")) {
            refresh_at = Some(match refresh_at {
                Some(cur) => cur.min(r),
                None => r,
            });
        }
    }
    if total <= 0.0 {
        return Err(format!(
            "接口未返回席位 Credits（未订阅 Token Plan？）: {}",
            brief(&data.to_string())
        ));
    }
    let used = (total - remaining).max(0.0);
    Ok(Quota::FixedQuota {
        used_percent: used / total * 100.0,
        used,
        total,
        unit: "Credits".into(),
        reset_at: refresh_at,
    })
}
