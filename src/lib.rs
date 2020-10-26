use std::env;
use std::time::SystemTime;

use aws_auth::{self, AwsRegion, AwsService, FormatTime, Hash, HttpMethod};

const TODO_REGION: AwsRegion = AwsRegion::ApNortheast1;

// TODO: error handling
fn bucket_key_from_s3_url(mut s3_url: &str) -> (&str, &str) {
    if s3_url.starts_with("s3://") {
        s3_url = &s3_url["s3://".len()..];
    } else {
        panic!()
    }
    let mut split = s3_url.splitn(2, '/');
    let bucket = split.next().expect("no domain");
    let key = split.next().expect("no key");
    (bucket, key)
}

fn s3_url_to_http_url(s3_url: &str, region: AwsRegion) -> String {
    let (bucket, key) = bucket_key_from_s3_url(s3_url);
    let path_style = bucket.contains('.');

    match path_style {
        true => format!(
            "https://s3.{}.amazonaws.com/{}/{}",
            region.to_str(),
            bucket,
            key
        ),
        false => format!(
            "https://{}.s3.{}.amazonaws.com/{}",
            bucket,
            region.to_str(),
            key
        ),
    }
}

// TODO: query and headers
fn easy_auth_header_now(
    http_method: HttpMethod,
    https_url: &str,
    secret_key: &str,
    key_id: &str,
    region: AwsRegion,
    payload: &[u8],
) -> (Vec<u8>, Hash, SystemTime) {
    let mut buffer = Vec::new();
    let secret_key = aws_auth::validate_secret_key(&secret_key).expect("invalid secret key");
    let key_id = aws_auth::validate_key_id(&key_id).expect("invalid key id");

    let (domain, abspath, query) = aws_auth::split_url(https_url.as_bytes());
    let mut query = query.collect::<Vec<_>>();
    aws_auth::ensure_query_order(&mut query);

    let request_time = SystemTime::now();
    let payload_hash = Hash::new(payload);
    let mut request_time_header = [0; 16];
    request_time.write_iso8602_basic_seconds_utc(&mut request_time_header);
    let signed_headers = vec![
        (&b"host"[..], domain),
        (&b"x-amz-content-sha256"[..], &payload_hash.as_hex()[..]),
        (&b"x-amz-date"[..], &request_time_header[..]),
    ];
    let key_date = SystemTime::now();
    let signing_key = aws_auth::signing_key(&secret_key, key_date, region, AwsService::S3);

    aws_auth::gen_auth_header(
        &mut buffer,
        http_method,
        abspath,
        &query,
        &signed_headers,
        &signing_key,
        key_id,
        region,
        AwsService::S3,
        request_time,
        key_date,
        &payload_hash,
    );

    (buffer, payload_hash, key_date)
}

pub async fn quick_get(s3_url: &str) -> Result<reqwest::Response, reqwest::Error> {
    let https_url = s3_url_to_http_url(s3_url, TODO_REGION);
    let secret_key = env::var("AWS_SECRET_ACCESS_KEY").expect("no secretkey");
    let key_id = env::var("AWS_ACCESS_KEY_ID").expect("no key id");
    let region =
        AwsRegion::try_from(&env::var("AWS_REGION").expect("no region")).expect("invalid region");
    let (auth_header, payload_hash, key_date) = easy_auth_header_now(
        HttpMethod::Get,
        &https_url,
        &secret_key,
        &key_id,
        region,
        "".as_bytes(),
    );

    let mut date_header = [0; 16];
    key_date.write_iso8602_basic_seconds_utc(&mut date_header);

    reqwest::ClientBuilder::new()
        .build()
        .unwrap()
        .get(&https_url)
        .header("Authorization", auth_header.as_slice())
        .header("x-amz-content-sha256", &payload_hash.as_hex()[..])
        .header("x-amz-date", &date_header[..])
        .send()
        .await
}
