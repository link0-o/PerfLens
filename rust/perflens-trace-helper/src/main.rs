use std::env;
use std::path::Path;
use std::process::ExitCode;

use perflens_trace_helper::{
    PRIVATE_TRACE_HELPER_SOCKET, TraceHelperServerPolicy, serve_private_socket,
};

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments == ["--version"] {
        println!("perflens-trace-helper {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let policy = match parse_policy_arguments(&arguments) {
        Ok(policy) => policy,
        Err(message) => {
            eprintln!("perflens-trace-helper: {message}");
            return ExitCode::from(64);
        }
    };
    match serve_private_socket(Path::new(PRIVATE_TRACE_HELPER_SOCKET), &policy) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_error) => {
            eprintln!("perflens-trace-helper: private service failed safely");
            ExitCode::from(70)
        }
    }
}

fn parse_policy_arguments(arguments: &[String]) -> Result<TraceHelperServerPolicy, &'static str> {
    let [
        broker_flag,
        broker_uid,
        allowed_flag,
        allowed_uid,
        policy_flag,
        policy_sha256,
    ] = arguments
    else {
        return Err("expected --broker-uid <uid> --allowed-uid <uid> --policy-sha256 <sha256>");
    };
    if broker_flag != "--broker-uid"
        || allowed_flag != "--allowed-uid"
        || policy_flag != "--policy-sha256"
    {
        return Err("expected --broker-uid <uid> --allowed-uid <uid> --policy-sha256 <sha256>");
    }
    let broker_uid = broker_uid
        .parse::<u32>()
        .map_err(|_error| "broker UID must be an unsigned integer")?;
    let allowed_uid = allowed_uid
        .parse::<u32>()
        .map_err(|_error| "allowed UID must be an unsigned integer")?;
    if !valid_sha256(policy_sha256) {
        return Err("policy SHA-256 must be 64 lowercase hexadecimal characters");
    }
    Ok(TraceHelperServerPolicy {
        broker_uid,
        allowed_uid,
        policy_sha256: policy_sha256.clone(),
    })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::parse_policy_arguments;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn parses_fixed_policy_identity() {
        let policy = parse_policy_arguments(&arguments(&[
            "--broker-uid",
            "991",
            "--allowed-uid",
            "1000",
            "--policy-sha256",
            &"a".repeat(64),
        ]))
        .expect("parse policy");
        assert_eq!(policy.broker_uid, 991);
        assert_eq!(policy.allowed_uid, 1000);
    }

    #[test]
    fn rejects_malformed_policy_arguments() {
        assert!(
            parse_policy_arguments(&arguments(&[
                "--broker-uid",
                "root",
                "--allowed-uid",
                "1000",
                "--policy-sha256",
                &"a".repeat(64),
            ]))
            .is_err()
        );
        assert!(
            parse_policy_arguments(&arguments(&[
                "--broker-uid",
                "991",
                "--allowed-uid",
                "1000",
                "--policy-sha256",
                "ABC",
            ]))
            .is_err()
        );
    }
}
