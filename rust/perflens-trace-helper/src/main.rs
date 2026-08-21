use std::env;
use std::path::Path;
use std::process::ExitCode;

use perflens_trace_helper::{
    PRIVATE_TRACE_HELPER_SOCKET, TraceHelperServerPolicy, TraceMode, serve_private_socket,
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
    let (policy_arguments, allow_rootful_container_targets) =
        match arguments.last().map(String::as_str) {
            Some("--allow-rootful-container-targets") => (&arguments[..arguments.len() - 1], true),
            _ => (arguments, false),
        };
    let [
        broker_flag,
        broker_uid,
        allowed_flag,
        allowed_uid,
        artifact_flag,
        artifact_gid,
        modes_flag,
        allowed_modes,
        policy_flag,
        policy_sha256,
    ] = policy_arguments
    else {
        return Err("expected fixed broker, target, artifact group, modes, and policy arguments");
    };
    if broker_flag != "--broker-uid"
        || allowed_flag != "--allowed-uid"
        || artifact_flag != "--artifact-gid"
        || modes_flag != "--allowed-modes"
        || policy_flag != "--policy-sha256"
    {
        return Err("expected fixed broker, target, artifact group, modes, and policy arguments");
    }
    let broker_uid = broker_uid
        .parse::<u32>()
        .map_err(|_error| "broker UID must be an unsigned integer")?;
    let allowed_uid = allowed_uid
        .parse::<u32>()
        .map_err(|_error| "allowed UID must be an unsigned integer")?;
    let artifact_gid = artifact_gid
        .parse::<u32>()
        .map_err(|_error| "artifact GID must be an unsigned integer")?;
    let allowed_modes = parse_allowed_modes(allowed_modes)?;
    if !valid_sha256(policy_sha256) {
        return Err("policy SHA-256 must be 64 lowercase hexadecimal characters");
    }
    Ok(TraceHelperServerPolicy {
        broker_uid,
        allowed_uid,
        artifact_gid,
        allowed_modes,
        policy_sha256: policy_sha256.clone(),
        allow_rootful_container_targets,
    })
}

fn parse_allowed_modes(value: &str) -> Result<Vec<TraceMode>, &'static str> {
    let mut modes = Vec::new();
    for raw in value.split(',') {
        let mode = match raw {
            "sched" => TraceMode::Sched,
            "off_cpu" => TraceMode::OffCpu,
            "lock" => TraceMode::Lock,
            _ => return Err("allowed modes contain an unknown value"),
        };
        if modes.contains(&mode) {
            return Err("allowed modes contain a duplicate value");
        }
        modes.push(mode);
    }
    if modes.is_empty() {
        return Err("at least one Trace mode is required");
    }
    let canonical = [TraceMode::Sched, TraceMode::OffCpu, TraceMode::Lock]
        .into_iter()
        .filter(|mode| modes.contains(mode))
        .collect::<Vec<_>>();
    if modes != canonical {
        return Err("allowed modes must use canonical order");
    }
    Ok(modes)
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
            "--artifact-gid",
            "992",
            "--allowed-modes",
            "sched,off_cpu,lock",
            "--policy-sha256",
            &"a".repeat(64),
        ]))
        .expect("parse policy");
        assert_eq!(policy.broker_uid, 991);
        assert_eq!(policy.allowed_uid, 1000);
        assert_eq!(policy.artifact_gid, 992);
        assert_eq!(policy.allowed_modes.len(), 3);
        assert!(!policy.allow_rootful_container_targets);

        let rootful = parse_policy_arguments(&arguments(&[
            "--broker-uid",
            "991",
            "--allowed-uid",
            "1000",
            "--artifact-gid",
            "992",
            "--allowed-modes",
            "sched,off_cpu,lock",
            "--policy-sha256",
            &"a".repeat(64),
            "--allow-rootful-container-targets",
        ]))
        .expect("parse rootful policy");
        assert!(rootful.allow_rootful_container_targets);
    }

    #[test]
    fn rejects_malformed_policy_arguments() {
        assert!(
            parse_policy_arguments(&arguments(&[
                "--broker-uid",
                "root",
                "--allowed-uid",
                "1000",
                "--artifact-gid",
                "992",
                "--allowed-modes",
                "sched,off_cpu,lock",
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
                "--artifact-gid",
                "992",
                "--allowed-modes",
                "sched,off_cpu,lock",
                "--policy-sha256",
                "ABC",
            ]))
            .is_err()
        );
    }
}
