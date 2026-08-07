use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use perflens_privileged_helper::{HelperServerPolicy, PRIVATE_HELPER_SOCKET, serve_private_socket};

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments == ["--version"] {
        println!("perflens-privileged-helper {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let policy = match parse_policy_arguments(&arguments) {
        Ok(policy) => policy,
        Err(message) => {
            eprintln!("perflens-privileged-helper: {message}");
            return ExitCode::from(64);
        }
    };
    match serve_private_socket(Path::new(PRIVATE_HELPER_SOCKET), &policy) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_error) => {
            eprintln!("perflens-privileged-helper: private service failed safely");
            ExitCode::from(70)
        }
    }
}

fn parse_policy_arguments(arguments: &[String]) -> Result<HelperServerPolicy, &'static str> {
    let (raw_broker_uid, raw_allowed_uid, raw_artifact_gid, raw_perf_path) = match arguments {
        [
            broker_flag,
            broker_uid,
            allowed_flag,
            allowed_uid,
            group_flag,
            artifact_gid,
            perf_flag,
            perf_path,
        ] if broker_flag == "--broker-uid"
            && allowed_flag == "--allowed-uid"
            && group_flag == "--artifact-gid"
            && perf_flag == "--perf-path" =>
        {
            (
                broker_uid.as_str(),
                allowed_uid.as_str(),
                artifact_gid.as_str(),
                perf_path.as_str(),
            )
        }
        [
            broker_flag,
            broker_uid,
            allowed_flag,
            allowed_uid,
            group_flag,
            artifact_gid,
        ] if broker_flag == "--broker-uid"
            && allowed_flag == "--allowed-uid"
            && group_flag == "--artifact-gid" =>
        {
            // Compatibility for a package upgrade before `perflens-admin upgrade` replaces
            // the v0.2.0 unit. That unit's reviewed immutable path was `/usr/bin/perf`.
            (
                broker_uid.as_str(),
                allowed_uid.as_str(),
                artifact_gid.as_str(),
                "/usr/bin/perf",
            )
        }
        _ => {
            return Err(
                "expected --broker-uid <uid> --allowed-uid <uid> --artifact-gid <gid> --perf-path <absolute-path>",
            );
        }
    };
    let broker_uid = raw_broker_uid
        .parse::<u32>()
        .map_err(|_error| "broker UID must be an unsigned integer")?;
    let allowed_uid = raw_allowed_uid
        .parse::<u32>()
        .map_err(|_error| "allowed UID must be an unsigned integer")?;
    let artifact_gid = raw_artifact_gid
        .parse::<u32>()
        .map_err(|_error| "artifact GID must be an unsigned integer")?;
    let perf_path = PathBuf::from(raw_perf_path);
    if !perf_path.is_absolute() {
        return Err("perf path must be absolute");
    }
    Ok(HelperServerPolicy {
        broker_uid,
        allowed_uid,
        artifact_gid,
        perf_path,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::parse_policy_arguments;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn parses_configured_perf_path_and_legacy_unit_arguments() {
        let configured = parse_policy_arguments(&arguments(&[
            "--broker-uid",
            "991",
            "--allowed-uid",
            "1000",
            "--artifact-gid",
            "992",
            "--perf-path",
            "/opt/trusted/bin/perf",
        ]))
        .expect("parse current unit");
        assert_eq!(configured.perf_path, PathBuf::from("/opt/trusted/bin/perf"));

        let legacy = parse_policy_arguments(&arguments(&[
            "--broker-uid",
            "991",
            "--allowed-uid",
            "1000",
            "--artifact-gid",
            "992",
        ]))
        .expect("parse legacy unit during package upgrade");
        assert_eq!(legacy.perf_path, PathBuf::from("/usr/bin/perf"));
    }

    #[test]
    fn rejects_relative_perf_path_and_malformed_uids() {
        let relative = arguments(&[
            "--broker-uid",
            "991",
            "--allowed-uid",
            "1000",
            "--artifact-gid",
            "992",
            "--perf-path",
            "bin/perf",
        ]);
        assert!(parse_policy_arguments(&relative).is_err());

        let malformed = arguments(&[
            "--broker-uid",
            "root",
            "--allowed-uid",
            "1000",
            "--artifact-gid",
            "992",
        ]);
        assert!(parse_policy_arguments(&malformed).is_err());
    }
}
