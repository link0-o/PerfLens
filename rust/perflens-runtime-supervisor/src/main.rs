use perflens_runtime_supervisor::{ControlDescriptors, run_supervisor};
use std::env;
use std::ffi::OsString;
use std::process::ExitCode;

fn main() -> ExitCode {
    match parse_arguments(env::args_os()).and_then(|control| run_supervisor(&control)) {
        Ok(receipt) if receipt.cleanup_complete => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(70),
        Err(error) => {
            eprintln!("perflens-runtime-supervisor: {error}");
            ExitCode::from(64)
        }
    }
}

fn parse_arguments<I>(
    arguments: I,
) -> Result<ControlDescriptors, perflens_runtime_supervisor::SupervisorError>
where
    I: IntoIterator<Item = OsString>,
{
    let values: Vec<OsString> = arguments.into_iter().collect();
    if values.len() != 7
        || values[1] != "--request-fd"
        || values[3] != "--receipt-fd"
        || values[5] != "--liveness-fd"
    {
        return Err(perflens_runtime_supervisor::SupervisorError::new(
            "invalid_arguments",
            "expected fixed request, receipt, and liveness descriptor options",
        ));
    }
    Ok(ControlDescriptors {
        request: parse_descriptor(&values[2])?,
        receipt: parse_descriptor(&values[4])?,
        liveness: parse_descriptor(&values[6])?,
    })
}

fn parse_descriptor(
    value: &std::ffi::OsStr,
) -> Result<i32, perflens_runtime_supervisor::SupervisorError> {
    let Some(value) = value.to_str() else {
        return Err(perflens_runtime_supervisor::SupervisorError::new(
            "invalid_arguments",
            "descriptor is not UTF-8",
        ));
    };
    let descriptor = value.parse::<i32>().map_err(|_| {
        perflens_runtime_supervisor::SupervisorError::new(
            "invalid_arguments",
            "descriptor is not a decimal integer",
        )
    })?;
    if descriptor < 3 {
        return Err(perflens_runtime_supervisor::SupervisorError::new(
            "invalid_arguments",
            "descriptor overlaps standard input/output/error",
        ));
    }
    Ok(descriptor)
}

#[cfg(test)]
mod tests {
    use super::parse_arguments;
    use std::ffi::OsString;

    #[test]
    fn accepts_only_fixed_descriptor_options() {
        let parsed = parse_arguments(
            [
                "supervisor",
                "--request-fd",
                "3",
                "--receipt-fd",
                "4",
                "--liveness-fd",
                "5",
            ]
            .map(OsString::from),
        )
        .expect("valid fixed arguments");
        assert_eq!(parsed.request, 3);
        assert_eq!(parsed.receipt, 4);
        assert_eq!(parsed.liveness, 5);
    }

    #[test]
    fn rejects_extra_and_stdio_descriptors() {
        assert!(
            parse_arguments(
                [
                    "supervisor",
                    "--request-fd",
                    "0",
                    "--receipt-fd",
                    "4",
                    "--liveness-fd",
                    "5",
                ]
                .map(OsString::from),
            )
            .is_err()
        );
        assert!(
            parse_arguments(
                [
                    "supervisor",
                    "--request-fd",
                    "3",
                    "--receipt-fd",
                    "4",
                    "--liveness-fd",
                    "5",
                    "--unexpected",
                ]
                .map(OsString::from),
            )
            .is_err()
        );
    }
}
