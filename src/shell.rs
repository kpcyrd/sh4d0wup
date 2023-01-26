use crate::errors::*;
use maplit::hashset;
use std::collections::HashSet;

lazy_static::lazy_static! {
    static ref SHELLS: HashSet<&'static str> = hashset!["/bin/sh", "/bin/bash", "bash", "sh"];
}

pub fn supports_injection(header: &str) -> bool {
    let header = if let Some(header) = header.strip_prefix("#!") {
        header.trim()
    } else {
        return false;
    };

    let (prog, remaining) = header.split_once(' ').unwrap_or((header, ""));
    let (first_arg, _remaining) = remaining
        .split_once(' ')
        .map(|x| (Some(x.0), x.1))
        .unwrap_or(if remaining.is_empty() {
            (None, "")
        } else {
            (Some(remaining), "")
        });

    if SHELLS.contains(&prog) {
        debug!("Detected a shell we can inject into: {:?}", prog);
        true
    } else if let ("/usr/bin/env", Some(arg)) = (prog, first_arg) {
        if SHELLS.contains(&arg) {
            debug!(
                "Detected a shell (behind {:?}) we can inject into: {:?}",
                prog, arg
            );
            true
        } else {
            debug!("Unknown program behind {:?}: {:?}", prog, arg);
            false
        }
    } else {
        debug!("Unknown program: {:?}", prog);
        false
    }
}

pub fn inject_into_script(script: &str, payload: &str) -> Result<String> {
    let (mut header, data) = if let Some(idx) = script.find('\n') {
        (&script[..idx], &script[idx + 1..])
    } else {
        (script, "")
    };

    // if the program is 100% empty we can just decide it's now a shell script
    if header.is_empty() {
        header = "#!/bin/sh";
    }

    if !supports_injection(header) {
        bail!("Can't inject into this type of script");
    }

    debug!("Patching payload into shell script: {:?}", payload);
    let patched = format!("{header}\n{payload}\n{data}");
    debug!("Patched shell script: {:?}", patched);
    Ok(patched)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn patch_simple_script() {
        let patched = inject_into_script(
            "#!/bin/sh
echo hello world
",
            "id",
        )
        .unwrap();
        assert_eq!(
            patched,
            "#!/bin/sh
id
echo hello world
"
        );
    }

    #[test]
    pub fn patch_header_only_script() {
        let patched = inject_into_script("#!/bin/sh", "id").unwrap();
        assert_eq!(
            patched,
            "#!/bin/sh
id
"
        );
        let patched = inject_into_script("#!/bin/sh\n", "id").unwrap();
        assert_eq!(
            patched,
            "#!/bin/sh
id
"
        );
    }

    #[test]
    pub fn patch_empty_script() {
        let patched = inject_into_script("", "id").unwrap();
        assert_eq!(patched, "#!/bin/sh\nid\n");
    }

    #[test]
    pub fn patch_bash_script() {
        let patched = inject_into_script(
            "#!/bin/bash
echo hello world
",
            "id",
        )
        .unwrap();
        assert_eq!(
            patched,
            "#!/bin/bash
id
echo hello world
"
        );
    }

    #[test]
    pub fn patch_with_opts_script() {
        let patched = inject_into_script(
            "#!/bin/sh -e -x
echo hello world
",
            "id",
        )
        .unwrap();
        assert_eq!(
            patched,
            "#!/bin/sh -e -x
id
echo hello world
"
        );
    }

    #[test]
    pub fn looks_like_a_shell_but_isnt() {
        let r = inject_into_script(
            "#!/bin/should not match
echo hello world
",
            "id",
        );
        assert!(r.is_err());
    }

    #[test]
    pub fn space_before_shell() {
        let patched = inject_into_script(
            "#! /bin/sh
set -e
",
            "id",
        )
        .unwrap();
        assert_eq!(
            patched,
            "#! /bin/sh
id
set -e
"
        );
    }
}
